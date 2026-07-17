// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transport

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

func TestConfigureRejectsInvalidScheme(t *testing.T) {
	t.Cleanup(ResetForTest)
	err := Configure(Options{Proxy: "http://127.0.0.1:8080"})
	if err == nil || !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Fatalf("want unsupported scheme error, got %v", err)
	}
}

func TestConfigureRejectsMalformedURL(t *testing.T) {
	t.Cleanup(ResetForTest)
	err := Configure(Options{Proxy: "::not a url::"})
	if err == nil {
		t.Fatalf("want error for malformed URL, got nil")
	}
}

func TestConfigureAcceptsSocks5(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{Proxy: "socks5://127.0.0.1:1080"}); err != nil {
		t.Fatalf("socks5:// should be accepted: %v", err)
	}
	if !IsProxyConfigured() {
		t.Fatal("IsProxyConfigured should be true after successful Configure")
	}
}

func TestConfigureAcceptsSocks5h(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{Proxy: "socks5h://127.0.0.1:1080"}); err != nil {
		t.Fatalf("socks5h:// should be accepted: %v", err)
	}
}

func TestConfigureFromEnv(t *testing.T) {
	t.Cleanup(ResetForTest)
	t.Setenv("ALL_PROXY", "socks5h://127.0.0.1:1080")
	if err := Configure(Options{Proxy: ""}); err != nil {
		t.Fatalf("env-based configure should succeed: %v", err)
	}
	if !IsProxyConfigured() {
		t.Fatal("ALL_PROXY should enable proxy")
	}
}

func TestConfigureDoubleCallPanics(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{}); err != nil {
		t.Fatalf("first Configure failed: %v", err)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("second Configure should panic")
		}
	}()
	_ = Configure(Options{})
}

func TestIsProxyConfiguredFalseByDefault(t *testing.T) {
	t.Cleanup(ResetForTest)
	t.Setenv("ALL_PROXY", "")
	if err := Configure(Options{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if IsProxyConfigured() {
		t.Fatal("IsProxyConfigured should be false with no -proxy and no ALL_PROXY")
	}
}

func TestDialUDPReturnsErrWhenProxied(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{Proxy: "socks5h://127.0.0.1:1080"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	_, err := DialUDP("127.0.0.1:53")
	if !errors.Is(err, ErrUDPUnderProxy) {
		t.Fatalf("want ErrUDPUnderProxy, got %v", err)
	}
}

func TestDialContextReturnsErrOnUDPUnderProxy(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{Proxy: "socks5h://127.0.0.1:1080"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	_, err := DialContext(t.Context(), "udp", "127.0.0.1:53")
	if !errors.Is(err, ErrUDPUnderProxy) {
		t.Fatalf("want ErrUDPUnderProxy, got %v", err)
	}
}

func TestProxyURLRedactsCredentials(t *testing.T) {
	t.Cleanup(ResetForTest)
	if err := Configure(Options{Proxy: "socks5h://user:s3cret@127.0.0.1:1080"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	got := ProxyURL()
	if strings.Contains(got, "s3cret") {
		t.Fatalf("ProxyURL leaked password: %q", got)
	}
	if !strings.Contains(got, "user") || !strings.Contains(got, "127.0.0.1:1080") {
		t.Fatalf("ProxyURL unexpected shape: %q", got)
	}
}

func TestProxyURLEmptyWhenUnconfigured(t *testing.T) {
	t.Cleanup(ResetForTest)
	t.Setenv("ALL_PROXY", "")
	if err := Configure(Options{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if got := ProxyURL(); got != "" {
		t.Fatalf("ProxyURL should be empty when unconfigured, got %q", got)
	}
}

// TestDialDirectWithNoProxy verifies that with no -proxy and no ALL_PROXY,
// transport.Dial reaches a target directly (via directDial). Guards against
// regressions where proxy plumbing accidentally intercepts the no-proxy path.
func TestDialDirectWithNoProxy(t *testing.T) {
	t.Cleanup(ResetForTest)
	t.Setenv("ALL_PROXY", "")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	if err := Configure(Options{}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if IsProxyConfigured() {
		t.Fatal("no proxy should be configured")
	}

	conn, err := Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial direct: %v", err)
	}
	defer conn.Close()

	want := []byte("direct-path-ok")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

// TestEndToEndDialThroughSocks5 wires Configure to an in-process SOCKS5 server
// and verifies a TCP round-trip flows through it.
func TestEndToEndDialThroughSocks5(t *testing.T) {
	t.Cleanup(ResetForTest)

	// Echo server, the "real" target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	socks := newTestSOCKS5(t)

	if err := Configure(Options{Proxy: "socks5h://" + socks.addr}); err != nil {
		t.Fatalf("Configure: %v", err)
	}

	conn, err := Dial("tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatalf("Dial through proxy: %v", err)
	}
	defer conn.Close()

	want := []byte("hello-over-socks5")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}

	if n := socks.connects.Load(); n != 1 {
		t.Fatalf("SOCKS5 server saw %d CONNECTs, want 1", n)
	}
}
