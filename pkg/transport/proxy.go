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
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/net/proxy"
)

// ErrUDPUnderProxy is returned by DialUDP when a proxy is configured. SOCKS5
// UDP ASSOCIATE is rarely supported by proxies and servers, and silently
// leaking UDP packets from the attacker host when a proxy is configured would
// reveal the operator's real source IP. Callers should arrange for direct
// operation, or skip the UDP-dependent feature under -proxy.
var ErrUDPUnderProxy = errors.New("UDP disabled under -proxy; the underlying feature cannot be tunneled")

// Options holds runtime configuration for the transport layer.
type Options struct {
	// Proxy, if non-empty, is a SOCKS5 URL that outbound TCP is routed through.
	// Accepted schemes: socks5, socks5h. When empty, the ALL_PROXY / all_proxy
	// environment variables are consulted.
	Proxy string
}

// proxyHolder points to the configured proxy dialer, or nil for direct.
// Stored atomically so Dial is lock-free on the hot path.
var proxyHolder atomic.Pointer[dialerHolder]

type dialerHolder struct {
	cd  proxy.ContextDialer
	url string
}

var configured atomic.Bool

// Configure initializes the transport layer. Must be called exactly once,
// typically from flags.Parse at tool startup. Panics on subsequent calls so a
// misconfigured tool fails loudly rather than silently racing on package state.
func Configure(opts Options) error {
	if !configured.CompareAndSwap(false, true) {
		panic("transport.Configure called more than once")
	}

	// We intentionally don't use proxy.FromEnvironment here: it caches the env
	// value via sync.Once for the process lifetime, which breaks tests and
	// prevents consistent URL validation for env-supplied values.
	fromEnv := false
	if opts.Proxy == "" {
		envURL := os.Getenv("ALL_PROXY")
		if envURL == "" {
			envURL = os.Getenv("all_proxy")
		}
		if envURL == "" {
			return nil
		}
		opts.Proxy = envURL
		fromEnv = true
	}

	u, err := url.Parse(opts.Proxy)
	if err != nil {
		return fmt.Errorf("transport: invalid proxy URL %q: %v", opts.Proxy, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		// x/net/proxy treats both identically (always sends hostname to the
		// proxy; server decides resolution). socks5h is the documented
		// recommendation because it mirrors proxychains' proxy_dns=on default.
	default:
		return fmt.Errorf("transport: unsupported proxy scheme %q (supported: socks5, socks5h)", u.Scheme)
	}

	// Route the TCP connection to the SOCKS5 server through the libc dialer so
	// LD_PRELOAD-based proxies (proxychains) can still hook it, useful for
	// chaining: proxychains -> gopacket -> -proxy SOCKS5 -> target.
	d, err := proxy.FromURL(u, libcForwarder{})
	if err != nil {
		return fmt.Errorf("transport: initialize proxy dialer for %q: %v", opts.Proxy, err)
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return fmt.Errorf("transport: proxy dialer %T does not implement ContextDialer", d)
	}
	urlLabel := u.Redacted()
	if fromEnv {
		urlLabel += " (from ALL_PROXY)"
	}
	proxyHolder.Store(&dialerHolder{cd: cd, url: urlLabel})
	return nil
}

// IsProxyConfigured reports whether a proxy is in effect. Callers that cannot
// meaningfully operate through a proxy (UDP probes, local-IP discovery) should
// consult this and short-circuit.
func IsProxyConfigured() bool { return proxyHolder.Load() != nil }

// ProxyURL returns the configured proxy URL (redacted), or "" if none.
func ProxyURL() string {
	if h := proxyHolder.Load(); h != nil {
		return h.url
	}
	return ""
}

// libcForwarder is the base proxy.Dialer used to reach the SOCKS5 server
// itself. Goes through directDial so the TCP connect to the proxy is still
// hookable by LD_PRELOAD.
type libcForwarder struct{}

func (libcForwarder) Dial(network, address string) (net.Conn, error) {
	return directDial(network, address, DefaultTimeout)
}

func (libcForwarder) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return directDialContext(ctx, network, address)
}

// DialContext is a context-aware variant of Dial, suitable as an
// http.Transport.DialContext. Priority: package-level SetDial override, then
// configured SOCKS5 proxy, then the platform direct dialer. UDP under -proxy
// returns ErrUDPUnderProxy rather than letting a cryptic "network not
// implemented" bubble up from the SOCKS5 layer.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if _, _, err := splitHostPort(address); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d := currentDial(); d != nil {
		return d(ctx, network, address)
	}
	if h := proxyHolder.Load(); h != nil {
		if strings.HasPrefix(network, "udp") {
			return nil, ErrUDPUnderProxy
		}
		return h.cd.DialContext(ctx, network, address)
	}
	return directDialContext(ctx, network, address)
}

// DialUDP opens a connected UDP socket to address. Returns ErrUDPUnderProxy
// if a proxy is configured. SOCKS5 UDP ASSOCIATE is rarely supported and
// silently bypassing the proxy under -proxy would reveal the operator's real
// source IP.
func DialUDP(address string) (*net.UDPConn, error) {
	if IsProxyConfigured() {
		return nil, ErrUDPUnderProxy
	}
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return net.DialUDP("udp", nil, addr)
}
