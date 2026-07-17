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

// Package transport provides the shared TCP/TLS dialer used across goimpacket.
//
// Dial routing priority:
//  1. Per-instance Dialer.DialFn (embedders / per-execution routing)
//  2. Package-level SetDial override (global embedder hook / tripwire)
//  3. SOCKS5 proxy from Configure / ALL_PROXY
//  4. Platform direct dialer (libc connect on Unix/cgo, net.Dialer elsewhere)
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is the default connect timeout in seconds.
const DefaultTimeout = 30

// DialFunc is the signature accepted by SetDial and Dialer.DialFn.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

var (
	dialMu       sync.RWMutex
	dialOverride DialFunc
)

// SetDial installs a custom dialer used by Dial/DialTimeout/DialTLS/DialContext
// when no per-instance Dialer.DialFn is set. Pass nil to reset.
//
// Embedders (e.g. nuclei) typically install a tripwire here that refuses to
// dial unless an execution-bound Dialer was used, and pass per-call DialFn
// via Dialer / NewClientWithDialer / DialTCPWithDialer.
func SetDial(fn DialFunc) {
	dialMu.Lock()
	dialOverride = fn
	dialMu.Unlock()
}

func currentDial() DialFunc {
	dialMu.RLock()
	defer dialMu.RUnlock()
	return dialOverride
}

// Dial opens a TCP connection. Honors SetDial, then the configured proxy, then
// the platform's direct dialer (libc connect() on Unix/cgo, net.Dialer elsewhere).
func Dial(network, address string) (net.Conn, error) {
	return DialTimeout(network, address, DefaultTimeout)
}

// DialTimeout is Dial with an explicit connect timeout in seconds.
// A non-positive timeoutSec is normalized to DefaultTimeout so the direct and
// proxy branches behave consistently.
func DialTimeout(network, address string, timeoutSec int) (net.Conn, error) {
	if timeoutSec <= 0 {
		timeoutSec = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()
	return DialContext(ctx, network, address)
}

// DialTLS opens a TCP connection (via SetDial/proxy if configured) and wraps it in TLS.
func DialTLS(network, address string, config *tls.Config) (*tls.Conn, error) {
	rawConn, err := Dial(network, address)
	if err != nil {
		return nil, err
	}
	host, _, _ := splitHostPort(address)
	if config.ServerName == "" {
		config = config.Clone()
		config.ServerName = host
	}
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

// Dialer is a value-typed dialer suitable for APIs that expect a struct with a
// Dial method (e.g. pkg/smb, pkg/ldap). When DialFn is set it is used for every
// Dial/DialContext on this instance, bypassing the package-level SetDial
// override, proxy, and stdlib fallback. Embedders should install a DialFn
// closure that captures any per-call state (e.g. an execution id).
type Dialer struct {
	TimeoutSec int
	DialFn     DialFunc
}

// Dial establishes a TCP connection to address.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	timeout := DefaultTimeout
	if d != nil && d.TimeoutSec > 0 {
		timeout = d.TimeoutSec
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	return d.DialContext(ctx, network, address)
}

// DialContext establishes a TCP connection honoring the context. Per-instance
// DialFn takes precedence over the package-level SetDial hook.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if _, _, err := splitHostPort(address); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if d != nil && d.DialFn != nil {
		return d.DialFn(ctx, network, address)
	}
	return DialContext(ctx, network, address)
}

// ContextDialer is the value-typed counterpart of Dialer for APIs that expect
// a DialContext method (e.g. github.com/oiweiwei/go-msrpc/dcerpc.WithDialer,
// net/http.Transport.DialContext). Respects SetDial and the configured proxy.
// The zero value works.
type ContextDialer struct{}

// DialContext routes through SetDial / proxy if set, honoring ctx.
func (ContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return DialContext(ctx, network, address)
}

func splitHostPort(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		if !strings.Contains(address, ":") {
			return address, "", fmt.Errorf("missing port in address: %s", address)
		}
		return "", "", fmt.Errorf("invalid address %q: %w", address, err)
	}
	return host, port, nil
}
