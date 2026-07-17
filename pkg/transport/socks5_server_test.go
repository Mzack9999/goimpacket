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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// testSOCKS5 is a minimal SOCKS5 server for use in transport tests. It
// supports only CONNECT with no authentication (method 0x00) and only IPv4
// and DOMAIN address types. It is NOT a production SOCKS5 implementation.
type testSOCKS5 struct {
	ln       net.Listener
	addr     string
	wg       sync.WaitGroup
	connects atomic.Int32 // number of successful CONNECTs handled
}

// newTestSOCKS5 starts a SOCKS5 server on 127.0.0.1 with an ephemeral port.
// It terminates when t.Cleanup runs.
func newTestSOCKS5(t *testing.T) *testSOCKS5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSOCKS5{ln: ln, addr: ln.Addr().String()}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *testSOCKS5) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *testSOCKS5) handle(client net.Conn) {
	defer client.Close()

	// Greeting: VER | NMETHODS | METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// Accept only NO AUTH (0x00)
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 /* CONNECT */ {
		_, _ = client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // cmd not supported
		return
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03: // DOMAIN
		lb := make([]byte, 1)
		if _, err := io.ReadFull(client, lb); err != nil {
			return
		}
		b := make([]byte, lb[0])
		if _, err := io.ReadFull(client, b); err != nil {
			return
		}
		host = string(b)
	default:
		_, _ = client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // atyp not supported
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(client, pb); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(pb)

	target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		_, _ = client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // conn refused
		return
	}
	defer target.Close()

	// Reply: VER | REP=0 | RSV | ATYP=1 | BND.ADDR=0 | BND.PORT=0
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	s.connects.Add(1)

	// Splice both directions
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, target); done <- struct{}{} }()
	<-done
}
