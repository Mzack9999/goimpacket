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

//go:build !cgo || windows

package transport

import (
	"context"
	"net"
	"time"
)

// directDial opens a connection using the Go standard net.Dialer, bypassing
// any configured proxy. This path is used on Windows and on CGO_ENABLED=0
// builds. It does not interoperate with LD_PRELOAD proxies like proxychains.
// Users on those platforms should use the -proxy flag instead.
func directDial(network, address string, timeoutSec int) (net.Conn, error) {
	d := net.Dialer{Timeout: time.Duration(timeoutSec) * time.Second}
	return d.Dial(network, address)
}

// directDialContext dials directly using ctx for timeout/cancellation.
func directDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
