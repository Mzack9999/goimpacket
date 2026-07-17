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

//go:build cgo && !windows

package transport

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

// libc_dial connects via libc's getaddrinfo + connect, which ARE hookable by LD_PRELOAD.
// Returns the file descriptor on success, or -1 (getaddrinfo fail) / -2 (connect fail) on error.
int libc_dial(const char *host, const char *port, int timeout_sec) {
    struct addrinfo hints, *res, *p;
    int sockfd;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rv = getaddrinfo(host, port, &hints, &res);
    if (rv != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) continue;

        // Set connect timeout via SO_SNDTIMEO (Linux honors this for connect())
        if (timeout_sec > 0) {
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;
            setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) return -2;

    // Clear the send timeout so it doesn't affect subsequent writes
    if (timeout_sec > 0) {
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    return sockfd;
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"
)

// directDial opens a connection via libc connect(), bypassing any configured
// proxy. The libc path is what LD_PRELOAD-based proxies like proxychains hook.
// UDP falls through to net.Dial because libc_dial is wired for SOCK_STREAM only
// and LD_PRELOAD proxies rarely handle UDP anyway.
func directDial(network, address string, timeoutSec int) (net.Conn, error) {
	if strings.HasPrefix(network, "udp") {
		return net.Dial(network, address)
	}

	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	cHost := C.CString(host)
	cPort := C.CString(port)
	defer C.free(unsafe.Pointer(cHost))
	defer C.free(unsafe.Pointer(cPort))

	fd := C.libc_dial(cHost, cPort, C.int(timeoutSec))
	if fd == -1 {
		return nil, fmt.Errorf("getaddrinfo failed for %s", address)
	}
	if fd == -2 {
		return nil, fmt.Errorf("connect failed for %s", address)
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("tcp:%s", address))
	conn, err := net.FileConn(f)
	f.Close() // FileConn dups the fd
	if err != nil {
		return nil, fmt.Errorf("FileConn failed: %w", err)
	}
	return conn, nil
}

// directDialContext dials directly, honoring ctx's deadline for the connect timeout.
func directDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	timeout := DefaultTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 {
			timeout = int(d.Seconds())
			if timeout < 1 {
				timeout = 1
			}
		}
	}
	return directDial(network, address, timeout)
}
