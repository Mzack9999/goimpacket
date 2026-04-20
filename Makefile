# Makefile for goimpacket
#
# CGO is required to build all tools because pkg/transport uses libc's
# connect() so that LD_PRELOAD-based proxies (proxychains) can hook it.
# libpcap headers are NOT required at build time: the cgo-free
# github.com/Mzack9999/gopacket fork loads libpcap dynamically at runtime
# via purego.

CC=gcc
TOOLS=$(shell ls tools/)

# -static-libgcc is GNU ld only; clang/ld64 on macOS rejects it.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	LDFLAGS := -ldflags '-linkmode external -extldflags "-static-libgcc"'
else
	LDFLAGS :=
endif

all: build

build:
	@mkdir -p bin/
	@for tool in $(TOOLS); do \
		echo "[*] Building $$tool..."; \
		CGO_ENABLED=1 go build -o bin/$$tool $(LDFLAGS) tools/$$tool/main.go; \
	done

clean:
	rm -rf bin/

.PHONY: all build clean
