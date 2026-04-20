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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Mzack9999/goimpacket/pkg/flags"
	"github.com/Mzack9999/goimpacket/pkg/mqtt"
	"github.com/Mzack9999/goimpacket/pkg/session"
)

func main() {
	clientID := flag.String("client-id", "", "Client ID used when authenticating (default random)")
	ssl := flag.Bool("ssl", false, "Turn SSL on")

	flags.ExtraUsageLine = ""
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target: %v\n", err)
		os.Exit(1)
	}

	opts.ApplyToSession(&target, &creds)

	// Default port for MQTT is 1883, not 445
	portSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portSet = true
		}
	})
	if !portSet {
		opts.Port = 1883
	}

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	if *clientID == "" {
		*clientID = " "
	}

	address := target.Host
	if target.IP != "" {
		address = target.IP
	}

	conn, err := mqtt.NewConnection(address, opts.Port, *ssl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	err = conn.Connect(*clientID, creds.Username, creds.Password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[*] Connection Accepted")
}
