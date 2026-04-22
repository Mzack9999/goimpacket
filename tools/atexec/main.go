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

// atexec is a thin CLI wrapper around the pkg/atexec library. All the heavy
// lifting (task XML, register / run / poll-output / cleanup) lives in
// pkg/atexec so other Go projects can reuse the exact same logic without
// forking this main.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Mzack9999/goimpacket/pkg/atexec"
	"github.com/Mzack9999/goimpacket/pkg/dcerpc"
	"github.com/Mzack9999/goimpacket/pkg/dcerpc/tsch"
	"github.com/Mzack9999/goimpacket/pkg/flags"
	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/smb"
)

var (
	noOutput      = flag.Bool("nooutput", false, "Don't retrieve command output")
	codec         = flag.String("codec", "", "Output encoding (e.g., cp850, utf-8)")
	timeout       = flag.Int("timeout", 30, "timeout in seconds waiting for command output")
	silentCommand = flag.Bool("silentcommand", false, "does not execute cmd.exe to run given command (no output)")
	sessionId     = flag.Int("session-id", -1, "Session ID to run the task in (requires SYSTEM privileges)")
)

func main() {
	_ = codec
	opts := flags.Parse()

	if opts.TargetStr == "" {
		flag.Usage()
		os.Exit(1)
	}

	target, creds, err := session.ParseTargetString(opts.TargetStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error parsing target string: %v\n", err)
		os.Exit(1)
	}
	opts.ApplyToSession(&target, &creds)

	if creds.DCIP != "" {
		target.IP = creds.DCIP
	}
	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	atPipe, err := smbClient.OpenPipe("atsvc")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open atsvc pipe: %v\n", err)
		os.Exit(1)
	}
	defer atPipe.Close()

	rpcClient := dcerpc.NewClient(atPipe)
	if creds.UseKerberos {
		if err := rpcClient.BindAuthKerberos(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, &creds, target.Host); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to bind ITaskSchedulerService (Kerberos): %v\n", err)
			os.Exit(1)
		}
	} else {
		if err := rpcClient.BindAuth(tsch.UUID, tsch.MajorVersion, tsch.MinorVersion, &creds); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to bind ITaskSchedulerService: %v\n", err)
			os.Exit(1)
		}
	}
	ts := tsch.NewTaskScheduler(rpcClient)

	execOpts := atexec.Options{
		Share:     "ADMIN$",
		Timeout:   time.Duration(*timeout) * time.Second,
		NoOutput:  *noOutput,
		Silent:    *silentCommand,
		SessionID: *sessionId,
	}

	command := opts.Command()
	if command == "" {
		interactiveShell(ts, smbClient, execOpts)
		return
	}
	res, err := atexec.Exec(ts, smbClient, command, execOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(res.Output)
}

// interactiveShell drives a semi-interactive REPL on top of atexec.Exec.
// Kept inside the CLI tool because nothing about it belongs in a library.
func interactiveShell(ts *tsch.TaskScheduler, smbClient *smb.Client, opts atexec.Options) {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	prompt := "C:\\Windows\\system32>"
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print(prompt)
		if !scanner.Scan() {
			fmt.Println()
			break
		}
		cmd := strings.TrimSpace(scanner.Text())
		if cmd == "" {
			continue
		}
		if strings.EqualFold(cmd, "exit") {
			break
		}
		if strings.HasPrefix(cmd, "!") {
			localCmd := strings.TrimPrefix(cmd, "!")
			if localCmd == "" {
				fmt.Println("[!] Usage: !command - runs command on local system")
				continue
			}
			out, err := exec.Command("sh", "-c", localCmd).CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Local command error: %v\n", err)
			}
			fmt.Print(string(out))
			continue
		}
		res, err := atexec.Exec(ts, smbClient, cmd, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			continue
		}
		fmt.Print(res.Output)
	}
}
