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

// wmiexec is a thin CLI wrapper around the pkg/wmiexec library. All the heavy
// DCOM bootstrap, NTLM/Kerberos negotiation and Win32_Process.Create calls
// live in pkg/wmiexec so other Go projects can drive the exact same flow
// without forking this main.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Mzack9999/goimpacket/pkg/flags"
	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/wmiexec"
)

var (
	noOutput      = flag.Bool("nooutput", false, "Don't retrieve command output")
	silentCommand = flag.Bool("silentcommand", false, "does not execute cmd.exe to run given command (no output)")
	share         = flag.String("share", "ADMIN$", "Share to use for output retrieval")
	shell         = flag.String("shell", wmiexec.DefaultShell, "Shell prefix for command execution")
	shellType     = flag.String("shell-type", "cmd", "Choose shell type: cmd or powershell")
	codec         = flag.String("codec", "", "Sets encoding used (codec) from the target's output (default \"utf-8\")")
	comVersion    = flag.String("com-version", "", "DCOM version, format is MAJOR_VERSION:MINOR_VERSION (e.g. 5.7)")
	timeout       = flag.Int("timeout", 30, "Timeout in seconds waiting for command output")
)

func main() {
	_, _ = codec, comVersion
	opts := flags.Parse()

	if *silentCommand {
		*shell = ""
		*noOutput = true
	}
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

	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	sess, err := wmiexec.Dial(context.Background(), target, &creds, wmiexec.DialOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] WMI dial failed: %v\n", err)
		os.Exit(1)
	}
	defer sess.Close()

	execOpts := wmiexec.Options{
		Share:     *share,
		Shell:     *shell,
		ShellType: *shellType,
		NoOutput:  *noOutput,
		Stealth:   *silentCommand,
		Timeout:   time.Duration(*timeout) * time.Second,
	}

	command := opts.Command()
	if command == "" {
		interactiveShell(sess, execOpts)
		return
	}
	res, err := sess.Exec(command, execOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(res.Output)
}

// interactiveShell drives a semi-interactive REPL on top of wmiexec.Session.
// PWD tracking is preserved so cd works as expected.
func interactiveShell(sess *wmiexec.Session, opts wmiexec.Options) {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	pwd := "C:\\"
	opts.PWD = pwd

	// Best-effort initial prompt by resolving the actual PWD.
	if r, err := sess.Exec("cd", opts); err == nil {
		out := strings.TrimSpace(r.Output)
		if out != "" && strings.Contains(out, ":\\") {
			pwd = strings.ReplaceAll(out, "\r\n", "")
			opts.PWD = pwd
		}
	}

	prompt := pwd + ">"
	if opts.ShellType == "powershell" {
		prompt = "PS " + prompt + " "
	}

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
		if strings.HasPrefix(strings.ToLower(cmd), "cd") {
			r, err := sess.Exec(cmd+" && cd", opts)
			if err == nil {
				lines := strings.Split(strings.TrimSpace(r.Output), "\r\n")
				if len(lines) > 0 {
					potential := strings.TrimSpace(lines[len(lines)-1])
					if strings.Contains(potential, ":\\") {
						pwd = potential
						opts.PWD = pwd
						prompt = pwd + ">"
						if opts.ShellType == "powershell" {
							prompt = "PS " + prompt + " "
						}
					}
				}
			} else {
				fmt.Fprintf(os.Stderr, "[-] cd failed: %v\n", err)
			}
			continue
		}
		r, _ := sess.Exec(cmd, opts)
		fmt.Print(r.Output)
	}
}
