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

// smbexec is a thin CLI wrapper around the pkg/smbexec library. The service-
// creation / start / poll-output / cleanup flow lives in pkg/smbexec so other
// Go projects can drive the exact same logic.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mzack9999/goimpacket/pkg/dcerpc"
	"github.com/Mzack9999/goimpacket/pkg/dcerpc/svcctl"
	"github.com/Mzack9999/goimpacket/pkg/flags"
	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/smb"
	"github.com/Mzack9999/goimpacket/pkg/smbexec"
)

var (
	noOutput    = flag.Bool("nooutput", false, "Don't retrieve command output")
	share       = flag.String("share", "C$", "Share to use for output retrieval (default C$)")
	mode        = flag.String("mode", "SHARE", "Mode to use: SHARE or SERVER (SERVER needs root!)")
	serviceName = flag.String("service-name", "", "The name of the service used to trigger the payload")
	shellType   = flag.String("shell-type", "cmd", "Choose a command processor for the semi-interactive shell")
	codec       = flag.String("codec", "", "Output encoding (e.g., cp850, utf-8). If not set, uses raw bytes")
	timeout     = flag.Int("timeout", 30, "Timeout in seconds waiting for command output")
)

const (
	smbServerShare = "TMP"
	smbServerDir   = "__tmp"
	outputFilename = "__output"
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
	if !opts.NoPass {
		if err := session.EnsurePassword(&creds); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	libMode := smbexec.Mode(strings.ToUpper(*mode))
	if libMode != smbexec.ModeShare && libMode != smbexec.ModeServer {
		fmt.Fprintf(os.Stderr, "[-] Invalid mode '%s'. Must be SHARE or SERVER.\n", *mode)
		os.Exit(1)
	}

	smbClient := smb.NewClient(target, &creds)
	if err := smbClient.Connect(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] SMB connection failed: %v\n", err)
		os.Exit(1)
	}
	defer smbClient.Close()

	svcPipe, err := smbClient.OpenPipe("svcctl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open svcctl pipe: %v\n", err)
		os.Exit(1)
	}
	defer svcPipe.Close()

	svcRPC := dcerpc.NewClient(svcPipe)
	if err := svcRPC.Bind(svcctl.UUID, svcctl.MajorVersion, svcctl.MinorVersion); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to bind svcctl: %v\n", err)
		os.Exit(1)
	}
	sc, err := svcctl.NewServiceController(svcRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create service controller: %v\n", err)
		os.Exit(1)
	}
	defer sc.Close()

	var serverLocalIP string
	if libMode == smbexec.ModeServer {
		serverLocalIP = getLocalIP(target.Host)
		if serverLocalIP == "" {
			fmt.Fprintln(os.Stderr, "[-] Could not determine local IP for SERVER mode")
			os.Exit(1)
		}
		if err := os.MkdirAll(smbServerDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to create local directory %s: %v\n", smbServerDir, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[*] SERVER mode: output will be received via \\\\%s\\%s\n", serverLocalIP, smbServerShare)
		fmt.Fprintf(os.Stderr, "[!] SERVER mode requires a local SMB server sharing '%s' as '%s' on port 445 (needs root)\n", smbServerDir, smbServerShare)
		fmt.Fprintf(os.Stderr, "[!] Start one with: sudo impacket-smbserver %s %s -smb2support\n", smbServerShare, smbServerDir)
	}

	// CLI keeps Impacket's fixed __output filename so users running multiple
	// tools side-by-side recognize it; the library would otherwise generate
	// a per-call random one.
	execOpts := smbexec.Options{
		Share:         *share,
		Mode:          libMode,
		ServiceName:   *serviceName,
		OutputFile:    outputFilename,
		ShellType:     *shellType,
		NoOutput:      *noOutput,
		Timeout:       time.Duration(*timeout) * time.Second,
		ServerLocalIP: serverLocalIP,
		ServerShare:   smbServerShare,
	}

	command := opts.Command()
	if command == "" {
		interactiveShell(sc, smbClient, execOpts)
		return
	}
	res, err := smbexec.Exec(sc, smbClient, command, execOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Execution failed: %v\n", err)
		os.Exit(1)
	}
	out := res.Output
	if execOpts.Mode == smbexec.ModeServer && !execOpts.NoOutput {
		out = readServerOutput(execOpts.Timeout)
	}
	fmt.Print(out)
}

// interactiveShell drives a semi-interactive REPL on top of smbexec.Exec.
// Lives in the CLI tool only.
func interactiveShell(sc *svcctl.ServiceController, smbClient *smb.Client, opts smbexec.Options) {
	fmt.Println("[!] Launching semi-interactive shell - Careful what you execute")
	fmt.Println("[!] Press Ctrl+D or type 'exit' to quit")
	fmt.Println("[!] Type '!command' to run local commands")

	prompt := "C:\\Windows\\system32>"
	if r, err := smbexec.Exec(sc, smbClient, "cd", opts); err == nil {
		out := strings.TrimSpace(r.Output)
		if opts.Mode == smbexec.ModeServer {
			out = strings.TrimSpace(readServerOutput(opts.Timeout))
		}
		if out != "" {
			prompt = strings.ReplaceAll(out, "\r\n", "") + ">"
		}
	}
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
			r, err := smbexec.Exec(sc, smbClient, cmd+" & cd", opts)
			if err == nil {
				out := r.Output
				if opts.Mode == smbexec.ModeServer {
					out = readServerOutput(opts.Timeout)
				}
				lines := strings.Split(strings.TrimSpace(out), "\r\n")
				if len(lines) > 0 {
					last := strings.TrimSpace(lines[len(lines)-1])
					if strings.Contains(last, ":\\") || strings.Contains(last, ":/") {
						prompt = last + ">"
						if opts.ShellType == "powershell" {
							prompt = "PS " + prompt + " "
						}
					}
				}
			}
			continue
		}
		r, err := smbexec.Exec(sc, smbClient, cmd, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error: %v\n", err)
			continue
		}
		out := r.Output
		if opts.Mode == smbexec.ModeServer {
			out = readServerOutput(opts.Timeout)
		}
		fmt.Print(out)
	}

	// Cleanup any leftover service / output file.
	if opts.Mode == smbexec.ModeShare {
		_ = smbClient.Rm(opts.OutputFile)
	} else {
		_ = os.Remove(filepath.Join(smbServerDir, outputFilename))
		_ = os.Remove(smbServerDir)
	}
}

// readServerOutput tails the local impacket-smbserver landing directory for
// the captured output file. Lives in the CLI because the library is
// agnostic to how the caller's local SMB server stores files.
func readServerOutput(timeout time.Duration) string {
	localPath := filepath.Join(smbServerDir, outputFilename)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		data, err := os.ReadFile(localPath)
		if err == nil {
			_ = os.Remove(localPath)
			return string(data)
		}
	}
	return ""
}

// getLocalIP determines the local IP address used to reach the target host.
func getLocalIP(targetHost string) string {
	conn, err := net.Dial("udp", targetHost+":445")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}
