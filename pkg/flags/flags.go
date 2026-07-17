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

package flags

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Mzack9999/goimpacket/internal/build"
	"github.com/Mzack9999/goimpacket/pkg/session"
	"github.com/Mzack9999/goimpacket/pkg/transport"
)

// ExtraUsageLine is appended to the "Usage: tool [options] target" line (e.g. "[maxRid]")
var ExtraUsageLine string

// ExtraUsageText is printed after the grouped help sections (e.g. positional arg descriptions)
var ExtraUsageText string

// Options holds all standard CLI options.
type Options struct {
	// Authentication
	Hashes   string
	NoPass   bool
	Kerberos bool
	AesKey   string
	Keytab   string

	// Connection
	DcHost   string
	DcIP     string
	TargetIP string
	Port     int
	IPv6     bool
	Proxy    string

	// Utility
	InputFile  string
	OutputFile string
	Timestamp  bool

	// Debug
	Debug bool

	// Target (Positional)
	TargetStr string

	// Arguments - remaining positional arguments after target (e.g., command for wmiexec)
	Arguments []string
}

// ProxyFlagUsage is the shared usage string for -proxy. Keep tools consistent
// so the flag behaves identically whether registered via Parse() or
// RegisterProxyFlag().
const ProxyFlagUsage = "SOCKS5 proxy URL (e.g. socks5h://127.0.0.1:1080). Routes TCP through the proxy. UDP features are disabled. If unset, ALL_PROXY env is consulted."

// ConfigureProxy wires the transport layer with the given proxy URL. Exits on
// error so a misconfigured -proxy fails the tool instead of silently bypassing
// the proxy. Call after flag.Parse().
func ConfigureProxy(proxyURL string) {
	if err := transport.Configure(transport.Options{Proxy: proxyURL}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

// RegisterProxyFlag registers -proxy on the default flag.CommandLine and
// returns a finalizer to call after flag.Parse(). Intended for tools that
// hand-roll their flag setup instead of using Parse().
func RegisterProxyFlag() func() {
	proxyURL := flag.String("proxy", "", ProxyFlagUsage)
	return func() { ConfigureProxy(*proxyURL) }
}

// CheckHelp scans os.Args for -h/--help anywhere and shows usage if found.
// Call this after setting flag.Usage but before flag.Parse().
// This handles the case where -h appears after positional arguments,
// which Go's flag package doesn't catch.
func CheckHelp() {
	for _, arg := range os.Args[1:] {
		if arg == "-h" || arg == "--help" || arg == "-help" {
			flag.Usage()
			os.Exit(0)
		}
	}
}

// Parse registers and parses the standard flags.
func Parse() *Options {
	opts := &Options{}

	flag.StringVar(&opts.Hashes, "hashes", "", "NTLM hashes, format is LMHASH:NTHASH")
	flag.BoolVar(&opts.NoPass, "no-pass", false, "don't ask for password (useful for -k)")
	flag.BoolVar(&opts.Kerberos, "k", false, "Use Kerberos authentication")
	flag.StringVar(&opts.AesKey, "aesKey", "", "AES key to use for Kerberos Authentication (128 or 256 bits)")
	flag.StringVar(&opts.Keytab, "keytab", "", "Read keys for SPN from keytab file")

	flag.StringVar(&opts.DcHost, "dc-host", "", "Hostname of the domain controller")
	flag.StringVar(&opts.DcIP, "dc-ip", "", "IP Address of the domain controller")
	flag.StringVar(&opts.TargetIP, "target-ip", "", "IP Address of the target machine")
	flag.IntVar(&opts.Port, "port", 445, "Destination port to connect to SMB Server")
	flag.BoolVar(&opts.IPv6, "6", false, "Connect via IPv6")
	flag.StringVar(&opts.Proxy, "proxy", "", ProxyFlagUsage)

	flag.StringVar(&opts.InputFile, "inputfile", "", "input file with list of entries")
	flag.StringVar(&opts.OutputFile, "outputfile", "", "base output filename")
	flag.BoolVar(&opts.Timestamp, "ts", false, "Adds timestamp to every logging output")

	flag.BoolVar(&opts.Debug, "debug", false, "Turn DEBUG output ON")

	// Custom Usage to mimic Impacket
	flag.Usage = func() {
		printBanner()
		usageLine := fmt.Sprintf("\nUsage: %s [options] target", os.Args[0])
		if ExtraUsageLine != "" {
			usageLine += " " + ExtraUsageLine
		}
		fmt.Fprintln(os.Stderr, usageLine)
		fmt.Fprintln(os.Stderr, "\nTarget:")
		fmt.Fprintln(os.Stderr, "  [[domain/]username[:password]@]<targetName or address>")

		printGroupedHelp()

		if ExtraUsageText != "" {
			fmt.Fprintln(os.Stderr, ExtraUsageText)
		}
	}

	// Check for -h anywhere in args before parsing
	CheckHelp()

	flag.Parse()

	// Set global settings and configure transport unconditionally, even when
	// no positional args were given. Tools that take config entirely via
	// flags (e.g. listeners) still need Debug/Timestamp/-proxy to take effect.
	if opts.Debug {
		build.Debug = true
	}
	if opts.Timestamp {
		build.Timestamp = true
	}
	ConfigureProxy(opts.Proxy)

	// Handle Positional Arguments (target + optional command/args)
	if flag.NArg() == 0 {
		return opts
	}
	opts.TargetStr = flag.Arg(0)
	if flag.NArg() > 1 {
		opts.Arguments = flag.Args()[1:]
	}

	return opts
}

// Version is the current gopacket release version.
const Version = "v0.1.1-beta"

// Banner returns the standard gopacket banner string.
func Banner() string {
	return "gopacket " + Version + " - Copyright 2026 Google LLC"
}

func printBanner() {
	fmt.Fprintln(os.Stderr, Banner())
}

func printGroupedHelp() {
	authFlags := []string{"hashes", "no-pass", "k", "aesKey", "keytab"}
	connFlags := []string{"6", "dc-host", "dc-ip", "target-ip", "port", "proxy"}
	miscFlags := []string{"inputfile", "outputfile", "ts", "debug"}

	// Maps to store flags
	authMap := make(map[string]*flag.Flag)
	connMap := make(map[string]*flag.Flag)
	miscMap := make(map[string]*flag.Flag)
	otherMap := make(map[string]*flag.Flag) // Tool specific

	flag.VisitAll(func(f *flag.Flag) {
		found := false
		for _, name := range authFlags {
			if f.Name == name {
				authMap[f.Name] = f
				found = true
				break
			}
		}
		if found {
			return
		}

		for _, name := range connFlags {
			if f.Name == name {
				connMap[f.Name] = f
				found = true
				break
			}
		}
		if found {
			return
		}

		for _, name := range miscFlags {
			if f.Name == name {
				miscMap[f.Name] = f
				found = true
				break
			}
		}
		if found {
			return
		}

		otherMap[f.Name] = f
	})

	printCategory("Authentication", authMap)
	printCategory("Connection", connMap)
	printCategory("Tool Specific", otherMap)
	printCategory("Miscellaneous", miscMap)
}

func printCategory(name string, flags map[string]*flag.Flag) {
	if len(flags) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\n%s:\n", name)

	// Sort keys
	var keys []string
	for k := range flags {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		f := flags[k]
		s := fmt.Sprintf("  -%s", f.Name)
		name, usage := flag.UnquoteUsage(f)
		if len(name) > 0 {
			s += " " + name
		}
		// Pad to align
		if len(s) <= 4 { // Space for 4 chars
			s += "\t"
		} else {
			s += "\n    \t"
		}
		s += strings.ReplaceAll(usage, "\n", "\n    \t")
		fmt.Fprintln(os.Stderr, s)
	}
}

// Command returns the remaining arguments joined as a single command string.
func (o *Options) Command() string {
	if len(o.Arguments) == 0 {
		return ""
	}
	return strings.Join(o.Arguments, " ")
}

// ApplyToSession updates a Session object with the parsed options.
func (o *Options) ApplyToSession(target *session.Target, creds *session.Credentials) {
	if o.Hashes != "" {
		creds.Hash = o.Hashes
	}
	if o.NoPass {
		creds.Password = ""
	}

	creds.UseKerberos = o.Kerberos
	creds.DCHost = o.DcHost
	creds.DCIP = o.DcIP
	creds.AESKey = o.AesKey
	creds.Keytab = o.Keytab

	if o.TargetIP != "" {
		target.IP = o.TargetIP
	}
	if target.Port == 0 {
		target.Port = o.Port
	} else if o.Port != 445 {
		target.Port = o.Port
	}
	if o.IPv6 {
		target.IPv6 = true
	}
}
