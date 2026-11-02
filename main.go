package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"strings"

	"github.com/songgao/water"
)

func usage() {
	msgFmt := `Usage
  server:
    %[1]s listen [--fwmark <fwmark>] [--server-key <server key path> --server-cert <server cert path> --client-cert <client cert path>] [--whitelist <addr1:port,addr2:port,...> --fallback-proxy-to <target address>] <bind address> <interface>

  client:
    %[1]s connect [--fwmark <fwmark>] [--client-key <client key path> --client-cert <client cert path> --server-cert <server cert path>] <server address> <interface>

Key & certs flags should either be all specified (thus enabling TLS mode) or omitted for plaintext TCP.
Firewall mark is set for socket iff the --fwmark flag is specified.
If whitelist (comma separated list of address:port pairs) is specified, so should be the fallback reverse proxy target address. Any non-whitelisted inbound connection will be TCP-proxied to the target address. Zero port matches all ports.
`
	fmt.Fprintf(os.Stderr, msgFmt, os.Args[0])
}

func createTUN(name string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})
}

func parseWhitelist(s string) (map[netip.AddrPort]struct{}, error) {
	addrs := make(map[netip.AddrPort]struct{})
	for _, strAddr := range strings.Split(s, ",") {
		addr, err := netip.ParseAddrPort(strings.TrimSpace(strAddr))
		if err != nil {
			return nil, fmt.Errorf("Invalid address %q: %w", strAddr, err)
		}
		addrs[addr] = struct{}{}
	}
	return addrs, nil
}

func newServerFromArgs(args []string) (*Server, error) {
	var (
		serverKeyPath  string
		serverCertPath string
		clientCertPath string
		whitelist      string
		proxyTarget    string
	)
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	fs.StringVar(&serverKeyPath, "server-key", "", "Path to the server key file")
	fs.StringVar(&serverCertPath, "server-cert", "", "Path to the server cert file")
	fs.StringVar(&clientCertPath, "client-cert", "", "Path to the client cert file")
	fs.StringVar(&whitelist, "whitelist", "", "Comma separated array of allowed addresses for inbound connections")
	fs.StringVar(&proxyTarget, "fallback-proxy-to", "", "Fallback proxy target address")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 2 {
		return nil, errors.New("Invalid use: bind address and interface must be provided")
	}

	var tlsCfg *tls.Config
	if serverKeyPath != "" && serverCertPath != "" && clientCertPath != "" {
		var err error
		tlsCfg, err = LoadServerTLSConfig(serverKeyPath, serverCertPath, clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load tls certs or key: %w", err)
		}
	} else if !(serverKeyPath == "" && serverCertPath == "" && clientCertPath == "") {
		return nil, errors.New("Invalid use: either all key/cert flags should be set or none of them")
	}

	parsedWhitelist, err := parseWhitelist(whitelist)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse whitelist: %w", err)
	}

	addr := fs.Arg(0)
	ifaceName := fs.Arg(1)

	iface, err := createTUN(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN: %w", err)
	}

	server := Server{
		BindAddr:        addr,
		TLSCfg:          tlsCfg,
		Iface:           iface,
		WhiteList:       parsedWhitelist,
		ProxyTargetAddr: proxyTarget,
	}
	return &server, nil
}

func newClientFromArgs(args []string) (*Client, error) {
	var (
		clientKeyPath  string
		clientCertPath string
		serverCertPath string
		fwmark         int64
	)
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	fs.StringVar(&clientKeyPath, "client-key", "", "Path to the client key file")
	fs.StringVar(&clientCertPath, "client-cert", "", "Path to the client cert file")
	fs.StringVar(&serverCertPath, "server-cert", "", "Path to the server cert file")
	fs.Int64Var(&fwmark, "fwmark", 0, "Firewall mark")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 2 {
		return nil, errors.New("Invalid use: server address and interface must be provided")
	}

	var tlsCfg *tls.Config
	if clientKeyPath != "" && clientCertPath != "" && serverCertPath != "" {
		var err error
		tlsCfg, err = LoadClientTLSConfig(clientKeyPath, clientCertPath, serverCertPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to load tls certs or key: %w", err)
		}
	} else if !(clientKeyPath == "" && clientCertPath == "" && serverCertPath == "") {
		return nil, errors.New("Invalid use: either all key/cert flags should be set or none of them")
	}

	if fwmark < 0 || fwmark > math.MaxUint32 {
		return nil, errors.New("Invalid use: invalid fwmark")
	}

	addr := fs.Arg(0)
	ifaceName := fs.Arg(1)

	iface, err := createTUN(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN: %w", err)
	}

	client := Client{
		ServerAddr:  addr,
		TLSCfg:      tlsCfg,
		Fwmark:      uint32(fwmark),
		Iface:       iface,
	}
	return &client, nil
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		usage()
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "No command was given")
		usage()
		os.Exit(1)
	}

	if os.Args[1] == "listen" {
		server, err := newServerFromArgs(os.Args[2:])
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				usage()
				os.Exit(0)
			} else {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if err := server.Run(); err != nil {
			log.Fatal(err)
		}
	} else if os.Args[1] == "connect" {
		client, err := newClientFromArgs(os.Args[2:])
		if err != nil {
			if errors.Is(err, flag.ErrHelp) {
				usage()
				os.Exit(0)
			} else {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if err := client.Run(); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Unknown command %q\n", os.Args[1])
		os.Exit(1)
	}
}
