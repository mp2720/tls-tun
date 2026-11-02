package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"

	"github.com/songgao/water"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage\n")
	fmt.Fprintf(os.Stderr, "  server:\n")
	fmt.Fprintf(os.Stderr, "    %s listen [--fwmark <fwmark>] [--server-key <key path> --server-cert <cert path> --client-cert <cert path>] <bind address> <interface>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  client:\n")
	fmt.Fprintf(os.Stderr, "    %s connect [--fwmark <fwmark>] [--client-key <key path> --client-cert <cert path> --server-cert <cert path>] <server address> <interface>\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Key & certs flags should either be all specified (thus enabling TLS mode) or omitted for plaintext TCP.\n")
	fmt.Fprintf(os.Stderr, "Firewall mark is set for socket iff the --fwmark flag is specified.\n")
}

func createTUN(name string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: name,
		},
	})
}

func newServerFromArgs(args []string) (*Server, error) {
	var (
		serverKeyPath  string
		serverCertPath string
		clientCertPath string
	)
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	fs.StringVar(&serverKeyPath, "server-key", "", "Path to the server key file")
	fs.StringVar(&serverCertPath, "server-cert", "", "Path to the server cert file")
	fs.StringVar(&clientCertPath, "client-cert", "", "Path to the client cert file")
	fs.Usage = usage
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 2 {
		return nil, errors.New("Invalid use: bind address and interface must be provided")
	}

	var secure bool
	if serverKeyPath == "" && serverCertPath == "" && clientCertPath == "" {
		secure = false
	} else if serverKeyPath != "" && serverCertPath != "" && clientCertPath != "" {
		secure = true
	} else {
		return nil, errors.New("Invalid use: either all key/cert flags should be set or none of them")
	}

	addr := fs.Arg(0)
	ifaceName := fs.Arg(1)

	iface, err := createTUN(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN: %w", err)
	}

	server := Server{
		BindAddr:       addr,
		Secure:         secure,
		ServerCertPath: serverCertPath,
		ServerKeyPath:  serverKeyPath,
		ClientCertPath: clientCertPath,
		Iface:          iface,
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

	var secure bool
	if clientKeyPath == "" && clientCertPath == "" && serverCertPath == "" {
		secure = false
	} else if clientKeyPath != "" && clientCertPath != "" && serverCertPath != "" {
		secure = true
	} else {
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
		ServerAddr:     addr,
		Secure:         secure,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		ServerCertPath: serverCertPath,
		Iface:          iface,
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
