package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/songgao/water"
)

type Client struct {
	Secure         bool
	ServerAddr     string
	ClientCertPath string
	ClientKeyPath  string
	ServerCertPath string
	Fwmark         uint32
	Iface          *water.Interface
}

func (c *Client) Run() error {
	var (
		conn    net.Conn
		rawConn syscall.RawConn
	)
	if c.Secure {
		var err error
		conn, rawConn, err = dialTLS(c.ClientKeyPath, c.ClientCertPath, c.ServerCertPath, c.ServerAddr)
		if err != nil {
			return fmt.Errorf("Failed to dial plaintext TCP: %w", err)
		}
		defer conn.Close()
	} else {
		log.Printf("WARNING: dialing plaintext TCP")
		var err error
		conn, rawConn, err = dial(c.ServerAddr)
		if err != nil {
			return fmt.Errorf("Failed to dial plaintext TCP: %w", err)
		}
		defer conn.Close()
	}

	log.Printf("Connected to server")

	if c.Fwmark != 0 {
		err := setFwmark(rawConn, uint32(c.Fwmark))
		if err != nil {
			return fmt.Errorf("Failed to set fwmark: %w", err)
		}
	}

	connClosedCh := make(chan struct{})
	signalCh := make(chan os.Signal, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go sender(&wg, 0, c.Iface, conn)
	go receiver(&wg, 0, c.Iface, conn, nil)
	go func() {
		wg.Wait()
		connClosedCh <- struct{}{}
	}()

	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-connClosedCh:
	case <-signalCh:
	}

	return nil
}

func dial(remoteAddr string) (net.Conn, syscall.RawConn, error) {
	tcpConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		return nil, nil, err
	}
	rawConn, err := tcpConn.(*net.TCPConn).SyscallConn()
	if err != nil {
		tcpConn.Close()
		return nil, nil, err
	}
	return tcpConn, rawConn, nil
}

func dialTLS(
	clientKeyPath string,
	clientCertPath string,
	serverCertPath string,
	remoteAddr string,
) (net.Conn, syscall.RawConn, error) {
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, nil, err
	}
	serverCertBytes, err := os.ReadFile(serverCertPath)
	if err != nil {
		return nil, nil, err
	}
	serverCertPool := x509.NewCertPool()
	if !serverCertPool.AppendCertsFromPEM(serverCertBytes) {
		return nil, nil, errors.New("failed to load server cert")
	}

	cfg := tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCertPool,
	}

	tlsConn, err := tls.Dial("tcp", remoteAddr, &cfg)
	if err != nil {
		return nil, nil, err
	}

	rawConn, err := tlsConn.NetConn().(*net.TCPConn).SyscallConn()
	if err != nil {
		return nil, nil, err
	}

	return tlsConn, rawConn, nil
}
