package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/songgao/water"
)

type Server struct {
	BindAddr       string
	Secure         bool
	ServerCertPath string
	ServerKeyPath  string
	ClientCertPath string
	Iface          *water.Interface
}

func (s *Server) Run() error {
	var listener net.Listener
	if s.Secure {
		var err error
		listener, err = listenTLS(s.ServerKeyPath, s.ServerCertPath, s.ClientCertPath, s.BindAddr)
		if err != nil {
			return fmt.Errorf("Failed to listen TLS: %w", err)
		}
		defer listener.Close()
		log.Printf("Listening for TLS on %s", s.BindAddr)
	} else {
		var err error
		listener, err = listen(s.BindAddr)
		if err != nil {
			return fmt.Errorf("Failed to listen plaintext TCP: %w", err)
		}
		defer listener.Close()
		log.Printf("WARNING: Listening for plaintext TCP on %s", s.BindAddr)
	}

	var (
		prevConn net.Conn
		clientNo int
	)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept: %s", err)
			continue
		}
		log.Printf("Accepted %s", conn.RemoteAddr())

		go sender(nil, clientNo, s.Iface, conn)
		go receiver(nil, clientNo, s.Iface, conn, prevConn)

		prevConn = conn
		clientNo++
	}
}

func listen(bind string) (net.Listener, error) {
	return net.Listen("tcp", bind)
}

func listenTLS(
	serverKeyPath string,
	serverCertPath string,
	clientCertPath string,
	bind string,
) (net.Listener, error) {
	servCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, err
	}
	clientCertBytes, err := os.ReadFile(clientCertPath)
	if err != nil {
		return nil, err
	}
	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(clientCertBytes) {
		err = errors.New("failed to load client cert")
		return nil, err
	}

	cfg := tls.Config{
		Certificates: []tls.Certificate{servCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}

	return tls.Listen("tcp", bind, &cfg)
}
