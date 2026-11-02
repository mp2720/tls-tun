package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/songgao/water"
)

type Server struct {
	BindAddr        string
	TLSCfg          *tls.Config
	Iface           *water.Interface
	WhiteList       map[netip.AddrPort]struct{}
	ProxyTargetAddr string
}

func (s *Server) Run() error {
	listener, err := net.Listen("tcp", s.BindAddr)
	if err != nil {
		return err
	}
	defer listener.Close()
	log.Printf("Listening on %s", s.BindAddr)
	if s.TLSCfg == nil {
		log.Print("WARN: Accepting plaintext TCP connections")
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

		allowed := filterTCPAddr(conn.RemoteAddr(), s.WhiteList)
		if allowed {
			log.Printf("Accepted client %d from %s (whitelisted)", clientNo, conn.RemoteAddr())

			if s.TLSCfg != nil {
				conn = tls.Client(conn, s.TLSCfg)
			}

			go sender(nil, clientNo, s.Iface, conn)
			go receiver(nil, clientNo, s.Iface, conn, prevConn)

			prevConn = conn
		} else {
			log.Printf("Accepted client %d from %s: not in whitelist, serving as proxy", clientNo, conn.RemoteAddr())
			go ReverseProxyRoutine(clientNo, conn, s.ProxyTargetAddr)
		}

		clientNo++
	}
}

func filterTCPAddr(addr net.Addr, whitelist map[netip.AddrPort]struct{}) (allowed bool) {
	if len(whitelist) == 0 {
		return true
	}

	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		log.Printf("Remote address is not TCPAddr (!?)")
		return false
	}

	_, ok = whitelist[tcpAddr.AddrPort()]
	if ok {
		return true
	}

	_, ok = whitelist[netip.AddrPortFrom(tcpAddr.AddrPort().Addr(), 0)]
	return ok
}

func LoadServerTLSConfig(
	serverKeyPath string,
	serverCertPath string,
	clientCertPath string,
) (*tls.Config, error) {
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
	return &tls.Config{
		Certificates: []tls.Certificate{servCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCertPool,
	}, nil
}
