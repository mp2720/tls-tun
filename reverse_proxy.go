package main

import (
	"log"
	"net"
)

func ReverseProxyRoutine(no int, inboundConn net.Conn, targetAddress string) {
	targetConn, err := net.Dial("tcp", targetAddress)
	if err != nil {
		log.Printf("reverse proxy %d: Failed to start: Failed to dial reverse proxy target address: %s", no, err)
	}

	toTarget := func() {
		var rx uint64

		defer targetConn.Close()
		defer inboundConn.Close()
		defer func(rxPtr *uint64) {
			log.Printf("reverse proxy %d (inbound -> target): Terminated; rx: %d bytes", no, *rxPtr)
		}(&rx)

		var buf [8192]byte
		for {
			n, err := inboundConn.Read(buf[:])
			if err != nil {
				log.Printf("reverse proxy %d (inbound -> target): Read from inbound connection failed: %s", no, err)
				return
			}
			rx += uint64(n)

			err = writeAll(targetConn, buf[:n])
			if err != nil {
				log.Printf("reverse proxy %d (inbound -> target): Write to target connection failed: %s", no, err)
				return
			}
		}
	}

	fromTarget := func() {
		var tx uint64

		defer targetConn.Close()
		defer inboundConn.Close()
		defer func(txPtr *uint64) {
			log.Printf("reverse proxy %d (target -> inbound): Terminated; tx: %d bytes", no, *txPtr)
		}(&tx)

		var buf [8192]byte
		for {
			n, err := targetConn.Read(buf[:])
			if err != nil {
				log.Printf("reverse proxy %d (target -> inbound): Read from target connection failed: %s", no, err)
				return
			}
			tx += uint64(n)

			err = writeAll(inboundConn, buf[:n])
			if err != nil {
				log.Printf("reverse proxy %d (target -> inbound): Write to inbound connection failed: %s", no, err)
				return
			}
		}
	}

	go toTarget()
	fromTarget()
}
