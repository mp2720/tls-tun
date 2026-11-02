package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

func sender(wg *sync.WaitGroup, no int, iface io.Reader, wr io.WriteCloser) {
	if wg != nil {
		defer wg.Done()
	}
	defer log.Printf("sender %d: Terminated", no)
	defer wr.Close()

	log.Printf("sender %d: Started", no)

	if err := writeAll(wr, []byte{0x27, 0x20}); err != nil {
		log.Printf("sender %d: Failed to send session ack: %s", no, err)
		return
	}

	packet := new([65536]byte)
	for {
		packetSize, err := iface.Read(packet[:])
		if err != nil {
			log.Printf("sender %d: Failed to read packet from TUN: %s", no, err)
			return
		}

		if err := writeAll(wr, packet[:packetSize]); err != nil {
			log.Printf("sender %d: Failed to send packet: %s", no, err)
			return
		}
	}
}

func receiver(wg *sync.WaitGroup, no int, iface io.Writer, conn net.Conn, prevConn io.Closer) {
	if wg != nil {
		defer wg.Done()
	}
	defer log.Printf("receiver %d: Terminated", no)
	defer conn.Close()

	log.Printf("receiver %d: Started", no)

	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 30)); err != nil {
		log.Printf("receiver %d: Failed to set read deadline: %s", no, err)
		return
	}

	var sessionStartAck [2]byte
	if err := readAll(conn, sessionStartAck[:]); err != nil {
		log.Printf("receiver %d: Failed to read session ack: %s", no, err)
		return
	}
	if sessionStartAck[0] != 0x27 || sessionStartAck[1] != 0x20 {
		log.Printf("receiver %d: Invalid session ack", no)
		return
	}
	if prevConn != nil {
		if err := prevConn.Close(); err != nil {
			log.Printf("receiver %d: Failed to close the previous client socket: %s", no, err)
		} else {
			log.Printf("receiver %d: Closed the previous client socket: %s", no, err)
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		log.Printf("receiver %d: Failed to clear read deadline: %s", no, err)
		return
	}

	var header [8]byte
	packet := new([65536]byte)
	for {
		if err := readAll(conn, header[:]); err != nil {
			log.Printf("receiver %d: Failed to read header: %s", no, err)
			return
		}

		var packetSize int
		switch (header[0] & 0xf0) >> 4 {
		case 4:
			packetSize = int(header[2])<<8 | int(header[3])
		case 6:
			packetSize = 40 + (int(header[4])<<8 | int(header[5]))
		default:
			log.Printf("receiver %d: Invalid packet header", no)
			return
		}

		copy(packet[0:8], header[:])

		if err := readAll(conn, packet[8:packetSize]); err != nil {
			log.Printf("receiver %d: Failed to receive packet: %s", no, err)
			return
		}

		_, err := iface.Write(packet[:packetSize])
		if err != nil {
			log.Printf("receiver %d: Failed to write packet to TUN: %s", no, err)
			// may happen if, for example, the interface is not ready yet.
			// so, no reason to fail
		}
	}
}
