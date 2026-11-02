package main

import "io"

func readAll(rd io.Reader, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		bytesRead, err := rd.Read(buf[offset:])
		if err != nil {
			return err
		}
		offset += bytesRead
	}
	return nil
}

func writeAll(wr io.Writer, buf []byte) error {
	offset := 0
	for offset < len(buf) {
		written, err := wr.Write(buf[offset:])
		if err != nil {
			return err
		}
		offset += written
	}
	return nil
}
