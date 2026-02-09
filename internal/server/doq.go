package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/davidgroves/gadget-dns-server/internal/handler"
	"github.com/davidgroves/gadget-dns-server/internal/logging"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const doqALPN = "doq"

// serveDoQ starts a DNS over QUIC server on addr. It blocks until the listener fails.
func serveDoQ(ctx context.Context, h *handler.Handler, addr, tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{doqALPN},
	}
	listener, err := quic.ListenAddr(addr, tlsConfig, &quic.Config{})
	if err != nil {
		return err
	}
	defer listener.Close()
	logging.Info("DoQ listening", "addr", addr)
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return err
		}
		go handleDoQConn(conn, h)
	}
}

func handleDoQConn(conn quic.Connection, h *handler.Handler) {
	defer conn.CloseWithError(0, "")
	ctx := context.Background()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go handleDoQStream(stream, conn.RemoteAddr(), h)
	}
}

func handleDoQStream(stream quic.Stream, remoteAddr net.Addr, h *handler.Handler) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf)
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(msgBuf); err != nil {
		return
	}
	msg := h.Handle(req, remoteAddr, "DoQ")
	packed, err := msg.Pack()
	if err != nil {
		return
	}
	binary.BigEndian.PutUint16(lenBuf, uint16(len(packed)))
	if _, err := stream.Write(lenBuf); err != nil {
		return
	}
	if _, err := stream.Write(packed); err != nil {
		return
	}
}
