package socks5

import (
	"fmt"
	"net"
	"time"

	"github.com/nikandfor/errors"
)

type (
	UDPConn struct {
		raddr net.Addr
		udp   net.Conn
		tcp   net.Conn
	}
)

func (c UDPConn) Read(p []byte) (n int, err error) {
	n, _, err = c.ReadFrom(p)
	return
}

func (c UDPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, err = c.udp.Read(p)
		if err != nil {
			return
		}

		if n < 6 {
			continue
		}

		if p[2] != 0 {
			continue
		}

		var i int

		addr, i, err = parseAddr(p, 3, true)
		if err != nil {
			continue
		}

		copy(p, p[i:])

		return n - i, addr, nil
	}
}

func (c UDPConn) Write(p []byte) (n int, err error) {
	return c.WriteTo(p, c.raddr)
}

func (c UDPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	l := 6 + 256 + len(p)

	d := make([]byte, l)

	d[0] = 0
	d[1] = 0
	d[2] = 0

	i, err := encodeAddr(d, 3, addr)
	if err != nil {
		return 0, errors.Wrap(err, "encode addr")
	}

	copy(d[i:], p)

	n, err = c.udp.Write(d[:i+len(p)])
	if err != nil {
		return n, err
	}

	return n - i, nil
}

func (c UDPConn) LocalAddr() net.Addr {
	return c.udp.LocalAddr()
}

func (c UDPConn) RemoteAddr() net.Addr {
	return c.udp.RemoteAddr()
}

func (c UDPConn) SetDeadline(t time.Time) error {
	return c.udp.SetDeadline(t)
}

func (c UDPConn) SetReadDeadline(t time.Time) error {
	return c.udp.SetReadDeadline(t)
}

func (c UDPConn) SetWriteDeadline(t time.Time) error {
	return c.udp.SetWriteDeadline(t)
}

func (c UDPConn) Close() (err error) {
	err = c.udp.Close()

	e := c.tcp.Close()
	if e != nil {
		err = e
	}

	return
}

func parseAddr(p []byte, st int, udp bool) (a net.Addr, i int, err error) {
	switch p[st] {
	case 0x01: // ipv4
		return parseIP(p, st+1, 4, udp)
	case 0x04: // ipv6
		return parseIP(p, st+1, 16, udp)
	case 0x03: // domain name
		return parseName(p, st+1, udp)
	default:
		return nil, -1, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, p[st])
	}
}

func parseIP(p []byte, st int, l int, udp bool) (a net.Addr, i int, err error) {
	i = st

	if i+l+2 >= len(p) {
		return nil, -1, fmt.Errorf("malformed datagram")
	}

	ip := make(net.IP, l)
	i += copy(ip, p[i:])

	port := int(p[i])<<8 | int(p[i+1])

	i += 2

	if udp {
		return &net.UDPAddr{
			IP:   ip,
			Port: port,
		}, i, nil
	} else {
		return &net.TCPAddr{
			IP:   ip,
			Port: port,
		}, i, nil
	}
}

func parseName(p []byte, st int, udp bool) (addr net.Addr, i int, err error) {
	i = st
	l := int(p[i])
	i++

	if i+l+2 >= len(p) {
		return nil, -1, fmt.Errorf("malformed datagram")
	}

	//	a = Addr(p[i : i+l])
	i += l

	port := int(p[i])<<8 | int(p[i+1])

	a := fmt.Sprintf("%s:%d", p[i-l:i], port)

	i += 2

	if udp {
		addr = UDPAddr(a)
	} else {
		addr = TCPAddr(a)
	}

	return addr, i, nil
}
