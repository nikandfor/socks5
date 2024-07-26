package socks5

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"tlog.app/go/errors"
)

type (
	UDPProto struct {
		Proto
	}

	UDPConn struct {
		Proto UDPProto

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

		addr, i, err = c.Proto.parseAddr(p, 3, true)
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
	buf := make([]byte, 32+len(p))

	buf[0] = 0
	buf[1] = 0
	buf[2] = 0

	i, buf, err := c.Proto.encodeAddr(buf, 3, addr)
	if err != nil {
		return 0, errors.Wrap(err, "encode addr")
	}

	buf = grow(buf, i+len(p))
	copy(buf[i:], p)

	n, err = c.udp.Write(buf[:i+len(p)])
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

func (p UDPProto) ParsePacketHeader(b []byte) (net.Addr, int, error) {
	if len(b) < 6 || b[2] != 0 {
		return nil, 0, errors.New("malformed packet")
	}

	return p.parseAddr(b, 3, true)
}

func (p UDPProto) parseAddr(b []byte, st int, udp bool) (a net.Addr, i int, err error) {
	switch b[st] {
	case 0x01: // ipv4
		return p.parseIPPort(b, st+1, 4, udp)
	case 0x04: // ipv6
		return p.parseIPPort(b, st+1, 16, udp)
	case 0x03: // domain name
		return p.parseName(b, st+1, udp)
	default:
		return nil, -1, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, b[st])
	}
}

func (p UDPProto) parseIPPort(buf []byte, st int, size int, udp bool) (addr net.Addr, i int, err error) {
	i = st

	if i+size+2 >= len(buf) {
		return nil, -1, fmt.Errorf("malformed datagram")
	}

	port := int(buf[i])<<8 | int(buf[i+1])

	if p.NetIPAddrs {
		a, ok := netip.AddrFromSlice(buf[:size])
		if !ok {
			panic("bad ip")
		}

		ap := netip.AddrPortFrom(a, uint16(port))

		if udp {
			addr = UDPAddr(ap)
		} else {
			addr = TCPAddr(ap)
		}
	} else {
		ip := make(net.IP, size)
		copy(ip, buf)

		if udp {
			addr = &net.UDPAddr{
				IP:   ip,
				Port: port,
			}
		} else {
			addr = &net.TCPAddr{
				IP:   ip,
				Port: port,
			}
		}
	}

	return addr, i, nil
}

func (p UDPProto) parseName(b []byte, st int, udp bool) (addr net.Addr, i int, err error) {
	i = st
	l := int(b[i])
	i++

	if i+l+2 >= len(b) {
		return nil, -1, fmt.Errorf("malformed datagram")
	}

	//	a = Addr(b[i : i+l])
	i += l

	port := int(b[i])<<8 | int(b[i+1])

	a := fmt.Sprintf("%s:%d", b[i-l:i], port)

	i += 2

	if udp {
		addr = UDPName(a)
	} else {
		addr = TCPName(a)
	}

	return addr, i, nil
}

func (p UDPProto) EncodePacketHeader(buf []byte, dst int, addr net.Addr) (int, error) {
	end, buf, err := p.encodeAddr(buf[:dst], 3, addr)
	if err != nil {
		return 0, err
	}
	if end > dst {
		return end, io.ErrShortBuffer
	}

	if end == dst {
		return 0, nil
	}

	off := dst - end

	end, _, err = p.encodeAddr(buf[:dst], off+3, addr)
	if err != nil {
		return 0, err
	}
	if end != dst {
		return end, errors.New("bad address encoder")
	}

	copy(buf[off:], []byte{0, 0, 0})

	return off, nil
}
