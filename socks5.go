package socks5

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type (
	AuthMethod uint8

	Command uint8

	StatusCode uint8

	Addr string

	Authenticator func(c BufConn) error

	ConstAuthenticator struct {
		User string
		Pass string
	}

	Request struct {
		Command Command
		Addr    net.Addr

		c net.Conn
	}

	Handler interface {
		ServeSOCKS5(Request) error
	}

	Server struct {
		h Handler

		// Auth methods in order of priority
		AuthMethods []AuthMethod

		Auth map[AuthMethod]Authenticator
	}

	Dialer struct {
		net.Dialer

		// Auth methods in order of priority
		AuthMethods []AuthMethod

		Auth map[AuthMethod]Authenticator
	}

	dialerTo struct {
		*Dialer
		nw, addr string
	}

	BufConn struct {
		*bufio.Reader
		net.Conn
		raddr net.Addr
	}
)

// Auth methids.
const (
	AuthNone AuthMethod = iota
	AuthGSSAPI
	AuthUserPass
	AuthChallengeHandshake
	_
	AuthChallengeResponse
	AuthSSL
	AuthNDS
	AuthMultiAuthFramework
	AuthJSON
	AuthN

	AuthUnacceptable AuthMethod = 0xff
)

// Commands
const (
	CommandTCPConn Command = 0x01
	CommandTCPBind Command = 0x02
	CommandUDP     Command = 0x03
)

// errors
var (
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrUnacceptableAuth   = errors.New("auth methods are unacceptable")
	ErrNoAuthenticator    = errors.New("no authenticator func for method")
	ErrUnauthenticated    = errors.New("unauthenticated")
)

func (s *Server) HandleConn(c net.Conn) (err error) {
	defer func() {
		e := c.Close()
		if err == nil {
			err = e
		}
	}()

	bc := BufConn{Conn: c}
	bc.Reset(c)

	cauth, err := s.handshake(bc)
	if err != nil {
		return err
	}

	if cauth != AuthNone {
		auth := s.Auth[cauth]
		if auth == nil {
			return ErrNoAuthenticator
		}

		err = auth(bc)
		if err != nil {
			return err
		}
	}

	req, err := s.readRequest(bc)
	if err != nil {
		return err
	}

	req.c = bc

	return s.h.ServeSOCKS5(req)
}

func (s *Server) readRequest(c BufConn) (req Request, err error) {
	buf, err := c.Peek(2)
	if err != nil {
		return
	}

	if buf[0] != 0x05 { // proto version
		err = ErrUnsupportedVersion
		return
	}

	req.Command = Command(buf[1])

	req.Addr, err = readAddr(c, req.Command)
	if err != nil {
		return
	}

	return
}

func (s *Server) handshake(c BufConn) (_ AuthMethod, err error) {
	buf, err := c.Peek(2)
	if err != nil {
		return
	}

	if buf[0] != 0x5 { // protocol version
		return 0, ErrUnsupportedVersion
	}

	nauth := int(buf[1])

	_, err = c.Discard(2)
	if err != nil {
		return 0, err
	}

	buf, err = c.Peek(nauth)
	if err != nil {
		return 0, err
	}

	var clAuth [256]bool
	for _, a := range buf {
		clAuth[a] = true
	}

	var cauth AuthMethod = AuthUnacceptable
	if len(s.AuthMethods) == 0 && clAuth[AuthNone] {
		cauth = AuthNone
	}
	for _, a := range s.AuthMethods {
		if clAuth[a] {
			cauth = a
			break
		}
	}

	_, err = c.Write([]byte{0x5, byte(cauth)}) // version, cauth
	if err != nil {
		return 0, err
	}

	if cauth == AuthUnacceptable {
		return 0, ErrUnacceptableAuth
	}

	return cauth, nil
}

func (r *Request) WriteStatus(s StatusCode, a net.Addr) (c net.Conn, err error) {
	defer func() {
		if err == nil {
			return
		}

		_ = r.c.Close()
	}()

	var b []byte

	b = append(b, []byte{0x05, byte(s), 0x00}...)

	addIP := func(ip []byte, p int) {
		switch len(ip) {
		case 4:
			b = append(b, 0x01, ip[0], ip[1], ip[2], ip[3])
		case 16:
			b = append(b, 0x04)
			b = append(b, ip...)
		default:
			panic("unsupported ip size")
		}

		b = append(b, byte(p>>8), byte(p))
	}

	switch a := a.(type) {
	case *net.TCPAddr:
		addIP(a.IP, a.Port)
	case *net.UDPAddr:
		addIP(a.IP, a.Port)
	default:
		return nil, errors.New("unsupported address type")
	}

	_, err = r.c.Write(b)
	if err != nil {
		return
	}

	return r.c, nil
}

func (d dialerTo) DialContext(ctx context.Context, nw, addr string) (cc net.Conn, err error) {
	host, ports, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}

	if len(host) > 0xff {
		return nil, errors.New("too long host")
	}

	port, err := strconv.Atoi(ports)
	if err != nil {
		return
	}

	c, err := d.Dialer.Dialer.DialContext(ctx, d.nw, d.addr)
	if err != nil {
		return
	}

	defer func() {
		if err == nil {
			return
		}

		_ = c.Close()
	}()

	// handshake

	var b []byte

	b = append(b[:0], 0x05, byte(len(d.AuthMethods))) // proto version, nauth
	for _, a := range d.AuthMethods {
		b = append(b, byte(a))
	}

	_, err = c.Write(b)
	if err != nil {
		return
	}

	n, err := c.Read(b[:2])
	if err != nil {
		return
	}

	if n < 2 {
		return c, io.ErrUnexpectedEOF
	}

	if b[0] != 0x05 { // proto version
		return c, ErrUnsupportedVersion
	}

	bc := BufConn{
		Reader: bufio.NewReader(c),
		Conn:   c,
	}

	cauth := AuthMethod(b[1])

	// auth
	if cauth != AuthNone {
		auth := d.Auth[cauth]
		if auth == nil {
			return c, ErrNoAuthenticator
		}

		err = auth(bc)
		if err != nil {
			return
		}
	}

	// request

	b = append(b[:0], 0x05, 0x01, 0, 0x03, byte(len(host))) // proto version, cmd (tcp/ip conn), reserved, addr_type (domain name), addr_len

	switch nw {
	case "tcp", "tcp4", "tcp6":
		b[1] = 0x01
	case "udp", "udp4", "udp6":
		b[1] = 0x03
	default:
		panic("unsupported network type")
	}

	b = append(b, host...)

	b = append(b, byte(port>>8), byte(port))

	_, err = c.Write(b)
	if err != nil {
		return
	}

	buf, err := bc.Peek(2)
	if err != nil {
		return
	}

	if buf[0] != 0x05 {
		return nil, ErrUnsupportedVersion
	}

	if buf[1] != 0 {
		err = StatusCode(buf[1])
		return
	}

	bc.raddr, err = readAddr(bc, CommandTCPConn)
	if err != nil {
		return
	}

	return bc, nil
}

func (a *ConstAuthenticator) Auth(c BufConn) (err error) {
	var status byte = 1
	defer func() {
		_, e := c.Write([]byte{0x01, status}) // version, status
		if err == nil {
			err = e
		}
	}()

	l := 2

again:
	buf, err := c.Peek(l)
	if err != nil {
		return err
	}

	if buf[0] != 0x01 { // auth algo version
		return ErrUnsupportedVersion
	}

	idlen := int(buf[1])
	if 2+idlen+1 < len(buf) {
		l = 2 + idlen + 1
		goto again
	}

	if string(buf[2:2+idlen]) != a.User {
		return ErrUnauthenticated
	}

	_, err = c.Discard(2 + idlen)
	if err != nil {
		return err
	}

	pwlen := int(buf[2+idlen])
	buf, err = c.Peek(1 + pwlen)
	if err != nil {
		return err
	}

	if string(buf[1:1+pwlen]) != a.Pass {
		return ErrUnauthenticated
	}

	_, err = c.Discard(1 + pwlen)
	if err != nil {
		return err
	}

	status = 0 // ok

	return nil
}

func (c BufConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func readAddr(c BufConn, cmd Command) (addr net.Addr, err error) {
	var ip []byte
	var domain []byte
	l := 1

again:
	buf, err := c.Peek(l)
	if err != nil {
		return
	}

	i := 0          // port start
	switch buf[0] { // addr type
	case 0x01: // ipv4
		if l < 7 {
			l = 7
			goto again
		}

		ip = make([]byte, 4)
		copy(ip, buf[1:5])

		i += 5
	case 0x03: // domain name
		dl := int(buf[1])

		if l < 2+dl+2 {
			l = 2 + dl + 2
			goto again
		}

		i += 2 // type, len

		domain = buf[i : i+dl]

		i += dl
	case 0x04: // ipv6
		if l < 1+16+2 {
			l = 1 + 16 + 2
			goto again
		}

		ip = make([]byte, 16)
		copy(ip, buf[1:17])

		i += 17
	}

	port := int(buf[i])<<8 | int(buf[i])
	i += 2

	if ip == nil {
		addr = Addr(fmt.Sprintf("%s:%d", domain, port))
	} else {
		switch cmd {
		case 0x01, // TCP/IP connection
			0x02: // TCP/IP bind
			addr = &net.TCPAddr{
				IP:   ip,
				Port: port,
			}
		case 0x03: // UDP
			addr = &net.UDPAddr{
				IP:   ip,
				Port: port,
			}
		}
	}

	_, err = c.Discard(i)
	if err != nil {
		return
	}

	return

}

func (a Addr) Network() string { return "" }
func (a Addr) String() string  { return string(a) }

func (c StatusCode) Error() string { return fmt.Sprintf("%v", int(c)) }
