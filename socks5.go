package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/nikandfor/errors"
	"github.com/nikandfor/tlog"
)

type (
	AuthMethod uint8

	Command uint8

	StatusCode uint8

	Addr string

	MethodAuthenticator interface {
		AuthMethod(m AuthMethod, c net.Conn) error
	}

	MethodAuthenticatorFunc func(m AuthMethod, c net.Conn) error

	Authenticator interface {
		Auth(c net.Conn) error
	}

	ClientAuthenticator interface {
		ClientAuth(c net.Conn) error
	}

	ConstUserPassAuthenticator struct {
		User string
		Pass string
	}

	UserPassAuthenticator func(u, p string, c net.Conn) error

	Request struct {
		Command Command
		Addr    net.Addr

		c net.Conn
	}

	Handler interface {
		ServeSOCKS5(Request) error
	}

	HandlerFunc func(Request) error

	Server struct {
		Handler Handler

		// Auth methods in order of priority
		AuthMethods []AuthMethod

		Auth map[AuthMethod]Authenticator
	}

	Dialer struct {
		DialContext func(ctx context.Context, nw, addr string) (net.Conn, error)

		// Auth methods in order of priority
		AuthMethods []AuthMethod

		Auth map[AuthMethod]ClientAuthenticator
	}

	DialerTo struct {
		*Dialer
		Net, Addr string
	}

	ProxyConn struct {
		net.Conn
		rAddr net.Addr
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

// Status Codes
const (
	StatusOK StatusCode = iota
	StatusGeneralFailure
	StatusNotAllowed
	StatusNetworkUnreachable
	StatusHostUnreachable
	StatusConnRefused
	StatusTTLExpired
	StatusProtocolError
	StatusAddressTypeNotSupported

	StatusUnsupportedCommand = StatusProtocolError
)

// errors
var (
	ErrUnsupportedVersion = errors.New("unsupported version")
	ErrUnacceptableAuth   = errors.New("auth methods are unacceptable")
	ErrNoAuthenticator    = errors.New("no authenticator func for method")
	ErrUnauthenticated    = errors.New("unauthenticated")
)

var zeroDialer net.Dialer

var tl *tlog.Logger

func (s *Server) Serve(l net.Listener) (err error) {
	for {
		var c net.Conn
		c, err = l.Accept()
		if err != nil {
			return
		}

		go s.ServeConn(c) //nolint:errcheck
	}
}

func (s *Server) ServeConn(c net.Conn) (err error) {
	return s.ServeConnAuthHandler(c, s, s.Handler)
}

func (s *Server) ServeConnAuthHandler(c net.Conn, a MethodAuthenticator, h Handler) (err error) {
	defer func() {
		if c == nil {
			return
		}

		tl.Printf("close server conn: %v", err)

		e := c.Close()
		if err == nil {
			err = e
		}
	}()

	cauth, err := s.handshake(c)
	if err != nil {
		return err
	}

	tl.Printf("handshake done: cauth %v", cauth)

	err = a.AuthMethod(cauth, c)
	if err != nil {
		return err
	}

	tl.Printf("auth done")

	req, err := s.readRequest(c)
	if err != nil {
		return err
	}

	req.c = c
	c = nil

	tl.Printf("request read")

	return h.ServeSOCKS5(req)
}

func (s *Server) AuthMethod(cauth AuthMethod, c net.Conn) (err error) {
	if cauth == AuthNone {
		return nil
	}

	auth := s.Auth[cauth]
	if auth == nil {
		return ErrNoAuthenticator
	}

	err = auth.Auth(c)
	if err != nil {
		return err
	}

	return nil
}

func (s *Server) readRequest(c net.Conn) (req Request, err error) {
	var buf [3]byte

	n, err := c.Read(buf[:])
	if err != nil {
		return
	}

	if n < 2 {
		return req, io.ErrUnexpectedEOF
	}

	if buf[0] != 0x05 { // proto version
		return req, errors.Wrap(ErrUnsupportedVersion, "request proto version")
	}

	req.Command = Command(buf[1])

	tl.Printf("read req header: %v", req.Command)

	req.Addr, err = readAddr(c, req.Command)
	if err != nil {
		return
	}

	return
}

func (s *Server) handshake(c net.Conn) (_ AuthMethod, err error) {
	var buf [256]byte

	n, err := c.Read(buf[:2])
	if err != nil {
		return
	}

	if n < 2 {
		return 0, io.ErrUnexpectedEOF
	}

	if buf[0] != 0x05 { // protocol version
		return 0, errors.Wrap(ErrUnsupportedVersion, "handshake proto version")
	}

	nauth := int(buf[1])

	n, err = c.Read(buf[:nauth])
	if err != nil {
		return 0, err
	}

	if n != nauth {
		return 0, io.ErrUnexpectedEOF
	}

	var clAuth [256]bool
	for _, a := range buf[:n] {
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

	buf[0] = 0x05
	buf[1] = byte(cauth)

	_, err = c.Write(buf[:2]) // version, cauth
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

		tl.Printf("close server conn: %v", err)

		_ = r.c.Close()
	}()

	var b []byte

	b = append(b, 0x05, byte(s), 0x00)

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
	tl.Printf("sent response: % x  => %v", b, err)
	if err != nil {
		return
	}

	return r.c, nil
}

func (d *Dialer) ForProxy(nw, addr string) DialerTo {
	return DialerTo{
		Dialer: d,
		Net:    nw,
		Addr:   addr,
	}
}

func (d DialerTo) Dial(nw, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), nw, addr)
}

func (d DialerTo) DialContext(ctx context.Context, nw, addr string) (cc net.Conn, err error) {
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

	dial := d.Dialer.DialContext
	if dial == nil {
		dial = zeroDialer.DialContext
	}
	c, err := dial(ctx, d.Net, d.Addr)
	if err != nil {
		return
	}

	defer func() {
		if err == nil {
			return
		}

		tl.Printf("close client conn: %v", err)

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
		return nil, errors.Wrap(err, "send handshake")
	}

	n, err := c.Read(b[:2])
	if err != nil {
		return nil, errors.Wrap(err, "read handshake")
	}

	tl.Printf("handshake resp % x", b[:2])

	if n < 2 {
		return nil, io.ErrUnexpectedEOF
	}

	if b[0] != 0x05 { // proto version
		return nil, errors.Wrap(ErrUnsupportedVersion, "handshake proto version")
	}

	cauth := AuthMethod(b[1])

	// auth
	if cauth != AuthNone {
		auth := d.Auth[cauth]
		if auth == nil {
			return c, ErrNoAuthenticator
		}

		err = auth.ClientAuth(c)
		if err != nil {
			return
		}
	}

	tl.Printf("auth done")

	// request

	b = append(b[:0], 0x05, 0x01, 0, // proto version, cmd (tcp/ip conn), reserved
		0x03, byte(len(host))) // addr_type (domain name), addr_len

	switch nw {
	case "tcp", "tcp4", "tcp6":
		b[1] = 0x01 // tcp conn
	case "udp", "udp4", "udp6":
		b[1] = 0x03 // udp bind
	default:
		panic("unsupported network type")
	}

	b = append(b, host...)

	b = append(b, byte(port>>8), byte(port))

	tl.Printf("request sent % x", b)

	_, err = c.Write(b)
	if err != nil {
		return
	}

	// response

	n, err = c.Read(b[:3])
	if err != nil {
		return
	}

	tl.Printf("resp % x", b[:3])

	if n < 3 {
		return nil, io.ErrUnexpectedEOF
	}

	if b[0] != 0x05 {
		return nil, errors.Wrap(ErrUnsupportedVersion, "response proto version")
	}

	if b[1] != 0 {
		err = StatusCode(b[1])
		return
	}

	raddr, err := readAddr(c, CommandTCPConn)
	if err != nil {
		return
	}

	tl.Printf("remote addr %v", raddr)

	return ProxyConn{
		Conn:  c,
		rAddr: raddr,
	}, nil
}

func (a ConstUserPassAuthenticator) Auth(c net.Conn) (err error) {
	return UserPassAuthenticator(func(u, p string, c net.Conn) error {
		if u != a.User || p != a.Pass {
			return ErrUnauthenticated
		}

		return nil
	}).Auth(c)
}

func (a ConstUserPassAuthenticator) ClientAuth(c net.Conn) (err error) {
	if len(a.User) > 255 || len(a.Pass) > 255 {
		panic("too long user or password")
	}

	var b []byte

	b = append(b, 0x01, byte(len(a.User)))
	b = append(b, a.User...)
	b = append(b, byte(len(a.Pass)))
	b = append(b, a.Pass...)

	_, err = c.Write(b)
	if err != nil {
		return
	}

	n, err := c.Read(b[:2])
	if err != nil {
		return
	}

	if n != 2 {
		return io.ErrUnexpectedEOF
	}

	if b[0] != 0x01 {
		return errors.Wrap(ErrUnsupportedVersion, "user/pass auth")
	}

	if b[1] != 0 {
		return ErrUnauthenticated
	}

	return nil
}

func (a UserPassAuthenticator) Auth(c net.Conn) (err error) {
	var status byte = 1
	defer func() {
		_, e := c.Write([]byte{0x01, status}) // version, status
		if err == nil {
			err = e
		}
	}()

	var buf [3 + 255 + 255]byte

	n, err := c.Read(buf[:2])
	if err != nil {
		return err
	}

	if n < 2 {
		return io.ErrUnexpectedEOF
	}

	if buf[0] != 0x01 { // auth algo version
		return errors.Wrap(ErrUnsupportedVersion, "user/pass auth")
	}

	idlen := int(buf[1])

	n, err = c.Read(buf[:idlen+1])
	if err != nil {
		return err
	}
	if n < idlen+1 {
		return io.ErrUnexpectedEOF
	}

	user := string(buf[:idlen])

	pwlen := int(buf[idlen])

	n, err = c.Read(buf[:pwlen])
	if err != nil {
		return err
	}
	if n < pwlen {
		return io.ErrUnexpectedEOF
	}

	pwd := string(buf[:pwlen])

	err = a(user, pwd, c)
	if err != nil {
		return err
	}

	status = 0 // ok

	return nil
}

func readAddr(c net.Conn, cmd Command) (addr net.Addr, err error) {
	var ip []byte
	var domain []byte

	var buf [257]byte

	n, err := c.Read(buf[:1])
	if err != nil {
		return
	}
	if n < 1 {
		return nil, io.ErrUnexpectedEOF
	}

	tl.Printf("addr type %x", buf[0])

	i := 0
	addrType := buf[0]
	read := 0
	switch addrType {
	case 0x01: // ipv4
		read = 4 + 2
	case 0x03: // domain name
		i++
		n, err = c.Read(buf[i : i+1])
		if err != nil {
			return
		}
		if n < 1 {
			return nil, io.ErrUnexpectedEOF
		}

		read = int(buf[i]) + 2
	case 0x04: // ipv6
		read = 16 + 2
	default:
		return nil, errors.Wrap(ErrUnsupportedVersion, "address type (%x)", addrType)
	}

	i++
	n, err = c.Read(buf[i : i+read])
	if err != nil {
		return nil, err
	}
	if n < read {
		return nil, io.ErrUnexpectedEOF
	}

	tl.Printf("addr data % x", buf[1:i+read])

	switch addrType {
	case 0x01: // ipv4
		ip = make([]byte, 4)
		copy(ip, buf[i:])
	case 0x03: // domain name
		domain = buf[i : i+read-2]
	case 0x04: // ipv6
		ip = make([]byte, 16)
		copy(ip, buf[i:])
	}

	port := int(buf[i+read-2])<<8 | int(buf[i+read-1])

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

	tl.Printf("addr read: %v  of % x", addr, buf[:i+read])

	return

}

func (f MethodAuthenticatorFunc) AuthMethod(m AuthMethod, c net.Conn) error {
	return f(m, c)
}

func (f HandlerFunc) ServeSOCKS5(req Request) error {
	return f(req)
}

func (c ProxyConn) RemoteAddr() net.Addr { return c.rAddr }

func (a Addr) Network() string { return "" }
func (a Addr) String() string  { return string(a) }

func (a AuthMethod) String() string {
	switch a {
	case AuthNone:
		return "none"
	case AuthUserPass:
		return "user/pass"
	default:
		return fmt.Sprintf("auth[%x]", int(a))
	}
}

func (c Command) String() string {
	switch c {
	case CommandTCPConn:
		return "tcp_connect"
	case CommandTCPBind:
		return "tcp_bind"
	case CommandUDP:
		return "udp_assoc"
	default:
		return fmt.Sprintf("cmd[%x]", int(c))
	}
}

func (c StatusCode) String() string { return c.Error() }

func (c StatusCode) Error() string {
	switch c {
	case StatusOK:
		return "ok"
	case StatusGeneralFailure:
		return "general_fail"
	case StatusNotAllowed:
		return "not_allowed"
	case StatusNetworkUnreachable:
		return "net_unreachable"
	case StatusHostUnreachable:
		return "host_unreachable"
	case StatusConnRefused:
		return "conn_refused"
	case StatusTTLExpired:
		return "ttl_expired"
	case StatusProtocolError:
		return "proto_error"
	case StatusAddressTypeNotSupported:
		return "addr_type_not_supported"
	default:
		return fmt.Sprintf("status[%x]", int(c))
	}
}
