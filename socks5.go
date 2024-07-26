package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

type (
	AuthMethod uint8

	// Command is request command or reply code.
	Command uint8

	Reply Command

	// TCPName is a string address.
	TCPName string

	// UDPName is a string address.
	UDPName string

	TCPAddr netip.AddrPort
	UDPAddr netip.AddrPort

	Proto struct {
		NetIPAddrs bool
	}

	tcpObj struct {
		Addr net.TCPAddr
		IP   [16]byte
	}

	udpObj struct {
		Addr net.UDPAddr
		IP   [16]byte
	}
)

// Auth Methods
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

	AuthNoAcceptable AuthMethod = 0xff
)

// Commands
const (
	CommandTCPConn  Command = 0x01
	CommandTCPBind  Command = 0x02
	CommandUDPAssoc Command = 0x03
)

// Reply Codes
const (
	ReplySuccess Reply = iota
	ReplyGeneralFailure
	ReplyNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

// Errors
var (
	ErrUnsupportedProtocol    = errors.New("unsupported protocol")
	ErrUnsupportedCommand     = errors.New("unsupported command")
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	ErrNoAcceptableAuth       = errors.New("no acceptable auth method")
)

func (p Proto) ClientHandshakeWrite(c net.Conn, methods ...AuthMethod) error {
	var bufdata [8]byte
	buf := noEscapeSlice(bufdata[:])
	buf = grow(buf, 2+len(methods))

	buf[0] = 0x5
	buf[1] = byte(len(methods))

	for i, m := range methods {
		buf[2+i] = byte(m)
	}

	_, err := c.Write(buf[:2+len(methods)])
	if err != nil {
		return err
	}

	return nil
}

func (p Proto) ClientHandshakeRead(c net.Conn) (auth AuthMethod, err error) {
	var bufdata [2]byte
	buf := noEscapeSlice(bufdata[:])

	_, err = io.ReadFull(c, buf[:2])
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}

	if buf[0] != 0x5 {
		return 0, ErrUnsupportedProtocol
	}

	auth = AuthMethod(buf[1])

	if auth == AuthNoAcceptable {
		return auth, ErrNoAcceptableAuth
	}

	return auth, nil
}

func (p Proto) ClientHandshake(c net.Conn, methods ...AuthMethod) (auth AuthMethod, err error) {
	err = p.ClientHandshakeWrite(c, methods...)
	if err != nil {
		return 0, err
	}

	return p.ClientHandshakeRead(c)
}

func (p Proto) ServerHandshakeRead(c net.Conn, methods ...AuthMethod) (auth AuthMethod, err error) {
	var bufdata [8]byte
	buf := noEscapeSlice(bufdata[:])

	_, err = io.ReadFull(c, buf[:2])
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}

	if buf[0] != 0x5 { // version
		return 0, ErrUnsupportedProtocol
	}

	nmeth := int(buf[1])
	buf = grow(buf, nmeth)

	n, err := io.ReadFull(c, buf[:nmeth])
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, err
	}

	auth = AuthNoAcceptable

authloop:
	for _, m := range methods {
		for _, q := range buf[:n] {
			if m == AuthMethod(q) {
				auth = m

				break authloop
			}
		}
	}

	if auth == AuthNoAcceptable {
		return 0, ErrNoAcceptableAuth
	}

	return auth, nil
}

func (p Proto) ServerHandshakeWrite(c net.Conn, auth AuthMethod) (err error) {
	var bufdata [2]byte
	buf := noEscapeSlice(bufdata[:])

	buf[0] = 5
	buf[1] = byte(auth)

	_, err = c.Write(buf[:2])
	if err != nil {
		return err
	}

	return nil
}

func (p Proto) ServerHandshake(c net.Conn, methods ...AuthMethod) (auth AuthMethod, err error) {
	auth, err = p.ServerHandshakeRead(c, methods...)
	if auth == AuthNoAcceptable {
		_ = p.ServerHandshakeWrite(c, auth)
	}
	if err != nil {
		return
	}

	err = p.ServerHandshakeWrite(c, auth)
	if err != nil {
		return auth, err
	}

	return auth, err
}

func (p Proto) ReadRequest(c net.Conn) (Command, net.Addr, error) {
	var bufdata [40]byte
	buf := noEscapeSlice(bufdata[:])

	cmd, addr, _, err := p.readReqRep(c, 0, buf)
	return cmd, addr, err
}

func (p Proto) ReadReply(c net.Conn, cmd Command) (Reply, net.Addr, error) {
	var bufdata [40]byte
	buf := noEscapeSlice(bufdata[:])

	reply, addr, _, err := p.readReqRep(c, cmd, buf)

	return Reply(reply), addr, err
}

func (p Proto) WriteRequest(c net.Conn, cmd Command, addr net.Addr) (err error) {
	var bufdata [40]byte
	buf := noEscapeSlice(bufdata[:])

	_, err = p.writeReqRep(c, cmd, addr, buf)
	return err
}

func (p Proto) WriteReply(c net.Conn, rep Reply, addr net.Addr) (err error) {
	var bufdata [40]byte
	buf := noEscapeSlice(bufdata[:])

	_, err = p.writeReqRep(c, Command(rep), addr, buf)
	return err
}

func (p Proto) readReqRep(c net.Conn, rcmd Command, buf []byte) (cmd Command, addr net.Addr, _ []byte, err error) {
	buf = grow(buf, 20)

	_, err = io.ReadFull(c, buf[:4])
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return 0, nil, buf, err
	}

	if buf[0] != 0x5 {
		return 0, nil, buf, ErrUnsupportedProtocol
	}

	cmd = Command(buf[1])

	addr, buf, err = p.readAddr(c, buf[3], buf, rcmd == CommandUDPAssoc || cmd == CommandUDPAssoc)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		return cmd, addr, buf, err
	}

	return cmd, addr, buf, nil
}

func (p Proto) writeReqRep(c net.Conn, cmd Command, addr net.Addr, buf []byte) (_ []byte, err error) {
	buf = grow(buf, 24)

	buf[0] = 0x5
	buf[1] = byte(cmd)
	buf[2] = 0

	i := 3

	i, buf, err = p.encodeAddr(buf, i, addr)
	if err != nil {
		return buf, err
	}

	_, err = c.Write(buf[:i])
	if err != nil {
		return buf, err
	}

	return buf, nil
}

func (p Proto) encodeAddr(buf []byte, st int, a net.Addr) (i int, _ []byte, err error) {
	i = st

	switch a := a.(type) {
	case TCPAddr:
		i, buf, err = p.encodeNetIPAddrPort(buf, st, netip.AddrPort(a))
	case UDPAddr:
		i, buf, err = p.encodeNetIPAddrPort(buf, st, netip.AddrPort(a))
	case *net.TCPAddr:
		i, buf, err = p.encodeIPPort(buf, st, a.IP, a.Port)
	case *net.UDPAddr:
		i, buf, err = p.encodeIPPort(buf, st, a.IP, a.Port)
	case TCPName:
		i, buf, err = p.encodeAddrString(buf, st, string(a))
	case UDPName:
		i, buf, err = p.encodeAddrString(buf, st, string(a))
	case nil:
		i, buf, err = p.encodeIPPort(buf, st, nil, 0)
	default:
		i, buf, err = p.encodeAddrString(buf, st, a.String())
	}
	if err != nil {
		return 0, buf, err
	}

	return i, buf, nil
}

func (p Proto) encodeNetIPAddrPort(buf []byte, st int, addr netip.AddrPort) (i int, _ []byte, err error) {
	i = st
	a := addr.Addr().Unmap()

	ipsize := 4
	if !a.Is4() {
		ipsize = 16
	}

	buf = grow(buf, i+1+ipsize+2)

	switch {
	case !a.IsValid():
		buf[i] = 0x1
		i++

		i += copy(buf[i:], []byte{0, 0, 0, 0})
	case a.Is4():
		buf[i] = 0x1
		i++

		ip := a.As4()
		i += copy(buf[i:], ip[:])
	case a.Is6():
		buf[i] = 0x4
		i++

		ip := a.As16()
		i += copy(buf[i:], ip[:])
	default:
		return 0, buf, fmt.Errorf("bad ip: %v", a)
	}

	port := addr.Port()

	buf[i] = byte(port >> 8)
	i++
	buf[i] = byte(port)
	i++

	return i, buf, nil
}

func (p Proto) encodeIPPort(buf []byte, st int, ip net.IP, port int) (i int, _ []byte, err error) {
	i, buf, err = p.encodeIP(buf, st, ip)
	if err != nil {
		return i, buf, err
	}

	buf[i] = byte(port >> 8)
	i++
	buf[i] = byte(port)
	i++

	return i, buf, err
}

func (p Proto) encodeIP(buf []byte, st int, ip net.IP) (i int, _ []byte, err error) {
	i = st
	q := ip.To4()
	buf = grow(buf, i+1+len(ip)+2)

	switch {
	case q != nil:
		buf[i] = 0x1
		i++

		i += copy(buf[i:], q)
	case ip.To16() != nil:
		buf[i] = 0x4
		i++

		i += copy(buf[i:], ip)
	case len(ip) == 0:
		buf[i] = 0x1
		i++

		i += copy(buf[i:], []byte{0, 0, 0, 0})
	default:
		return 0, buf, fmt.Errorf("bad ip: %v", ip)
	}

	return i, buf, nil
}

func (p Proto) encodeAddrString(buf []byte, st int, addr string) (i int, _ []byte, err error) {
	i = st

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, buf, err
	}

	if len(host) > 256 {
		return 0, buf, fmt.Errorf("too long hostname")
	}

	porti, err := strconv.ParseInt(port, 10, 16)
	if err != nil {
		return 0, buf, err
	}

	buf = grow(buf, i+1+1+len(host)+2)

	buf[i] = 0x3
	i++
	buf[i] = byte(len(host))
	i++

	i += copy(buf[i:], host)

	buf[i] = byte(porti >> 8)
	i++
	buf[i] = byte(porti)
	i++

	return i, buf, nil
}

func (p Proto) readAddr(c net.Conn, typ byte, buf []byte, udp bool) (addr net.Addr, _ []byte, err error) {
	switch typ {
	case 0x01: // ipv4
		return p.readIPPort(c, 4, buf, udp)
	case 0x04: // ipv6
		return p.readIPPort(c, 16, buf, udp)
	case 0x03: // domain name
		return p.readNamePort(c, buf, udp)
	default:
		return nil, buf, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, typ)
	}
}

func (p Proto) readIPPort(c net.Conn, size int, buf []byte, udp bool) (addr net.Addr, _ []byte, err error) {
	buf = grow(buf, size+2)

	_, err = io.ReadFull(c, buf[:size+2])
	if err != nil {
		return nil, buf, err
	}

	port := int(buf[size])<<8 | int(buf[size+1])

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
		if udp {
			obj := &udpObj{}
			copy(obj.IP[:size], buf)

			obj.Addr.IP = obj.IP[:size]
			obj.Addr.Port = port

			addr = &obj.Addr
		} else {
			obj := &tcpObj{}
			copy(obj.IP[:size], buf)

			obj.Addr.IP = obj.IP[:size]
			obj.Addr.Port = port

			addr = &obj.Addr
		}
	}

	return addr, buf, nil
}

func (p Proto) readNamePort(c net.Conn, buf []byte, udp bool) (addr net.Addr, _ []byte, err error) {
	_, err = c.Read(buf[:1])
	if err != nil {
		return nil, buf, err
	}

	n := buf[0]
	buf = grow(buf, int(n)+6)

	_, err = io.ReadFull(c, buf[:n+2])
	if err != nil {
		return nil, buf, err
	}

	port := int(buf[n])<<8 | int(buf[n+1])

	buf[n] = ':'
	buf = strconv.AppendInt(buf[:n+1], int64(port), 10)

	if udp {
		addr = UDPName(buf)
	} else {
		addr = TCPName(buf)
	}

	return addr, buf, nil
}

func (m AuthMethod) String() string {
	switch m {
	case AuthNone:
		return "none"
	case AuthUserPass:
		return "user_pass"
	default:
		return fmt.Sprintf("auth[%x]", int(m))
	}
}

func (c Command) String() string {
	switch c {
	case CommandTCPConn:
		return "tcp_connect"
	case CommandTCPBind:
		return "tcp_bind"
	case CommandUDPAssoc:
		return "udp_assoc"
	default:
		return fmt.Sprintf("cmd[%x]", int(c))
	}
}

func (r Reply) String() string {
	switch r {
	case ReplySuccess:
		return "success"
	case ReplyGeneralFailure:
		return "general_failure"
	case ReplyNotAllowed:
		return "not_allowed"
	case ReplyNetworkUnreachable:
		return "network_unreachable"
	case ReplyHostUnreachable:
		return "host_unreachable"
	case ReplyConnRefused:
		return "conn_refused"
	case ReplyTTLExpired:
		return "ttl_expired"
	case ReplyCommandNotSupported:
		return "command_not_supported"
	case ReplyAddressTypeNotSupported:
		return "address_type_not_supported"
	default:
		return fmt.Sprintf("reply[%x]", int(r))
	}
}

func (r Reply) Error() string {
	return r.String()
}

func (a TCPName) Network() string { return "tcp" }
func (a TCPName) String() string  { return string(a) }

func (a UDPName) Network() string { return "udp" }
func (a UDPName) String() string  { return string(a) }

func (a TCPAddr) Network() string { return "tcp" }
func (a TCPAddr) String() string  { return netip.AddrPort(a).String() }
func (a UDPAddr) Network() string { return "udp" }
func (a UDPAddr) String() string  { return netip.AddrPort(a).String() }

func grow(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:cap(b)]
	}

	return append(b, make([]byte, n-len(b))...)
}
