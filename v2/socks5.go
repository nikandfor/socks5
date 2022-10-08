package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

type (
	AuthMethod uint8

	// Command is request command or reply code
	Command uint8

	Reply Command

	// Addr is domain name addr
	Addr string

	Proto struct{}
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

// errors
var (
	ErrUnsupportedProtocol    = errors.New("unsupported protocol")
	ErrUnsupportedCommand     = errors.New("unsupported command")
	ErrUnsupportedAddressType = errors.New("unsupported address type")
	ErrNoAcceptableAuth       = errors.New("no acceptable auth method")
)

func (p Proto) ClientHandshake(c net.Conn, methods ...AuthMethod) (auth AuthMethod, err error) {
	var buf [257]byte

	if len(methods) > 255 {
		return 0, fmt.Errorf("too much of auth methods")
	}

	buf[0] = 0x5
	buf[1] = byte(len(methods))

	for i, m := range methods {
		buf[2+i] = byte(m)
	}

	_, err = c.Write(buf[:2+len(methods)])
	if err != nil {
		return 0, err
	}

	_, err = io.ReadFull(c, buf[:2])
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

func (p Proto) ServerHandshake(c net.Conn, methods ...AuthMethod) (auth AuthMethod, err error) {
	var buf [256]byte

	_, err = io.ReadFull(c, buf[:2])
	if err != nil {
		return 0, err
	}

	if buf[0] != 0x5 {
		return 0, ErrUnsupportedProtocol
	}

	n, err := io.ReadFull(c, buf[:buf[1]])
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

	buf[0] = 5
	buf[1] = byte(auth)

	_, err = c.Write(buf[:2])
	if err != nil {
		return 0, err
	}

	if auth == AuthNoAcceptable {
		return 0, ErrNoAcceptableAuth
	}

	return auth, nil
}

func (p Proto) ReadRequest(c net.Conn) (Command, net.Addr, error) {
	return p.readReqRep(c, 0)
}

func (p Proto) ReadReply(c net.Conn, cmd Command) (Reply, net.Addr, error) {
	reply, addr, err := p.readReqRep(c, cmd)

	return Reply(reply), addr, err
}

func (p Proto) WriteRequest(c net.Conn, cmd Command, addr net.Addr) (err error) {
	return p.writeReqRep(c, cmd, addr)
}

func (p Proto) WriteReply(c net.Conn, rep Reply, addr net.Addr) (err error) {
	return p.writeReqRep(c, Command(rep), addr)
}

func (p Proto) readReqRep(c net.Conn, rcmd Command) (cmd Command, addr net.Addr, err error) {
	var buf [258]byte

	_, err = io.ReadFull(c, buf[:4])
	if err != nil {
		return 0, nil, err
	}

	if buf[0] != 0x5 {
		return 0, nil, ErrUnsupportedProtocol
	}

	cmd = Command(buf[1])

	addr, err = readAddr(c, buf[3], buf[:], rcmd == CommandUDPAssoc || cmd == CommandUDPAssoc)
	if err != nil {
		return cmd, addr, err
	}

	return cmd, addr, nil
}

func (p Proto) writeReqRep(c net.Conn, cmd Command, addr net.Addr) (err error) {
	var buf [256 + 6]byte

	buf[0] = 0x5
	buf[1] = byte(cmd)
	buf[2] = 0

	i := 3

	i, err = encodeAddr(buf[:], i, addr)
	if err != nil {
		return err
	}

	_, err = c.Write(buf[:i])
	if err != nil {
		return err
	}

	return nil
}

func encodeAddr(buf []byte, st int, a net.Addr) (i int, err error) {
	i = st

	switch a := a.(type) {
	case *net.TCPAddr:
		i, err = encodeIP(buf, st, a.IP)
		if err != nil {
			return 0, err
		}

		buf[i] = byte(a.Port >> 8)
		i++
		buf[i] = byte(a.Port)
		i++
	case *net.UDPAddr:
		i, err = encodeIP(buf, st, a.IP)
		if err != nil {
			return 0, err
		}

		buf[i] = byte(a.Port >> 8)
		i++
		buf[i] = byte(a.Port)
		i++
	case Addr:
		i, err = encodeAddrString(buf, st, string(a))
		if err != nil {
			return 0, err
		}
	case nil:
		i, err = encodeAddrString(buf, st, "")
		if err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("unsupported address: %v", a)
	}

	return i, nil
}

func encodeIP(buf []byte, st int, ip net.IP) (i int, err error) {
	i = st
	q := ip.To4()

	if q != nil {
		buf[i] = 0x1
		i++

		i += copy(buf[i:], q)
	} else if ip.To16() != nil {
		buf[i] = 0x4
		i++

		i += copy(buf[i:], ip)
	} else {
		return 0, fmt.Errorf("bad ip: %v", ip)
	}

	return i, nil
}

func encodeAddrString(buf []byte, st int, addr string) (i int, err error) {
	i = st

	if addr == "" {
		// type
		buf[i] = 0x1 // ipv4
		i++

		// ipv4 + port
		i += copy(buf[i:], []byte{0, 0, 0, 0, 0, 0})

		return i, nil
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}

	if len(host) > 256 {
		return 0, fmt.Errorf("too long hostname")
	}

	porti, err := strconv.ParseInt(port, 10, 16)
	if err != nil {
		return 0, err
	}

	buf[i] = 0x3
	i++
	buf[i] = byte(len(host))
	i++

	i += copy(buf[i:], host)

	buf[i] = byte(porti >> 8)
	i++
	buf[i] = byte(porti)
	i++

	return i, nil
}

func readAddr(c net.Conn, typ byte, buf []byte, udp bool) (addr net.Addr, err error) {
	switch typ {
	case 0x01: // ipv4
		return readIP(c, 4, buf, udp)
	case 0x04: // ipv6
		return readIP(c, 16, buf, udp)
	case 0x03: // domain name
		return readName(c, buf)
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnsupportedAddressType, typ)
	}
}

func readIP(c net.Conn, len int, buf []byte, udp bool) (addr net.Addr, err error) {
	_, err = io.ReadFull(c, buf[:len+2])
	if err != nil {
		return nil, err
	}

	ip := make([]byte, len)

	copy(ip, buf)

	port := int(buf[len])<<8 | int(buf[len+1])

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

	return addr, nil
}

func readName(c net.Conn, buf []byte) (addr net.Addr, err error) {
	_, err = c.Read(buf[:1])
	if err != nil {
		return nil, err
	}

	n := buf[0]

	_, err = io.ReadFull(c, buf[:n+2])
	if err != nil {
		return nil, err
	}

	port := int(buf[n])<<8 | int(buf[n+1])

	return Addr(fmt.Sprintf("%s:%d", buf[:n], port)), nil
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

func (a Addr) Network() string { return "" }
func (a Addr) String() string  { return string(a) }
