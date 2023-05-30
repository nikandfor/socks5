package socks5

import (
	"context"
	"net"
	"net/netip"

	"github.com/nikandfor/errors"
)

type (
	Auther interface {
		Auth(ctx context.Context, meth AuthMethod, c net.Conn) error
	}

	AutherFunc func(ctx context.Context, meth AuthMethod, c net.Conn) error

	DialerFunc func(ctx context.Context, nw, addr string) (net.Conn, error)

	Dialer struct {
		Dialer interface {
			DialContext(ctx context.Context, nw, addr string) (net.Conn, error)
		}

		Proxy string

		AuthMethods []AuthMethod // in order of preference
		Auther      Auther
	}
)

func (d *Dialer) DialContext(ctx context.Context, nw, addr string) (_ net.Conn, err error) {
	var cmd Command

	switch nw {
	case "tcp", "tcp4", "tcp6":
		cmd = CommandTCPConn
	case "udp", "udp4", "udp6":
		cmd = CommandUDPAssoc
	default:
		return nil, errors.New("unsupported network: %v", nw)
	}

	var udpDstAddr *net.UDPAddr
	if cmd == CommandUDPAssoc {
		udpDstAddr, err = net.ResolveUDPAddr(nw, addr)
		if err != nil {
			return nil, errors.Wrap(err, "resolve addr")
		}
	}

	var dial func(context.Context, string, string) (net.Conn, error)
	if d.Dialer != nil {
		dial = d.Dialer.DialContext
	} else {
		var dd net.Dialer
		dial = dd.DialContext
	}

	tc, err := dial(ctx, "tcp", d.Proxy)
	if err != nil {
		return nil, errors.Wrap(err, "dial proxy")
	}

	defer func() {
		if err == nil {
			return
		}

		_ = tc.Close()
	}()

	var proto Proto

	meth, err := proto.ClientHandshake(tc, d.AuthMethods...)
	if err != nil {
		return nil, errors.Wrap(err, "proxy handshake")
	}

	if d.Auther != nil || meth != AuthNone {
		err = d.Auther.Auth(ctx, meth, tc)
		if err != nil {
			return nil, errors.Wrap(err, "auth")
		}
	}

	var reqAddr net.Addr

	if cmd == CommandTCPConn {
		reqAddr = TCPAddr(addr)

		if a, err := netip.ParseAddrPort(addr); err == nil {
			reqAddr = net.TCPAddrFromAddrPort(a)
		}
	} else if cmd == CommandUDPAssoc {
		reqAddr = UDPAddr("")
	} else {
		panic(cmd)
	}

	err = proto.WriteRequest(tc, cmd, reqAddr)
	if err != nil {
		return nil, errors.Wrap(err, "send request")
	}

	rep, raddr, err := proto.ReadReply(tc, cmd)
	if err != nil {
		return nil, errors.Wrap(err, "read reply")
	}

	if rep != ReplySuccess {
		return nil, errors.Wrap(rep, "got reply")
	}

	if cmd == CommandTCPConn {
		return tc, nil
	}

	uc, err := dial(ctx, nw, raddr.String())
	if err != nil {
		return nil, errors.Wrap(err, "dial udp")
	}

	return UDPConn{
		raddr: udpDstAddr,
		udp:   uc,
		tcp:   tc,
	}, nil
}

func (f AutherFunc) Auth(ctx context.Context, meth AuthMethod, c net.Conn) error {
	return f(ctx, meth, c)
}

func (f DialerFunc) DialContext(ctx context.Context, nw, addr string) (net.Conn, error) {
	return f(ctx, nw, addr)
}
