package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/nikandfor/hacked/hnet"
	"nikand.dev/go/cli"
	"nikand.dev/go/graceful"
	"tlog.app/go/errors"
	"tlog.app/go/tlog"
	"tlog.app/go/tlog/ext/tlflag"

	"nikand.dev/go/socks5"
)

type (
	Server struct {
		p socks5.Proto

		auth []socks5.AuthMethod

		creds []string
	}

	stdConn struct {
		in, out *os.File

		net.Conn
	}

	stdAddr struct{}
)

func main() {
	serverCmd := &cli.Command{
		Name:   "server",
		Action: serverMain,
		Flags: []*cli.Flag{
			cli.NewFlag("listen,l", ":1080", "server listen address"),
			cli.NewFlag("auth", "", "server auth credentials"),
		},
	}

	clientCmd := &cli.Command{
		Name:   "client",
		Action: clientMain,
		Args:   cli.Args{},
		Flags: []*cli.Flag{
			cli.NewFlag("proxy,x", "", "proxy address"),
			cli.NewFlag("proxy-auth,P", "", "proxy auth"),
		},
	}

	app := &cli.Command{
		Name:   "socks5",
		Before: before,
		Commands: []*cli.Command{
			serverCmd,
			clientCmd,
		},
		Flags: []*cli.Flag{
			cli.NewFlag("log", "stderr?dm", "log output file (or stderr)"),
			cli.NewFlag("verbosity,v", "", "logger verbosity topics"),
			cli.NewFlag("debug", "", "debug address"),
			cli.FlagfileFlag,
			cli.HelpFlag,
		},
	}

	cli.RunAndExit(app, os.Args, os.Environ())
}

func before(c *cli.Command) error {
	w, err := tlflag.OpenWriter(c.String("log"))
	if err != nil {
		return errors.Wrap(err, "open log file")
	}

	tlog.DefaultLogger = tlog.New(w)

	tlog.SetVerbosity(c.String("verbosity"))

	if q := c.String("debug"); q != "" {
		l, err := net.Listen("tcp", q)
		if err != nil {
			return errors.Wrap(err, "listen debug")
		}

		go func() {
			tlog.Printw("start debug interface", "addr", q)

			err := http.Serve(l, nil)
			if err != nil {
				tlog.Printw("debug", "addr", q, "err", err, "", tlog.Fatal)
				os.Exit(1)
			}
		}()
	}

	return nil
}

func clientMain(c *cli.Command) (err error) {
	ctx := context.Background()
	addr := c.Args.First()

	r, err := net.Dial("tcp", c.String("proxy"))
	if err != nil {
		return errors.Wrap(err, "dial")
	}

	var p socks5.Proto
	var usr, pwd string

	auth := []socks5.AuthMethod{socks5.AuthNone}

	if q := c.String("proxy-auth"); q != "" {
		auth = []socks5.AuthMethod{socks5.AuthUserPass, socks5.AuthNone}
		usr, pwd, _ = strings.Cut(q, ":")
	}

	meth, err := p.ClientHandshake(r, auth...)
	if err != nil {
		return errors.Wrap(err, "handshake")
	}

	switch meth {
	case socks5.AuthNone:
	case socks5.AuthUserPass:
		var auth socks5.UserPassAuth

		err := auth.WriteRequest(r, usr, pwd)
		if err != nil {
			return errors.Wrap(err, "auth: write request")
		}

		status, err := auth.ReadReply(r)
		if err != nil {
			return errors.Wrap(err, "auth: read reply")
		}

		if status != auth.StatusSuccess() {
			return errors.Wrap(err, "auth: unauthenticated")
		}
	default:
		return errors.New("unsupported auth method")
	}

	err = p.WriteRequest(r, socks5.CommandTCPConn, socks5.TCPName(addr))
	if err != nil {
		return errors.Wrap(err, "write request")
	}

	s, _, err := p.ReadReply(r, socks5.CommandTCPConn)
	if err != nil {
		return errors.Wrap(err, "read reply")
	}

	if s != socks5.ReplySuccess {
		return s
	}

	lc := stdConn{
		in:  os.Stdin,
		out: os.Stdout,
	}

	return biproxy(ctx, lc, r)
}

func serverMain(c *cli.Command) (err error) {
	ctx := context.Background()

	l, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		return errors.Wrap(err, "listen")
	}

	tlog.Printw("listen", "listen", l.Addr())
	defer tlog.Printw("finish", "err", &err)

	s := &Server{
		auth: []socks5.AuthMethod{socks5.AuthNone},
	}

	if q := c.String("auth"); q != "" {
		s.auth = []socks5.AuthMethod{socks5.AuthUserPass}
		s.creds = strings.FieldsFunc(q, isComma)
	}

	tlog.Printw("server auth", "methods", s.auth, "credentials", len(s.creds))

	gr := graceful.New()

	gr.Add(func(ctx context.Context) error {
		return s.serve(ctx, l)
	}, graceful.IgnoreErrors(context.Canceled))

	return gr.Run(ctx)
}

func (s *Server) serve(ctx context.Context, l net.Listener) error {
	var wg sync.WaitGroup

	defer wg.Wait()

	for {
		c, err := hnet.Accept(ctx, l)
		if err != nil {
			return errors.Wrap(err, "accept")
		}

		wg.Add(1)

		tr := tlog.Start("client_conn", "local_addr", c.LocalAddr(), "remote_addr", c.RemoteAddr())

		go func() {
			var err error

			defer wg.Done()
			defer tr.Finish("err", &err)

			ctx := tlog.ContextWithSpan(ctx, tr)

			err = s.handleConn(ctx, c)
		}()
	}

	return nil
}

func (s *Server) handleConn(ctx context.Context, c net.Conn) (err error) {
	tr := tlog.SpanFromContext(ctx)

	defer func() {
		e := c.Close()
		if err == nil {
			err = errors.Wrap(e, "close client")
		}
	}()

	meth, err := s.p.ServerHandshake(c, s.auth...)
	if err != nil {
		return errors.Wrap(err, "handshake")
	}

	tr.Printw("auth", "auth_method", meth)

	switch meth {
	case socks5.AuthNone:
		// we are fine
	case socks5.AuthUserPass:
		var auth socks5.UserPassAuth

		usr, pwd, err := auth.ReadRequest(c)
		if err != nil {
			return errors.Wrap(err, "user-pass auth: read request")
		}

		cred := usr + ":" + pwd

		ok := func() bool {
			for _, c := range s.creds {
				if c == cred {
					return true
				}
			}

			return false
		}()

		if !ok {
			_ = auth.WriteReply(c, auth.StatusFailure())

			return errors.New("user-pass auth: unauthenticated")
		}

		err = auth.WriteReply(c, auth.StatusSuccess())
		if err != nil {
			return errors.Wrap(err, "user-pass auth: write reply")
		}
	default:
		panic(meth)
	}

	cmd, addr, err := s.p.ReadRequest(c)
	if err != nil {
		return errors.Wrap(err, "read request")
	}

	tr.Printw("request", "command", cmd, "addr", addr)

	switch cmd {
	case socks5.CommandTCPConn:
		return handleTCPConn(ctx, c, addr)
	case socks5.CommandTCPBind:
		return handleTCPBind(ctx, c, addr)
	case socks5.CommandUDPAssoc:
		return handleUDPAssoc(ctx, c, addr)
	default:
		return errors.New("unsupported cmd: %v", cmd)
	}
}

func handleTCPConn(ctx context.Context, c net.Conn, addr net.Addr) (err error) {
	tr := tlog.SpanFromContext(ctx)
	var p socks5.Proto

	var responded bool

	defer func() {
		if responded {
			return
		}

		reply := replyFromErr(err)

		// ignore error as we exitin with error already
		_ = p.WriteReply(c, reply, nil)
	}()

	rc, err := net.Dial("tcp", addr.String())
	if err != nil {
		return errors.Wrap(err, "dial remote")
	}

	defer func() {
		e := rc.Close()
		if err == nil {
			err = errors.Wrap(e, "close remote")
		}
	}()

	err = p.WriteReply(c, socks5.ReplySuccess, rc.RemoteAddr())
	if err != nil {
		return errors.Wrap(err, "write reply")
	}

	responded = true

	tr.Printw("connected", "local_addr", rc.LocalAddr(), "remote_addr", rc.RemoteAddr())

	return biproxy(ctx, c, rc)
}

func handleTCPBind(ctx context.Context, c net.Conn, addr net.Addr) (err error) {
	var p socks5.Proto

	var responded bool

	defer func() {
		if responded {
			return
		}

		reply := replyFromErr(err)

		// ignore error as we exitin with error already
		_ = p.WriteReply(c, reply, nil)
	}()

	l, err := net.Listen("tcp", addr.String())
	if err != nil {
		l, err = net.Listen("tcp", "")
	}
	if err != nil {
		return errors.Wrap(err, "listen")
	}

	defer func() {
		if l == nil {
			return
		}

		e := l.Close()
		if err == nil {
			err = errors.Wrap(e, "close listener")
		}
	}()

	err = p.WriteReply(c, socks5.ReplySuccess, l.Addr())
	if err != nil {
		return errors.Wrap(err, "write reply")
	}

	rc, err := l.Accept()
	if err != nil {
		return errors.Wrap(err, "accept")
	}

	err = l.Close()
	if err != nil {
		return errors.Wrap(err, "close listener")
	}

	l = nil

	err = p.WriteReply(c, socks5.ReplySuccess, rc.RemoteAddr())
	if err != nil {
		return errors.Wrap(err, "write reply")
	}

	responded = true

	return biproxy(ctx, c, rc)
}

func handleUDPAssoc(ctx context.Context, c net.Conn, addr net.Addr) (err error) {
	var p socks5.Proto

	var responded bool

	defer func() {
		if responded {
			return
		}

		reply := replyFromErr(err)

		// ignore error as we exitin with error already
		_ = p.WriteReply(c, reply, nil)
	}()

	l, err := net.ListenPacket("udp", addr.String())
	if err != nil {
		l, err = net.ListenPacket("udp", "")
	}
	if err != nil {
		return errors.Wrap(err, "listen udp")
	}

	defer func() {
		e := l.Close()
		if err == nil {
			err = errors.Wrap(e, "close listener")
		}
	}()

	r, err := net.ListenPacket("udp", "")
	if err != nil {
		return errors.Wrap(err, "bind remote")
	}

	defer func() {
		e := r.Close()
		if err == nil {
			err = errors.Wrap(e, "close remote")
		}
	}()

	err = p.WriteReply(c, socks5.ReplySuccess, l.LocalAddr())
	if err != nil {
		return errors.Wrap(err, "write reply")
	}

	responded = true

	errc := make(chan error, 3)

	relay := ClientUDPRelay{}

	go func() {
		err := relay.proxyUDPClientToRemote(ctx, l, r)
		errc <- errors.Wrap(err, "udp client-to-remote")
	}()

	go func() {
		err := relay.proxyUDPRemoteToClient(ctx, l, r)
		errc <- errors.Wrap(err, "udp remote-to-client")
	}()

	go func() {
		_, err := io.Copy(io.Discard, c)
		errc <- errors.Wrap(err, "tcp read from client")
	}()

	for i := 0; i < 3; i++ {
		e := <-errc
		if err == nil {
			err = e
		}
	}

	return err
}

type ClientUDPRelay struct {
	mu     sync.Mutex
	client net.Addr
}

func (q *ClientUDPRelay) proxyUDPClientToRemote(ctx context.Context, c, r net.PacketConn) (err error) {
	buf := make([]byte, 0x8000)

	for {
		n, client, err := c.ReadFrom(buf)
		if err != nil {
			return errors.Wrap(err, "read")
		}

		q.mu.Lock()
		q.client = client
		q.mu.Unlock()

		addr, st, err := socks5.UDPProto{}.ParsePacketHeader(buf[:n])
		if err != nil {
			continue
		}

		_, err = r.WriteTo(buf[st:n], addr)
		if err != nil {
			return errors.Wrap(err, "write")
		}
	}
}

func (q *ClientUDPRelay) proxyUDPRemoteToClient(ctx context.Context, c, r net.PacketConn) (err error) {
	buf := make([]byte, 0x8000)
	dst := 32

	for {
		n, addr, err := r.ReadFrom(buf[dst:])
		if err != nil {
			return errors.Wrap(err, "read")
		}

		st, err := socks5.UDPProto{}.EncodePacketHeader(buf, dst, addr)
		if err != nil {
			return errors.Wrap(err, "encode packet header")
		}

		q.mu.Lock()
		client := q.client
		q.mu.Unlock()

		_, err = c.WriteTo(buf[st:n], client)
		if err != nil {
			return errors.Wrap(err, "write")
		}
	}
}

func biproxy(ctx context.Context, c, r net.Conn) error {
	errc := make(chan error, 2)

	proxy := func(name string, w, r net.Conn) {
		_, err := io.Copy(w, r)

		if c, ok := w.(interface {
			CloseWrite() error
		}); ok {
			e := c.CloseWrite()
			if err == nil {
				err = errors.Wrap(e, "close write")
			}
		}

		errc <- errors.Wrap(err, "%v", name)
	}

	go proxy("client-to-remote", r, c)
	go proxy("remote-to-client", c, r)

	err := <-errc
	e := <-errc
	if err == nil {
		err = e
	}

	return err
}

func replyFromErr(err error) socks5.Reply {
	switch {
	default:
		return socks5.ReplyGeneralFailure
	}
}

func (c stdConn) Read(p []byte) (int, error) {
	return c.in.Read(p)
}

func (c stdConn) Write(p []byte) (int, error) {
	return c.out.Write(p)
}

func (c stdConn) Close() error {
	e1 := c.out.Close()
	e2 := c.in.Close()

	if e1 != nil {
		return e1
	}
	if e2 != nil {
		return e2
	}

	return nil
}

func (c stdConn) LocalAddr() net.Addr  { return stdAddr{} }
func (c stdConn) RemoteAddr() net.Addr { return stdAddr{} }

func (stdAddr) Network() string { return "stdio" }
func (stdAddr) String() string  { return "local" }

func isComma(r rune) bool { return r == ',' }
