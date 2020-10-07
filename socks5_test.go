package socks5

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nikandfor/tlog"
	"github.com/stretchr/testify/assert"
)

type (
	pipe struct {
		r, w chan []byte

		loc, rem net.Addr

		rt, wt time.Time

		rb []byte

		l *tlog.Logger
	}

	timeoutErr struct{}
)

func TestPipe(t *testing.T) {
	var wg sync.WaitGroup

	sc, cc := Pipe(Addr("a"), Addr("b"))

	wg.Add(1)
	go func() {
		var b [7]byte
		n, err := sc.Read(b[:])
		assert.NoError(t, err)

		for i := 0; i < n/2; i++ {
			b[i], b[n-i-1] = b[n-i-1], b[i]
		}

		nr, err := sc.Write(b[:n])
		assert.NoError(t, err)

		assert.Equal(t, n, nr)

		err = sc.Close()
		assert.NoError(t, err)
	}()

	var b [10]byte

	n, err := cc.Write([]byte("1234567"))
	assert.NoError(t, err)
	assert.Equal(t, 7, n)

	nr, err := cc.Read(b[:])
	assert.True(t, err == io.EOF)
	assert.Equal(t, n, nr)

	assert.Equal(t, []byte("7654321"), b[:nr])

	err = cc.Close()
	assert.NoError(t, err)
}

func TestUserPassAuth(t *testing.T) {
	var wg sync.WaitGroup
	tl = tlog.NewTestLogger(t, "", tlog.Stderr)

	a := ConstUserPassAuthenticator{
		User: "user",
		Pass: "pwd",
	}

	//	sc, cc := Pipe(Addr("srv"), Addr("clt"))
	sc, cc := net.Pipe()

	wg.Add(1)
	go func() {
		defer wg.Done()

		err := a.Auth(sc)
		assert.NoError(t, err)
	}()

	err := a.ClientAuth(cc)
	assert.NoError(t, err)

	wg.Wait()

	sc.SetDeadline(time.Now().Add(time.Millisecond))
	cc.SetDeadline(time.Now().Add(time.Millisecond))

	var b [10]byte

	n, err := sc.Read(b[:])
	assert.True(t, err.(net.Error).Timeout())
	assert.Equal(t, 0, n)

	n, err = cc.Read(b[:])
	assert.True(t, err.(net.Error).Timeout())
	assert.Equal(t, 0, n)
}

func TestSOCKS5(t *testing.T) {
	stopErr := errors.New("success error")

	tl = tlog.NewTestLogger(t, "", tlog.Stderr)

	srv := Server{
		Handler: HandlerFunc(func(req Request) error {
			tl.Printf("connection started")

			c, err := req.WriteStatus(StatusOK, &net.TCPAddr{IP: []byte{1, 2, 3, 4}, Port: 88})
			if !assert.NoError(t, err) {
				return err
			}

			tl.Printf("connection established")

			defer func() {
				e := c.Close()

				if err == nil {
					err = e
				}
			}()

			var buf [100]byte

			n, err := c.Read(buf[:])
			if !assert.NoError(t, err) {
				return err
			}

			assert.Equal(t, []byte("message"), buf[:n])

			n, err = c.Write([]byte("response"))
			if !assert.NoError(t, err) {
				return err
			}
			assert.Equal(t, 8, n)

			return stopErr
		}),
		AuthMethods: []AuthMethod{AuthUserPass, AuthNone},
		Auth: map[AuthMethod]Authenticator{
			AuthUserPass: ConstUserPassAuthenticator{
				User: "user",
				Pass: "pass",
			},
		},
	}

	d := Dialer{
		AuthMethods: []AuthMethod{AuthUserPass, AuthNone},
		Auth: map[AuthMethod]ClientAuthenticator{
			AuthUserPass: ConstUserPassAuthenticator{
				User: "user",
				Pass: "pass",
			},
		},
	}

	sc, cc := net.Pipe()
	//	sc, cc := Pipe(Addr("srv"), Addr("clt"))
	//	sc.l = tl
	//	cc.l = tl

	d.DialContext = func(ctx context.Context, nw, addr string) (net.Conn, error) {
		assert.Equal(t, "proxy_net", nw)
		assert.Equal(t, "proxy_addr", addr)

		tl.Printf("proxy conn opended")

		return cc, nil
	}

	go func() {
		err := srv.ServeConn(sc)
		if err == stopErr {
			return
		}

		tl.Printf("connection served: %v", err)

		assert.NoError(t, err)
	}()

	c, err := d.ForProxy("proxy_net", "proxy_addr").DialContext(context.Background(), "tcp", "req_addr:80")
	assert.NoError(t, err)

	raddr := c.RemoteAddr()
	assert.Equal(t, &net.TCPAddr{
		IP:   []byte{1, 2, 3, 4},
		Port: 88,
	}, raddr)

	n, err := c.Write([]byte("message"))
	assert.NoError(t, err)
	assert.Equal(t, 7, n)

	var buf [100]byte

	n, err = c.Read(buf[:])
	assert.NoError(t, err)
	assert.Equal(t, []byte("response"), buf[:n])
}

func Pipe(la, lb net.Addr) (a, b *pipe) {
	c1 := make(chan []byte)
	c2 := make(chan []byte)

	a = &pipe{
		w:   c1,
		r:   c2,
		loc: la,
		rem: lb,
	}

	b = &pipe{
		w:   c2,
		r:   c1,
		loc: lb,
		rem: la,
	}

	return
}

func (p *pipe) Write(buf []byte) (int, error) {
	b := make([]byte, len(buf))
	copy(b, buf)

	p.w <- b

	p.l.Printf("%20v written: % x", p.loc, buf)

	return len(buf), nil
}

func (p *pipe) Read(buf []byte) (n int, err error) {
loop:
	for n < len(buf) {
		if len(p.rb) == 0 {
			var ok bool

			var to chan time.Time

			select {
			case p.rb, ok = <-p.r:
				if !ok {
					err = io.EOF
					break loop
				}
			case <-to:
				err = timeoutErr{}
				break loop
			}
		}

		np := copy(buf[n:], p.rb)

		p.rb = p.rb[np:]

		n += np
	}

	p.l.Printf("%20v read   : % x", p.loc, buf[:n])

	return n, err
}

func (p *pipe) Close() error {
	close(p.w)

	return nil
}

func (p *pipe) LocalAddr() net.Addr {
	return p.loc
}

func (p *pipe) RemoteAddr() net.Addr {
	return p.rem
}

func (p *pipe) SetDeadline(t time.Time) error      { p.rt = t; p.wt = t; return nil }
func (p *pipe) SetReadDeadline(t time.Time) error  { p.rt = t; return nil }
func (p *pipe) SetWriteDeadline(t time.Time) error { p.wt = t; return nil }

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
