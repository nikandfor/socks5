package socks5

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type (
	FakeConn struct {
		b  []byte
		ri int
		net.Conn
	}

	FakePipe struct {
		r, w *FakeConn
		net.Conn
	}
)

func TestHandshake(t *testing.T) {
	testHandshake(t)
}

func BenchmarkServerHandshake(b *testing.B) {
	b.ReportAllocs()

	var p Proto
	var m AuthMethod
	var err error

	_, s := testHandshake(b)

	for i := 0; i < b.N; i++ {
		s.Reset()

		m, err = p.ServerHandshake(s, 3, 4, 1)
	}

	assert.NoError(b, err)
	assert.Equal(b, m, AuthMethod(3))
}

func BenchmarkClientHandshake(b *testing.B) {
	b.ReportAllocs()

	var p Proto
	var m AuthMethod
	var err error

	c, _ := testHandshake(b)

	for i := 0; i < b.N; i++ {
		c.Reset()

		m, err = p.ClientHandshake(c, 1, 2, 3, 4)
	}

	assert.NoError(b, err)
	assert.Equal(b, m, AuthMethod(3))
}

func testHandshake(t testing.TB) (c, s *FakePipe) {
	var p Proto
	c, s = Pipe()

	// make client request
	_, err := p.ClientHandshake(c, 1, 2, 3, 4)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

	if _, ok := t.(*testing.T); ok {
		t.Logf("client written: % 02x", c.w.b)
	}

	if t.Failed() {
		t.FailNow()
	}

	// check server side
	m, err := p.ServerHandshake(s, 3, 4, 1)
	assert.NoError(t, err)
	assert.Equal(t, m, AuthMethod(3))

	if _, ok := t.(*testing.T); ok {
		t.Logf("server written: % 02x", s.w.b)
	}

	if t.Failed() {
		t.FailNow()
	}

	c.w.ResetWriter()

	// having server response, check client
	m, err = p.ClientHandshake(c, 1, 2, 3, 4)
	assert.NoError(t, err)
	assert.Equal(t, m, AuthMethod(3))

	assert.Equal(t, c.r.ri, len(c.r.b))
	assert.Equal(t, s.r.ri, len(s.r.b))

	return c, s
}

func Pipe() (x, y *FakePipe) {
	x = &FakePipe{}
	y = &FakePipe{}

	x.w = &FakeConn{}
	y.w = &FakeConn{}

	x.r = y.w
	y.r = x.w

	return
}

func (c *FakePipe) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *FakePipe) Write(p []byte) (int, error) {
	return c.w.Write(p)
}

func (c *FakePipe) Reset() {
	c.r.ResetReader()
	c.w.ResetWriter()
}

func (c *FakeConn) Read(p []byte) (n int, err error) {
	n = copy(p, c.b[c.ri:])
	c.ri += n

	if c.ri == len(c.b) {
		err = io.EOF
	}

	return
}

func (c *FakeConn) Write(p []byte) (n int, err error) {
	c.b = append(c.b, p...)

	return len(p), nil
}

func (c *FakeConn) ResetReader() { c.ri = 0 }
func (c *FakeConn) ResetWriter() { c.b = c.b[:0] }
