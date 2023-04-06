package socks5

import (
	"io"
	"net"

	"github.com/nikandfor/errors"
)

type (
	UserPassAuth struct{}
)

func (a UserPassAuth) ReadRequest(c net.Conn) (usr, pwd string, err error) {
	buf := grow(nil, 16)

	_, err = io.ReadFull(c, buf[:2])
	if err != nil {
		return "", "", err
	}

	if buf[0] != 0x1 {
		return "", "", errors.New("unsupported version")
	}

	l := int(buf[1])
	buf = grow(buf, l+1)

	_, err = io.ReadFull(c, buf[:l+1])
	if err != nil {
		return "", "", err
	}

	usr = string(buf[:l])

	l = int(buf[l])
	buf = grow(buf, l)

	_, err = io.ReadFull(c, buf[:l])
	if err != nil {
		return "", "", err
	}

	pwd = string(buf[:l])

	return
}

func (a UserPassAuth) WriteReply(c net.Conn, status int) (err error) {
	if status < 0 || status > 255 {
		panic("bad status")
	}

	_, err = c.Write([]byte{0x1, byte(status)})

	return err
}

func (a UserPassAuth) WriteRequest(c net.Conn, usr, pwd string) (err error) {
	if len(usr) > 255 || len(pwd) > 255 {
		return errors.New("too long user or password")
	}

	b := make([]byte, 1+1+len(usr)+1+len(pwd))
	i := 0

	b[i] = 0x1
	i++

	b[i] = byte(len(usr))
	i++
	copy(b[i:], usr)
	i += len(usr)

	b[i] = byte(len(pwd))
	i++
	copy(b[i:], pwd)
	i += len(pwd)

	_, err = c.Write(b[:i])

	return err
}

func (a UserPassAuth) ReadReply(c net.Conn) (status int, err error) {
	var buf [2]byte

	_, err = io.ReadFull(c, buf[:])
	if err != nil {
		return -1, err
	}

	if buf[0] != 0x1 {
		return -1, errors.New("unsupported version")
	}

	return int(buf[1]), nil
}

func (UserPassAuth) StatusSuccess() int { return 0 }
func (UserPassAuth) StatusFailure() int { return 1 }
