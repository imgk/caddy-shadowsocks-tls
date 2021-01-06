package shadowsocks

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/imgk/caddy-shadowsocks-tls/outline"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	Server    string   `json:"server,omitempty"`
	ShadowBox string   `json:"shadowbox,omitempty"`
	Users     []string `json:"users,omitempty"`

	logger *zap.Logger
	mutex  *sync.RWMutex
	users  map[string]struct{}
	last   time.Time
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.shadowsocks_tls",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (m *Handler) Provision(ctx caddy.Context) (err error) {
	m.logger = ctx.Logger(m)
	m.mutex = new(sync.RWMutex)
	m.users = make(map[string]struct{})

	prefix := os.Getenv("SB_API_PREFIX")
	port := os.Getenv("SB_API_PORT")
	if prefix != "" && port != "" && m.ShadowBox == "" {
		m.ShadowBox = fmt.Sprintf("https://127.0.0.1:%s/%s", port, prefix)
		m.logger.Info(fmt.Sprintf("add shadowbox server: %v", m.ShadowBox))
	}

	if m.ShadowBox != "" {
		server, er := outline.NewOutlineServer(m.ShadowBox)
		if er != nil {
			err = er
			return
		}

		if m.Server == "" {
			m.Server = "127.0.0.1:" + strconv.Itoa(server.PortForNewAccessKeys)
		}

		m.logger.Info("add user from shadowbox server")
		for _, user := range server.Users {
			m.logger.Info(fmt.Sprintf("add new user: %v", user.Password))
			sum := sha256.Sum224([]byte(user.Password))
			auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
			m.users[auth] = struct{}{}
		}
		m.last = time.Now()
	}

	if m.Server == "" {
		return errors.New("no shadowsocks server")
	}
	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user))
		sum := sha256.Sum224([]byte(user))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	return
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodConnect {
		return next.ServeHTTP(w, r)
	}
	if !m.authenticate(r) {
		return next.ServeHTTP(w, r)
	}

	var rwc io.ReadWriteCloser
	switch r.ProtoMajor {
	case 1:
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return errors.New("http hijacker error")
		}
		conn, rw, er := hijacker.Hijack()
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return er
		}
		if n := rw.Reader.Buffered(); n > 0 {
			b := make([]byte, n)
			if _, err := io.ReadFull(rw, b); err != nil {
				panic("io.ReadFull error")
			}
			rwc = &Conn{Closer: conn, rw: conn, Reader: bytes.NewReader(b)}
		} else {
			rwc = &Conn{Closer: conn, rw: conn}
		}
	case 2, 3:
		rwc = &rwConn{Reader: r.Body, Writer: w, Closer: r.Body}
	}

	switch r.Host[:4] {
	case "tcp.":
		m.logger.Info(fmt.Sprintf("handle tcp connection from %v", r.RemoteAddr))
		if err := HandleTCP(rwc, m.Server); err != nil {
			m.logger.Error(fmt.Sprintf("handle tcp error: %v", err))
		}
	case "udp.":
		m.logger.Info(fmt.Sprintf("handle udp connection from %v", r.RemoteAddr))
		if err := HandleUDP(rwc, m.Server, time.Minute*3); err != nil {
			m.logger.Error(fmt.Sprintf("handle udp error: %v", err))
		}
	default:
		if _, ok := w.(http.Hijacker); !ok {
			return next.ServeHTTP(w, r)
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

// AuthLen is the length is http basic auth
var AuthLen = len(fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(make([]byte, 28))))))

func (m *Handler) authenticate(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	m.mutex.RLock()
	_, ok := m.users[auth]
	m.mutex.RUnlock()

	if ok {
		return true
	}
	if AuthLen != len(auth) || m.ShadowBox == "" {
		return false
	}

	m.mutex.Lock()
	if _, ok = m.users[auth]; ok {
		m.mutex.Unlock()
		return true
	}
	if time.Now().Sub(m.last) < time.Second {
		m.mutex.Unlock()
		return false
	}

	server, err := outline.NewOutlineServer(m.ShadowBox)
	if err != nil {
		m.logger.Error(fmt.Sprintf("connect shadowbox error: %v", err))
		return false
	}

	for user := range m.users {
		delete(m.users, user)
	}
	for _, user := range server.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user.Password))
		sum := sha256.Sum224([]byte(user.Password))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user))
		sum := sha256.Sum224([]byte(user))
		auth := fmt.Sprintf("Basic %v", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(sum[:]))))
		m.users[auth] = struct{}{}
	}
	m.last = time.Now()
	m.mutex.Unlock()

	m.mutex.RLock()
	_, ok = m.users[auth]
	m.mutex.RUnlock()
	return ok
}

type rwConn struct {
	io.Reader
	io.Writer
	io.Closer
}

func (c *rwConn) Write(b []byte) (n int, err error) {
	n, err = c.Writer.Write(b)
	if flusher, ok := c.Writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return
}

// Conn is ...
type Conn struct {
	io.Closer
	rw     io.ReadWriter
	Reader io.Reader
	Writer io.Writer
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	if c.Reader == nil {
		return c.rw.Read(b)
	}
	n, err := c.Reader.Read(b)
	if errors.Is(err, io.EOF) {
		err = nil
		c.Reader = nil
	}
	return n, err
}

// Write ...
func (c *Conn) Write(b []byte) (int, error) {
	if c.Writer == nil {
		if _, err := io.WriteString(c.rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return 0, err
		}
		c.Writer = c.rw
	}
	return c.Writer.Write(b)
}

// HandleTCP is ...
func HandleTCP(rwc io.ReadWriteCloser, addr string) error {
	defer rwc.Close()

	raddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}

	rc, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(chan error) {
		_, err := io.Copy(io.Writer(rc), rwc)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			rc.CloseWrite()
			rwc.Close()
			errCh <- nil
			return
		}
		rc.SetReadDeadline(time.Now())
		rc.CloseRead()
		rwc.Close()
		errCh <- err
	}(errCh)

	_, err = io.Copy(rwc, io.Reader(rc))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		rc.CloseRead()
		rwc.Close()
		return <-errCh
	}
	rc.SetWriteDeadline(time.Now())
	rc.CloseWrite()
	rwc.Close()
	<-errCh

	return err
}

// HandleUDP is ...
func HandleUDP(rwc io.ReadWriteCloser, addr string, timeout time.Duration) error {
	defer rwc.Close()

	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	rc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(chan error) (err error) {
		defer func() {
			if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
				rwc.Close()
				errCh <- nil
				return
			}
			rwc.Close()
			errCh <- err
		}()

		b := make([]byte, 16*1024)
		for {
			if _, err = io.ReadFull(rwc, b[:2]); err != nil {
				break
			}
			n := int(b[0])<<8 | int(b[1])
			if _, err = io.ReadFull(rwc, b[:n]); err != nil {
				break
			}
			if _, err = rc.Write(b[:n]); err != nil {
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(errCh)

	b := make([]byte, 16*1024)
	for {
		n := 0
		rc.SetReadDeadline(time.Now().Add(timeout))
		n, err = rc.Read(b[2:])
		if err != nil {
			break
		}
		b[0] = byte(n >> 8)
		b[1] = byte(n)
		if _, err = rwc.Write(b[:2+n]); err != nil {
			break
		}
	}
	rc.SetWriteDeadline(time.Now())

	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
		rwc.Close()
		return <-errCh
	}
	rwc.Close()
	<-errCh

	return err
}
