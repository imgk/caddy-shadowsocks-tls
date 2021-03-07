package shadowsocks

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/time/rate"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"go.uber.org/zap"

	"github.com/imgk/caddy-shadowsocks-tls/outline"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements an HTTP handler that ...
type Handler struct {
	// Server is ...
	// shadowsocks server
	Server string `json:"server,omitempty"`
	// ShadowBox is ...
	// outline server
	ShadowBox string `json:"shadowbox,omitempty"`
	// Users is ...
	// shadowsoscks users
	Users []string `json:"users,omitempty"`

	logger *zap.Logger

	// users and outline users
	limit *rate.Limiter
	mutex *sync.RWMutex
	users map[string]struct{}

	proxyIP   net.IP
	proxyPort int
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
			m.Server = fmt.Sprintf("127.0.0.1:%v", server.PortForNewAccessKeys)
		}

		m.logger.Info("add user from shadowbox server")
		for _, user := range server.Users {
			m.logger.Info(fmt.Sprintf("add new user: %v", user.Password))
			m.users[GenKey(user.Password)] = struct{}{}
		}
		m.limit = rate.NewLimiter(rate.Every(time.Second), 1)
	}

	proxyAddr, err := net.ResolveTCPAddr("tcp", m.Server)
	if err != nil {
		return
	}
	m.proxyIP = proxyAddr.IP
	m.proxyPort = proxyAddr.Port

	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user))
		m.users[GenKey(user)] = struct{}{}
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

	rr, ww := io.Reader(nil), io.Writer(nil)
	switch r.ProtoMajor {
	case 1:
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return errors.New("http hijacker error")
		}

		conn, buf, er := hijacker.Hijack()
		if er != nil {
			http.Error(w, er.Error(), http.StatusInternalServerError)
			return er
		}
		defer conn.Close()

		if n := buf.Reader.Buffered(); n > 0 {
			b := make([]byte, n)
			if _, err := io.ReadFull(buf.Reader, b); err != nil {
				panic("io.ReadFull error")
			}
			c := &Conn{rw: conn, r: bytes.NewReader(b)}
			rr = c
			ww = c
		} else {
			c := &Conn{rw: conn}
			rr = c
			ww = c
		}
	case 2, 3:
		rr = r.Body
		ww = &FlushWriter{w: w, f: w.(http.Flusher)}
	}

	switch r.Host[:4] {
	case "tcp.":
		m.logger.Info(fmt.Sprintf("handle tcp connection from %v", r.RemoteAddr))
		if err := HandleTCP(rr, ww, &net.TCPAddr{IP: m.proxyIP, Port: m.proxyPort}); err != nil {
			m.logger.Error(fmt.Sprintf("handle tcp error: %v", err))
		}
	case "udp.":
		m.logger.Info(fmt.Sprintf("handle udp connection from %v", r.RemoteAddr))
		if err := HandleUDP(rr, ww, &net.UDPAddr{IP: m.proxyIP, Port: m.proxyPort}, time.Minute*10); err != nil {
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

// StringToByteSlice is ...
func StringToByteSlice(s string) []byte {
	ptr := (*reflect.StringHeader)(unsafe.Pointer(&s))
	hdr := &reflect.SliceHeader{
		Data: ptr.Data,
		Cap:  ptr.Len,
		Len:  ptr.Len,
	}
	return *(*[]byte)(unsafe.Pointer(hdr))
}

// GenKey is ...
func GenKey(s string) string {
	sum := sha256.Sum224(StringToByteSlice(s))
	hex := StringToByteSlice(hex.EncodeToString(sum[:]))
	b64 := base64.StdEncoding.EncodeToString(hex)
	return fmt.Sprintf("Basic %v", b64)
}

// AuthLen is the length is http basic auth
// len(GenKey("Test1234"))
const AuthLen = 82

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
	if !m.limit.Allow() {
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
		m.users[GenKey(user.Password)] = struct{}{}
	}
	for _, user := range m.Users {
		m.logger.Info(fmt.Sprintf("add new user: %v", user))
		m.users[GenKey(user)] = struct{}{}
	}
	m.mutex.Unlock()

	m.mutex.RLock()
	_, ok = m.users[auth]
	m.mutex.RUnlock()
	return ok
}

// FlushWriter is ...
type FlushWriter struct {
	w io.Writer
	f http.Flusher
}

// Write is ...
func (c *FlushWriter) Write(b []byte) (n int, err error) {
	n, err = c.w.Write(b)
	c.f.Flush()
	return
}

// Conn is ...
type Conn struct {
	rw net.Conn
	r  io.Reader
	w  io.Writer
}

// CloseWrite: *net.TCPConn and *tls.Conn
func (c *Conn) CloseWrite() error {
	if conn, ok := c.rw.(*net.TCPConn); ok {
		return conn.CloseWrite()
	}
	if conn, ok := c.rw.(*tls.Conn); ok {
		return conn.CloseWrite()
	}
	return errors.New("conn type error")
}

// Read is ...
func (c *Conn) Read(b []byte) (int, error) {
	if c.r == nil {
		return c.rw.Read(b)
	}
	n, err := c.r.Read(b)
	if errors.Is(err, io.EOF) {
		err = nil
		c.r = nil
	}
	return n, err
}

// Write is ...
func (c *Conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if _, err := io.WriteString(c.rw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return 0, err
		}
		c.w = c.rw
	}
	return c.w.Write(b)
}

// HandleTCP is ...
func HandleTCP(r io.Reader, w io.Writer, raddr *net.TCPAddr) error {
	rc, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(rc *net.TCPConn, r io.Reader, errCh chan error) {
		_, err := io.Copy(io.Writer(rc), r)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			rc.CloseWrite()
			errCh <- nil
			return
		}
		rc.SetReadDeadline(time.Now())
		errCh <- err
	}(rc, r, errCh)

	err = func(rc *net.TCPConn, w io.Writer, errCh chan error) (err error) {
		_, err = io.Copy(w, io.Reader(rc))
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			if c, ok := w.(*Conn); ok {
				c.CloseWrite()
			}
			err = <-errCh
			return
		}
		rc.SetWriteDeadline(time.Now())
		rc.CloseWrite()
		<-errCh
		return
	}(rc, w, errCh)

	return err
}

// HandleUDP is ...
func HandleUDP(r io.Reader, w io.Writer, raddr *net.UDPAddr, timeout time.Duration) error {
	rc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer rc.Close()

	errCh := make(chan error, 1)
	go func(rc *net.UDPConn, r io.Reader, errCh chan error) (err error) {
		defer func() {
			if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
				errCh <- nil
				return
			}
			errCh <- err
		}()

		b := make([]byte, 16*1024)
		for {
			if _, err = io.ReadFull(r, b[:2]); err != nil {
				break
			}
			n := int(b[0])<<8 | int(b[1])
			if _, err = io.ReadFull(r, b[:n]); err != nil {
				break
			}
			if _, err = rc.Write(b[:n]); err != nil {
				break
			}
		}
		rc.SetReadDeadline(time.Now())
		return
	}(rc, r, errCh)

	err = func(rc *net.UDPConn, w io.Writer, errCh chan error, timeout time.Duration) (err error) {
		n := 0
		b := make([]byte, 16*1024)
		for {
			rc.SetReadDeadline(time.Now().Add(timeout))
			n, err = rc.Read(b[2:])
			if err != nil {
				break
			}
			b[0] = byte(n >> 8)
			b[1] = byte(n)
			if _, err = w.Write(b[:2+n]); err != nil {
				break
			}
		}

		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, io.EOF) {
			err = <-errCh
			return
		}
		rc.SetWriteDeadline(time.Now())
		<-errCh
		return
	}(rc, w, errCh, timeout)

	return err
}
