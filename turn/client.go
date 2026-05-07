/* SPDX-License-Identifier: MIT
 *
 * TURN transport support adapted for WireGuard for Windows from
 * https://github.com/kiper292/wireguard-turn-android.
 */

package turn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	pionturn "github.com/pion/turn/v5"
)

const packetBufferMaxSize = 2048

type Config struct {
	PeerAddr         string
	Mode             string
	Link             string
	Streams          int
	UDP              bool
	ListenAddr       string
	TurnIP           string
	TurnPort         int
	PeerType         string
	StreamsPerCred   int
	WatchdogTimeout  int
	VKAutoCaptcha    bool
	VKAutoCaptchaSet bool
	VKCaptchaCommand string

	StaticUsername string
	StaticPassword string
	StaticServer   string
}

type Client struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type stream struct {
	ctx             context.Context
	id              int
	in              chan []byte
	out             net.PacketConn
	peer            atomic.Pointer[net.Addr]
	ready           atomic.Bool
	sessionID       []byte
	cert            *tls.Certificate
	watchdogTimeout int
	getCreds        getCredsFunc
}

type getCredsFunc func(context.Context, string, int) (string, string, string, error)

var packetPool = sync.Pool{New: func() any { return make([]byte, packetBufferMaxSize) }}

func turnLog(format string, args ...any) {
	log.Printf(format, args...)
}

func Start(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	peer, err := net.ResolveUDPAddr("udp", cfg.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve WireGuard peer address: %w", err)
	}
	lc, err := net.ListenPacket("udp", cfg.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen TURN proxy on %s: %w", cfg.ListenAddr, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	client := &Client{cancel: cancel, done: make(chan struct{})}
	context.AfterFunc(ctx, func() { _ = lc.Close() })

	getCreds, err := cfg.credentialsFunc()
	if err != nil {
		cancel()
		_ = lc.Close()
		return nil, err
	}

	sessionID, _ := uuid.New().MarshalBinary()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		cancel()
		_ = lc.Close()
		return nil, fmt.Errorf("generate DTLS certificate: %w", err)
	}

	ready := make(chan struct{}, cfg.Streams)
	streams := make([]*stream, cfg.Streams)
	for i := range streams {
		streams[i] = &stream{
			ctx: ctx, id: i, in: make(chan []byte, 512), out: lc,
			sessionID: sessionID, cert: &cert, watchdogTimeout: cfg.WatchdogTimeout,
			getCreds: getCreds,
		}
		go streams[i].run(cfg.Link, peer, cfg.UDP, ready, cfg.TurnIP, cfg.TurnPort, cfg.PeerType)
		time.Sleep(200 * time.Millisecond)
	}

	go client.runHub(ctx, lc, streams)

	select {
	case <-ready:
		log.Printf("TURN proxy ready on %s for peer %s", cfg.ListenAddr, cfg.PeerAddr)
		return client, nil
	case <-ctx.Done():
		_ = lc.Close()
		return nil, ctx.Err()
	case <-time.After(45 * time.Second):
		cancel()
		_ = lc.Close()
		return nil, errors.New("timed out waiting for TURN proxy stream")
	}
}

func (c *Client) Stop() {
	if c == nil {
		return
	}
	c.cancel()
	<-c.done
}

func (c *Client) runHub(ctx context.Context, lc net.PacketConn, streams []*stream) {
	defer close(c.done)
	lastUsed := 0
	for {
		b := packetPool.Get().([]byte)[:packetBufferMaxSize]
		n, addr, err := lc.ReadFrom(b)
		if err != nil {
			packetPool.Put(b[:cap(b)])
			return
		}
		select {
		case <-ctx.Done():
			packetPool.Put(b[:cap(b)])
			return
		default:
		}

		lastUsed = (lastUsed + 1) % len(streams)
		var s *stream
		for i := range streams {
			candidate := streams[(lastUsed+i)%len(streams)]
			if candidate.ready.Load() {
				s = candidate
				break
			}
		}
		if s == nil {
			packetPool.Put(b[:cap(b)])
			continue
		}
		returnAddr := addr
		s.peer.Store(&returnAddr)
		select {
		case s.in <- b[:n]:
		default:
			packetPool.Put(b[:cap(b)])
		}
	}
}

func (cfg *Config) normalize() error {
	if cfg.PeerAddr == "" {
		return errors.New("TURN peer address is required")
	}
	if cfg.Streams <= 0 {
		cfg.Streams = 1
	}
	if cfg.StreamsPerCred <= 0 {
		cfg.StreamsPerCred = 4
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.Mode == "" {
		cfg.Mode = "static"
	}
	if cfg.PeerType == "" {
		cfg.PeerType = "proxy_v2"
	}
	if cfg.PeerType != "proxy_v2" && cfg.PeerType != "proxy_v1" && cfg.PeerType != "wireguard" {
		return fmt.Errorf("unsupported TURN peer type %q", cfg.PeerType)
	}
	return nil
}

func (cfg Config) credentialsFunc() (getCredsFunc, error) {
	switch strings.ToLower(cfg.Mode) {
	case "static":
		if cfg.StaticUsername == "" || cfg.StaticPassword == "" || cfg.StaticServer == "" {
			return nil, errors.New("static TURN mode requires TurnUsername, TurnPassword, and TurnServer")
		}
		return func(context.Context, string, int) (string, string, string, error) {
			return cfg.StaticUsername, cfg.StaticPassword, cfg.StaticServer, nil
		}, nil
	case "wb":
		streamsPerCred = cfg.StreamsPerCred
		return func(ctx context.Context, link string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, link, streamID, wbFetch)
		}, nil
	case "vk":
		streamsPerCred = cfg.StreamsPerCred
		link := normalizeVKJoinLink(cfg.Link)
		if link == "" {
			return nil, errors.New("vk TURN mode requires Link with a VK call join URL or token")
		}
		autoCaptcha := true
		if cfg.VKAutoCaptchaSet {
			autoCaptcha = cfg.VKAutoCaptcha
		}
		vkOptions := vkCredentialOptions{
			AutoCaptcha:    autoCaptcha,
			CaptchaCommand: cfg.VKCaptchaCommand,
		}
		return func(ctx context.Context, _ string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, link, streamID, func(ctx context.Context, link string) (string, string, string, error) {
				return fetchVkCredsWithOptions(ctx, link, vkOptions)
			})
		}, nil
	default:
		return nil, fmt.Errorf("unsupported TURN credential mode %q", cfg.Mode)
	}
}

func (s *stream) run(link string, peer *net.UDPAddr, udp bool, ready chan<- struct{}, turnIP string, turnPort int, peerType string) {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		err := s.runOnce(link, peer, udp, ready, turnIP, turnPort, peerType)
		if err != nil && s.ctx.Err() == nil {
			log.Printf("TURN stream %d error: %v; reconnecting", s.id, err)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func (s *stream) runOnce(link string, peer *net.UDPAddr, udp bool, ready chan<- struct{}, turnIP string, turnPort int, peerType string) error {
	s.ready.Store(false)
	sCtx, sCancel := context.WithCancel(s.ctx)
	defer sCancel()
	user, pass, addr, err := s.getCreds(sCtx, link, s.id)
	if err != nil {
		return fmt.Errorf("TURN credentials failed: %w", err)
	}
	addr = overrideTURNAddr(addr, turnIP, turnPort)

	dialer := &net.Dialer{Timeout: 30 * time.Second}
	var turnConn net.PacketConn
	if udp {
		c, err := dialer.DialContext(sCtx, "udp", addr)
		if err != nil {
			return fmt.Errorf("TURN UDP dial failed: %w", err)
		}
		defer c.Close()
		turnConn = &connectedUDPConn{c.(*net.UDPConn)}
	} else {
		c, err := dialer.DialContext(sCtx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("TURN TCP dial failed: %w", err)
		}
		defer c.Close()
		turnConn = pionturn.NewSTUNConn(c)
	}

	client, err := pionturn.NewClient(&pionturn.ClientConfig{
		STUNServerAddr: addr, TURNServerAddr: addr, Username: user, Password: pass,
		Conn: turnConn, LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return fmt.Errorf("TURN client creation failed: %w", err)
	}
	defer client.Close()
	if err := client.Listen(); err != nil {
		if isAuthError(err) {
			handleAuthError(s.id)
		}
		return fmt.Errorf("TURN listen failed: %w", err)
	}
	relayConn, err := client.Allocate()
	if err != nil {
		if isAuthError(err) {
			handleAuthError(s.id)
		}
		return fmt.Errorf("TURN allocation failed: %w", err)
	}
	defer relayConn.Close()

	if peerType == "wireguard" {
		return s.runNoDTLS(sCtx, relayConn, peer, ready)
	}
	return s.runDTLS(sCtx, relayConn, peer, ready, peerType != "proxy_v1")
}

func overrideTURNAddr(addr, turnIP string, turnPort int) string {
	if turnIP == "" && turnPort == 0 {
		return addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if turnIP != "" {
		host = turnIP
	}
	if turnPort != 0 {
		port = fmt.Sprint(turnPort)
	}
	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, ready chan<- struct{}) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				_, err := relayConn.WriteTo(b, peer)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, packetBufferMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if from.String() == peer.String() {
				if last := s.peer.Load(); last != nil {
					if _, err := s.out.WriteTo(buf[:n], *last); err != nil {
						return
					}
				}
			}
		}
	}()
	s.ready.Store(true)
	select {
	case ready <- struct{}{}:
	default:
	}
	wg.Wait()
	return nil
}

func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, ready chan<- struct{}, sendHandshake bool) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()
	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates: []tls.Certificate{*s.cert}, InsecureSkipVerify: true,
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		return fmt.Errorf("DTLS client creation failed: %w", err)
	}
	defer dtlsConn.Close()
	context.AfterFunc(sCtx, func() { _ = relayConn.Close(); _ = c1.Close() })
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() { defer wg.Done(); defer sCancel(); relayToPeer(c2, relayConn, peer) }()
	go func() { defer wg.Done(); defer sCancel(); peerToRelay(relayConn, c2, peer) }()
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sCtx.Done():
				return
			case <-ticker.C:
				deadline := time.Now().Add(30 * time.Second)
				_ = relayConn.SetDeadline(deadline)
				_ = dtlsConn.SetDeadline(deadline)
				_ = c2.SetDeadline(deadline)
			}
		}
	}()
	_ = dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := dtlsConn.HandshakeContext(sCtx); err != nil {
		return fmt.Errorf("DTLS handshake failed: %w", err)
	}
	_ = dtlsConn.SetDeadline(time.Time{})
	if sendHandshake {
		handshakeBuf := make([]byte, 17)
		copy(handshakeBuf[:16], s.sessionID)
		handshakeBuf[16] = byte(s.id)
		_ = dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := dtlsConn.Write(handshakeBuf); err != nil {
			return fmt.Errorf("session ID handshake failed: %w", err)
		}
		_ = dtlsConn.SetWriteDeadline(time.Time{})
	}
	s.ready.Store(true)
	select {
	case ready <- struct{}{}:
	default:
	}
	lastRx := atomic.Int64{}
	lastRx.Store(time.Now().Unix())
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer sCancel()
		for {
			select {
			case <-sCtx.Done():
				return
			case b := <-s.in:
				if s.watchdogTimeout > 0 && time.Since(time.Unix(lastRx.Load(), 0)) > time.Duration(s.watchdogTimeout)*time.Second {
					packetPool.Put(b[:cap(b)])
					return
				}
				_, err := dtlsConn.Write(b)
				packetPool.Put(b[:cap(b)])
				if err != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer sCancel()
		buf := make([]byte, packetBufferMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				return
			}
			lastRx.Store(time.Now().Unix())
			if last := s.peer.Load(); last != nil {
				if _, err := s.out.WriteTo(buf[:n], *last); err != nil {
					return
				}
			}
		}
	}()
	wg.Wait()
	return nil
}

func relayToPeer(src net.PacketConn, dst net.PacketConn, peer net.Addr) {
	buf := make([]byte, packetBufferMaxSize)
	for {
		n, _, err := src.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := dst.WriteTo(buf[:n], peer); err != nil {
			return
		}
	}
}

func peerToRelay(src net.PacketConn, dst net.PacketConn, peer net.Addr) {
	buf := make([]byte, packetBufferMaxSize)
	for {
		n, from, err := src.ReadFrom(buf)
		if err != nil {
			return
		}
		if from.String() == peer.String() {
			if _, err := dst.WriteTo(buf[:n], peer); err != nil {
				return
			}
		}
	}
}

var turnHTTPClient = &http.Client{Timeout: 20 * time.Second}

type connectedUDPConn struct{ *net.UDPConn }

func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }
