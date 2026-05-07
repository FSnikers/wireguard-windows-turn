/* SPDX-License-Identifier: MIT
 * WB credential flow adapted from wireguard-turn-android.
 */

package turn

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	wbBase = "https://stream.wb.ru"
	wbUA   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

type wbTurnCred struct{ URL, Username, Password string }

func wbFetch(ctx context.Context, link string) (string, string, string, error) {
	_ = link
	creds, err := fetchWbCreds(ctx)
	if err != nil {
		return "", "", "", err
	}
	for _, cred := range creds {
		if strings.HasPrefix(cred.URL, "turn:") || strings.HasPrefix(cred.URL, "turns:") {
			clean := strings.Split(cred.URL, "?")[0]
			address := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
			return cred.Username, cred.Password, address, nil
		}
	}
	return "", "", "", fmt.Errorf("no TURN credentials received from WB")
}

func wbHTTPClient(serverName string) *http.Client {
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		MaxIdleConns: 100, MaxIdleConnsPerHost: 100, IdleConnTimeout: 90 * time.Second,
		DialContext:     (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{ServerName: serverName},
	}}
}

func wbReq(ctx context.Context, client *http.Client, method, ep string, body []byte, tok string) ([]byte, error) {
	baseURL := wbBase + ep
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	rq, err := http.NewRequestWithContext(ctx, method, baseURL, rd)
	if err != nil {
		return nil, err
	}
	rq.Host = parsedURL.Hostname()
	rq.Header.Set("User-Agent", wbUA)
	rq.Header.Set("Accept", "application/json")
	rq.Header.Set("Origin", wbBase)
	rq.Header.Set("Referer", wbBase+"/")
	if body != nil {
		rq.Header.Set("Content-Type", "application/json")
	}
	if tok != "" {
		rq.Header.Set("Authorization", "Bearer "+tok)
	}
	rs, err := client.Do(rq)
	if err != nil {
		return nil, err
	}
	defer rs.Body.Close()
	var r io.Reader = rs.Body
	if rs.Header.Get("Content-Encoding") == "gzip" {
		if g, e := gzip.NewReader(rs.Body); e == nil {
			defer g.Close()
			r = g
		}
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if rs.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", rs.StatusCode, string(b))
	}
	return b, nil
}

func fetchWbCreds(ctx context.Context) ([]wbTurnCred, error) {
	parsedBase, _ := url.Parse(wbBase)
	client := wbHTTPClient(parsedBase.Hostname())
	defer client.CloseIdleConnections()
	nm := fmt.Sprintf("lh_%d", time.Now().UnixMilli()%100000)
	rr, err := wbReq(ctx, client, "POST", "/auth/api/v1/auth/user/guest-register", []byte(`{"displayName":"`+nm+`"}`), "")
	if err != nil {
		return nil, fmt.Errorf("guest register: %w", err)
	}
	var reg struct {
		AccessToken string `json:"accessToken"`
	}
	if err = json.Unmarshal(rr, &reg); err != nil {
		return nil, err
	}
	if reg.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response")
	}
	rr, err = wbReq(ctx, client, "POST", "/api-room/api/v2/room", []byte(`{"roomType":"ROOM_TYPE_ALL_ON_SCREEN","roomPrivacy":"ROOM_PRIVACY_FREE"}`), reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("create room: %w", err)
	}
	var room struct {
		RoomID string `json:"roomId"`
	}
	if err = json.Unmarshal(rr, &room); err != nil {
		return nil, err
	}
	if room.RoomID == "" {
		return nil, fmt.Errorf("no room ID in response")
	}
	_, err = wbReq(ctx, client, "POST", fmt.Sprintf("/api-room/api/v1/room/%s/join", room.RoomID), []byte("{}"), reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("join room: %w", err)
	}
	rr, err = wbReq(ctx, client, "GET", fmt.Sprintf("/api-room-manager/api/v1/room/%s/token?deviceType=PARTICIPANT_DEVICE_TYPE_WEB_DESKTOP&displayName=%s", room.RoomID, url.QueryEscape(nm)), nil, reg.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	var tok struct {
		RoomToken string `json:"roomToken"`
	}
	if err = json.Unmarshal(rr, &tok); err != nil {
		return nil, err
	}
	if tok.RoomToken == "" {
		return nil, fmt.Errorf("no room token in response")
	}
	return wbLkICE(ctx, tok.RoomToken)
}

func wbLkICE(ctx context.Context, token string) ([]wbTurnCred, error) {
	wsURL := "wss://wbstream01-el.wb.ru:7880/rtc?access_token=" + url.QueryEscape(token) + "&auto_subscribe=1&sdk=js&version=2.15.3&protocol=16&adaptive_stream=1"
	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return nil, err
	}
	domain := parsedURL.Hostname()
	conn, _, err := (&websocket.Dialer{
		TLSClientConfig: &tls.Config{ServerName: domain}, HandshakeTimeout: 10 * time.Second,
		NetDialContext: (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
	}).DialContext(ctx, wsURL, http.Header{"User-Agent": {wbUA}, "Origin": {wbBase}, "Host": {domain}})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	for i := 0; i < 15; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if creds := wbPbICE(msg); len(creds) > 0 {
			return wbDedup(creds), nil
		}
	}
	return nil, fmt.Errorf("TURN credentials not found in LiveKit response")
}

func wbPbVar(d []byte, o int) (uint64, int) {
	var v uint64
	for s := 0; o < len(d) && s < 64; s += 7 {
		b := d[o]
		o++
		v |= uint64(b&0x7f) << s
		if b < 0x80 {
			return v, o
		}
	}
	return 0, o
}
func wbPbAll(d []byte, f uint64) (r [][]byte) {
	for o := 0; o < len(d); {
		t, n := wbPbVar(d, o)
		if n == o {
			break
		}
		o = n
		switch t & 7 {
		case 0:
			_, o = wbPbVar(d, o)
		case 2:
			l, n := wbPbVar(d, o)
			o = n
			e := o + int(l)
			if e > len(d) || e < o {
				return
			}
			if t>>3 == f {
				r = append(r, d[o:e])
			}
			o = e
		case 1:
			o += 8
		case 5:
			o += 4
		default:
			return
		}
	}
	return
}
func wbPbStr(d []byte, f uint64) string {
	if a := wbPbAll(d, f); len(a) > 0 {
		return string(a[0])
	}
	return ""
}
func wbPbICE(d []byte) (res []wbTurnCred) {
	for o := 0; o < len(d); {
		t, n := wbPbVar(d, o)
		if n == o {
			break
		}
		o = n
		switch t & 7 {
		case 0:
			_, o = wbPbVar(d, o)
		case 2:
			l, n := wbPbVar(d, o)
			o = n
			e := o + int(l)
			if e > len(d) || e < o {
				return
			}
			inner := d[o:e]
			for _, f := range []uint64{5, 9} {
				for _, blk := range wbPbAll(inner, f) {
					urls := wbPbAll(blk, 1)
					hit := false
					for _, u := range urls {
						s := string(u)
						if strings.HasPrefix(s, "turn") || strings.HasPrefix(s, "stun") {
							hit = true
							break
						}
					}
					if !hit {
						continue
					}
					un, pw := wbPbStr(blk, 2), wbPbStr(blk, 3)
					for _, u := range urls {
						res = append(res, wbTurnCred{string(u), un, pw})
					}
					return
				}
			}
			o = e
		case 1:
			o += 8
		case 5:
			o += 4
		default:
			return
		}
	}
	return
}
func wbDedup(cc []wbTurnCred) (r []wbTurnCred) {
	seen := map[string]bool{}
	for _, c := range cc {
		k := c.URL + "|" + c.Username
		if !seen[k] {
			seen[k] = true
			r = append(r, c)
		}
	}
	return
}
