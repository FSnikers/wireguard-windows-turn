/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/text/encoding/unicode"

	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/l18n"
)

type ParseError struct {
	why      string
	offender string
}

func (e *ParseError) Error() string {
	return l18n.Sprintf("%s: %q", e.why, e.offender)
}

func parseIPCidr(s string) (netip.Prefix, error) {
	ipcidr, err := netip.ParsePrefix(s)
	if err == nil {
		return ipcidr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ParseError{l18n.Sprintf("Invalid IP address: "), s}
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{l18n.Sprintf("Missing port from endpoint"), s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{l18n.Sprintf("Invalid endpoint host"), host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{l18n.Sprintf("Brackets must contain an IPv6 address"), host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			end := len(host) - 1
			if i := strings.LastIndexByte(host, '%'); i > 1 {
				end = i
			}
			maybeV6, err2 := netip.ParseAddr(host[1:end])
			if err2 != nil || !maybeV6.Is6() {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, port}, nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid MTU"), s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid port"), s}
	}
	return uint16(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{l18n.Sprintf("Invalid persistent keepalive"), s}
	}
	return uint16(m), nil
}

func parseTableOff(s string) (bool, error) {
	if s == "off" {
		return true, nil
	} else if s == "auto" || s == "main" {
		return false, nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return false, err
}

func parseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{l18n.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{l18n.Sprintf("Keys must decode to exactly 32 bytes"), s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}
func parseWGTBool(s string) bool {
	return strings.EqualFold(s, "true") || s == "1" || strings.EqualFold(s, "yes") || strings.EqualFold(s, "on")
}

func (c *Config) ensureWGTDefaults() {
	if c.Turn.Mode == "" {
		c.Turn.Mode = "vk_link"
	}
	if c.Turn.Streams == 0 {
		c.Turn.Streams = 4
	}
	if c.Turn.Listen.IsEmpty() {
		c.Turn.Listen = Endpoint{Host: "127.0.0.1", Port: 9000}
	}
	if c.Turn.PeerType == "" {
		c.Turn.PeerType = "proxy_v2"
	}
	if c.Turn.StreamsPerCred == 0 {
		c.Turn.StreamsPerCred = 4
	}
}

func (c *Config) parseWGTComment(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#@wgt:") {
		return false, nil
	}
	c.ensureWGTDefaults()
	body := strings.TrimSpace(strings.TrimPrefix(line, "#@wgt:"))
	equals := strings.IndexByte(body, '=')
	if equals < 0 {
		return true, nil
	}
	key := strings.ToLower(strings.TrimSpace(body[:equals]))
	val := strings.TrimSpace(body[equals+1:])
	if beforeComment, _, ok := strings.Cut(val, "#"); ok {
		val = strings.TrimSpace(beforeComment)
	}
	if val == "" {
		return true, nil
	}

	switch key {
	case "enableturn":
		c.Turn.Enabled = parseWGTBool(val)
	case "useudp":
		c.Turn.UDP = parseWGTBool(val)
	case "ipport":
		e, err := parseEndpoint(val)
		if err != nil {
			return true, err
		}
		c.Turn.Peer = *e
	case "vklink":
		c.Turn.Link = val
	case "mode":
		c.Turn.Mode = val
	case "streamnum":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 {
			return true, &ParseError{l18n.Sprintf("Invalid TURN stream count"), val}
		}
		c.Turn.Streams = n
	case "localport":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 65535 {
			return true, &ParseError{l18n.Sprintf("Invalid TURN local port"), val}
		}
		c.Turn.Listen = Endpoint{Host: "127.0.0.1", Port: uint16(n)}
	case "turnip":
		c.Turn.TurnIP = val
	case "turnport":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 || n > 65535 {
			return true, &ParseError{l18n.Sprintf("Invalid TURN port"), val}
		}
		c.Turn.TurnPort = n
	case "watchdogtimeout":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return true, &ParseError{l18n.Sprintf("Invalid TURN watchdog timeout"), val}
		}
		c.Turn.WatchdogTimeout = n
	case "nodtls":
		if parseWGTBool(val) {
			c.Turn.PeerType = "wireguard"
		}
	case "peertype":
		c.Turn.PeerType = val
	case "streamspercred":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 {
			return true, &ParseError{l18n.Sprintf("Invalid TURN streams-per-credential count"), val}
		}
		c.Turn.StreamsPerCred = n
	}
	return true, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for split := range strings.SplitSeq(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{l18n.Sprintf("Two commas in a row"), s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	inInterfaceSection parserState = iota
	inPeerSection
	notInASection
	inTurnSection
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

func FromWgQuick(s, name string) (*Config, error) {
	if !TunnelNameIsValid(name) {
		return nil, &ParseError{l18n.Sprintf("Tunnel name is not valid"), name}
	}
	lines := strings.Split(s, "\n")
	parserState := notInASection
	conf := Config{Name: name}
	sawPrivateKey := false
	var peer *Peer
	for _, line := range lines {
		if handled, err := conf.parseWGTComment(line); handled {
			if err != nil {
				return nil, err
			}
			continue
		}
		line, _, _ = strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)
		if len(line) == 0 {
			continue
		}
		if lineLower == "[interface]" {
			conf.maybeAddPeer(peer)
			parserState = inInterfaceSection
			continue
		}
		if lineLower == "[peer]" {
			conf.maybeAddPeer(peer)
			peer = &Peer{}
			parserState = inPeerSection
			continue
		}
		if lineLower == "[turn]" {
			conf.maybeAddPeer(peer)
			peer = nil
			parserState = inTurnSection
			continue
		}
		if parserState == notInASection {
			return nil, &ParseError{l18n.Sprintf("Line must occur in a section"), line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return nil, &ParseError{l18n.Sprintf("Config key is missing an equals separator"), line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return nil, &ParseError{l18n.Sprintf("Key must have a value"), line}
		}
		if parserState == inInterfaceSection {
			switch key {
			case "privatekey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.PrivateKey = *k
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.ListenPort = p
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					conf.Interface.Addresses = append(conf.Interface.Addresses, a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := netip.ParseAddr(address)
					if err != nil {
						conf.Interface.DNSSearch = append(conf.Interface.DNSSearch, address)
					} else {
						conf.Interface.DNS = append(conf.Interface.DNS, a)
					}
				}
			case "preup":
				conf.Interface.PreUp = val
			case "postup":
				conf.Interface.PostUp = val
			case "predown":
				conf.Interface.PreDown = val
			case "postdown":
				conf.Interface.PostDown = val
			case "table":
				tableOff, err := parseTableOff(val)
				if err != nil {
					return nil, err
				}
				conf.Interface.TableOff = tableOff
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Interface] section"), key}
			}
		} else if parserState == inTurnSection {
			switch key {
			case "enabled":
				conf.Turn.Enabled = strings.EqualFold(val, "true") || val == "1" || strings.EqualFold(val, "yes")
			case "mode":
				conf.Turn.Mode = val
			case "link":
				conf.Turn.Link = val
			case "peer":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				conf.Turn.Peer = *e
			case "listen":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				conf.Turn.Listen = *e
			case "streams":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return nil, &ParseError{l18n.Sprintf("Invalid TURN stream count"), val}
				}
				conf.Turn.Streams = n
			case "udp":
				conf.Turn.UDP = strings.EqualFold(val, "true") || val == "1" || strings.EqualFold(val, "yes")
			case "turnip":
				conf.Turn.TurnIP = val
			case "turnport":
				n, err := strconv.Atoi(val)
				if err != nil || n < 0 || n > 65535 {
					return nil, &ParseError{l18n.Sprintf("Invalid TURN port"), val}
				}
				conf.Turn.TurnPort = n
			case "peertype":
				conf.Turn.PeerType = val
			case "streamspercred":
				n, err := strconv.Atoi(val)
				if err != nil || n < 1 {
					return nil, &ParseError{l18n.Sprintf("Invalid TURN streams-per-credential count"), val}
				}
				conf.Turn.StreamsPerCred = n
			case "watchdogtimeout":
				n, err := strconv.Atoi(val)
				if err != nil || n < 0 {
					return nil, &ParseError{l18n.Sprintf("Invalid TURN watchdog timeout"), val}
				}
				conf.Turn.WatchdogTimeout = n
			case "turnusername":
				conf.Turn.Username = val
			case "turnpassword":
				conf.Turn.Password = val
			case "turnserver":
				conf.Turn.Server = val
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [TURN] section"), key}
			}
		} else if parserState == inPeerSection {
			switch key {
			case "publickey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := parseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = *k
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = *e
			default:
				return nil, &ParseError{l18n.Sprintf("Invalid key for [Peer] section"), key}
			}
		}
	}
	conf.maybeAddPeer(peer)

	if !sawPrivateKey {
		return nil, &ParseError{l18n.Sprintf("An interface must have a private key"), l18n.Sprintf("[none specified]")}
	}
	for _, p := range conf.Peers {
		if p.PublicKey.IsZero() {
			return nil, &ParseError{l18n.Sprintf("All peers must have public keys"), l18n.Sprintf("[none specified]")}
		}
	}

	return &conf, nil
}

func FromWgQuickWithUnknownEncoding(s, name string) (*Config, error) {
	c, firstErr := FromWgQuick(s, name)
	if firstErr == nil {
		return c, nil
	}
	for _, encoding := range unicode.All {
		decoded, err := encoding.NewDecoder().String(s)
		if err == nil {
			c, err := FromWgQuick(decoded, name)
			if err == nil {
				return c, nil
			}
		}
	}
	return nil, firstErr
}

func FromDriverConfiguration(interfaze *driver.Interface, existingConfig *Config) *Config {
	conf := Config{
		Name: existingConfig.Name,
		Interface: Interface{
			Addresses: existingConfig.Interface.Addresses,
			DNS:       existingConfig.Interface.DNS,
			DNSSearch: existingConfig.Interface.DNSSearch,
			MTU:       existingConfig.Interface.MTU,
			PreUp:     existingConfig.Interface.PreUp,
			PostUp:    existingConfig.Interface.PostUp,
			PreDown:   existingConfig.Interface.PreDown,
			PostDown:  existingConfig.Interface.PostDown,
			TableOff:  existingConfig.Interface.TableOff,
		},
	}
	if interfaze.Flags&driver.InterfaceHasPrivateKey != 0 {
		conf.Interface.PrivateKey = interfaze.PrivateKey
	}
	if interfaze.Flags&driver.InterfaceHasListenPort != 0 {
		conf.Interface.ListenPort = interfaze.ListenPort
	}
	var p *driver.Peer
	for i := uint32(0); i < interfaze.PeerCount; i++ {
		if p == nil {
			p = interfaze.FirstPeer()
		} else {
			p = p.NextPeer()
		}
		peer := Peer{}
		if p.Flags&driver.PeerHasPublicKey != 0 {
			peer.PublicKey = p.PublicKey
		}
		if p.Flags&driver.PeerHasPresharedKey != 0 {
			peer.PresharedKey = p.PresharedKey
		}
		if p.Flags&driver.PeerHasEndpoint != 0 {
			peer.Endpoint.Port = p.Endpoint.Port()
			peer.Endpoint.Host = p.Endpoint.Addr().String()
		}
		if p.Flags&driver.PeerHasPersistentKeepalive != 0 {
			peer.PersistentKeepalive = p.PersistentKeepalive
		}
		peer.TxBytes = Bytes(p.TxBytes)
		peer.RxBytes = Bytes(p.RxBytes)
		if p.LastHandshake != 0 {
			peer.LastHandshakeTime = HandshakeTime((p.LastHandshake - 116444736000000000) * 100)
		}
		var a *driver.AllowedIP
		for j := uint32(0); j < p.AllowedIPsCount; j++ {
			if a == nil {
				a = p.FirstAllowedIP()
			} else {
				a = a.NextAllowedIP()
			}
			var ip netip.Addr
			if a.AddressFamily == windows.AF_INET {
				ip = netip.AddrFrom4(*(*[4]byte)(a.Address[:4]))
			} else if a.AddressFamily == windows.AF_INET6 {
				ip = netip.AddrFrom16(*(*[16]byte)(a.Address[:16]))
			}
			peer.AllowedIPs = append(peer.AllowedIPs, netip.PrefixFrom(ip, int(a.Cidr)))
		}
		conf.Peers = append(conf.Peers, peer)
	}
	return &conf
}
