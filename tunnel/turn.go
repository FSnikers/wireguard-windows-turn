/* SPDX-License-Identifier: MIT */

package tunnel

import (
	"context"
	"fmt"
	"log"

	"golang.zx2c4.com/wireguard/windows/conf"
	turnproxy "golang.zx2c4.com/wireguard/windows/turn"
)

func startTurnProxy(ctx context.Context, config *conf.Config) (*turnproxy.Client, error) {
	if !config.Turn.Enabled {
		return nil, nil
	}
	if len(config.Peers) != 1 {
		return nil, fmt.Errorf("TURN mode currently supports exactly one peer, found %d", len(config.Peers))
	}
	if config.Turn.Listen.IsEmpty() {
		return nil, fmt.Errorf("TURN Listen must be set to a local endpoint, for example 127.0.0.1:51820")
	}
	peerEndpoint := config.Turn.Peer
	if peerEndpoint.IsEmpty() {
		peerEndpoint = config.Peers[0].Endpoint
	}
	if peerEndpoint.IsEmpty() {
		return nil, fmt.Errorf("TURN peer endpoint is required either as [TURN] Peer or [Peer] Endpoint")
	}

	cfg := turnproxy.Config{
		PeerAddr:         peerEndpoint.String(),
		Mode:             config.Turn.Mode,
		Link:             config.Turn.Link,
		Streams:          config.Turn.Streams,
		UDP:              config.Turn.UDP,
		ListenAddr:       config.Turn.Listen.String(),
		TurnIP:           config.Turn.TurnIP,
		TurnPort:         config.Turn.TurnPort,
		PeerType:         config.Turn.PeerType,
		StreamsPerCred:   config.Turn.StreamsPerCred,
		WatchdogTimeout:  config.Turn.WatchdogTimeout,
		VKAutoCaptcha:    config.Turn.VKAutoCaptcha,
		VKAutoCaptchaSet: config.Turn.VKAutoCaptchaSet,
		VKCaptchaCommand: config.Turn.VKCaptchaCommand,
		StaticUsername:   config.Turn.Username,
		StaticPassword:   config.Turn.Password,
		StaticServer:     config.Turn.Server,
	}
	client, err := turnproxy.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	config.Peers[0].Endpoint = config.Turn.Listen
	log.Printf("TURN proxy enabled: WireGuard peer endpoint rewritten to %s; relay peer is %s", config.Turn.Listen.String(), peerEndpoint.String())
	return client, nil
}
