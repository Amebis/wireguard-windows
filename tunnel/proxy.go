/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2024 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"

	"codeberg.org/eduVPN/proxyguard"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type ProxyLogger struct{}

func (pl *ProxyLogger) Logf(msg string, params ...interface{}) {
	log.Println("[Proxyguard] ", fmt.Sprintf(msg, params...))
}

func (pl *ProxyLogger) Log(msg string) {
	log.Println("[Proxyguard] ", msg)
}

func init() {
	proxyguard.UpdateLogger(&ProxyLogger{})
}

type proxy struct {
	proxyguard.Client
	Addresses []netip.Addr
}

func spawnProxies(conf *conf.Config, ctx context.Context) ([]*proxy, error) {
	proxies := make([]*proxy, 0)
	for _, peer := range conf.Peers {
		if len(peer.ProxyEndpoint) > 0 {
			log.Println("Resolving peer proxy name")
			u, err := url.Parse(peer.ProxyEndpoint)
			if err != nil {
				return nil, err
			}
			pips, err := net.DefaultResolver.LookupHost(ctx, u.Hostname())
			if err != nil {
				return nil, err
			}
			addresses := make([]netip.Addr, 0, len(pips))
			for _, ip := range pips {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, err
				}
				addresses = append(addresses, addr)
			}

			log.Println("Spawning peer proxy")
			proxyReady := make(chan error)
			p := &proxy{
				Client: proxyguard.Client{
					Listen: peer.Endpoint.String(),
					Ready:  func() { proxyReady <- nil },
				},
				Addresses: addresses,
			}
			proxies = append(proxies, p)
			go func() { proxyReady <- p.Tunnel(ctx, peer.ProxyEndpoint, pips) }()
			err = <-proxyReady
			if err != nil {
				return nil, err
			}
		}
	}
	return proxies, nil
}

func monitorProxyRoutes(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, proxies []*proxy) ([]winipcfg.ChangeCallback, error) {
	destProxy := make(map[netip.Prefix][]*proxy)
	for _, p := range proxies {
		for _, addr := range p.Addresses {
			if family == windows.AF_INET && !addr.Is4() {
				continue
			}
			if family == windows.AF_INET6 && !addr.Is6() {
				continue
			}
			destination := netip.PrefixFrom(addr, addr.BitLen())
			destProxy[destination] = append(destProxy[destination], p)
		}
	}

	type luidRouteData struct {
		luid        winipcfg.LUID
		destination netip.Prefix
		nextHop     netip.Addr
	}
	ourRoutes := make(map[luidRouteData]bool)

	doIt := func(restartProxies bool) error {
		newRoutes := make(map[luidRouteData]bool)
		proxiesToRestart := make(map[*proxy]bool)
		err := iterateForeignDefaultRoutes(family, ourLUID, func(r *winipcfg.MibIPforwardRow2) error {
			for destination := range destProxy {
				nextHop := r.NextHop.Addr()
				err := r.InterfaceLUID.AddRoute(destination, nextHop, 0)
				if err == nil {
					for _, p := range destProxy[destination] {
						proxiesToRestart[p] = true
					}
				}
				if err == nil || err == windows.ERROR_OBJECT_ALREADY_EXISTS {
					newRoutes[luidRouteData{
						luid:        r.InterfaceLUID,
						destination: destination,
						nextHop:     nextHop,
					}] = true
				} else {
					log.Printf("[Proxyguard] Failed to add route %v via %v: %v", destination, nextHop, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for r := range ourRoutes {
			if _, keepRoute := newRoutes[r]; !keepRoute {
				err := r.luid.DeleteRoute(r.destination, r.nextHop)
				if err == nil {
					for _, p := range destProxy[r.destination] {
						proxiesToRestart[p] = true
					}
				} else if err != windows.ERROR_NOT_FOUND {
					log.Printf("[Proxyguard] Failed to delete route %v via %v: %v", r.destination, r.nextHop, err)
				}
			}
		}
		ourRoutes = newRoutes
		// TODO: This is commented for the time being, as there are timing issues and does more harm.
		// Proxyguard cant handle rapid restart signals caused by multiple default route changes
		// rendering it into a zombie. On the other hand, should routing change drop its HTTP(S)
		// upstream connection, the Proxyguard will restart by its own.
		// if restartProxies {
		// 	for p := range proxiesToRestart {
		// 		log.Printf("[Proxyguard] Signaling proxy %v to restart after default route change", p.Listen)
		// 		err = p.SignalRestart()
		// 		if err != nil {
		// 			log.Printf("[Proxyguard] Failed to signal proxy %v to restart: %v", p.Listen, err)
		// 		}
		// 	}
		// }
		return nil
	}
	err := doIt(false)
	if err != nil {
		return nil, err
	}

	cleanIt := func() {
		for r := range ourRoutes {
			err := r.luid.DeleteRoute(r.destination, r.nextHop)
			if err != nil && err != windows.ERROR_NOT_FOUND {
				log.Printf("[Proxyguard] Failed to delete route %v via %v: %v", r.destination, r.nextHop, err)
			}
		}
		ourRoutes = make(map[luidRouteData]bool)
	}

	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			doIt(true)
		}
	}, cleanIt)
	if err != nil {
		cleanIt()
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			doIt(true)
		}
	}, cleanIt)
	if err != nil {
		cbr.Unregister()
		cleanIt()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}
