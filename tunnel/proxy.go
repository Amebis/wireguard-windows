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

func spawnProxies(conf *conf.Config, ctx context.Context) ([]netip.Addr, error) {
	m := make(map[netip.Addr]bool)
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
			for _, ip := range pips {
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					return nil, err
				}
				if m[addr] {
					continue
				}
				m[addr] = true
			}

			log.Println("Spawning peer proxy")
			proxyReady := make(chan error)
			proxy := proxyguard.Client{
				Listen: peer.Endpoint.String(),
				Ready:  func() { proxyReady <- nil },
			}
			go func() { proxyReady <- proxy.Tunnel(ctx, peer.ProxyEndpoint, pips) }()
			err = <-proxyReady
			if err != nil {
				return nil, err
			}
		}
	}

	proxies := make([]netip.Addr, len(m))
	for addr := range m {
		proxies = append(proxies, addr)
	}
	return proxies, nil
}

func monitorProxyRoutes(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, proxies []netip.Addr) ([]winipcfg.ChangeCallback, error) {
	destinations := make([]netip.Prefix, 0, len(proxies))
	for _, addr := range proxies {
		if family == windows.AF_INET && !addr.Is4() {
			continue
		}
		if family == windows.AF_INET6 && !addr.Is6() {
			continue
		}
		destinations = append(destinations, netip.PrefixFrom(addr, addr.BitLen()))
	}

	type luidRouteData struct {
		luid        winipcfg.LUID
		destination netip.Prefix
		nextHop     netip.Addr
	}
	ourRoutes := make(map[luidRouteData]bool)

	doIt := func() error {
		newRoutes := make(map[luidRouteData]bool)
		err := iterateForeignDefaultRoutes(family, ourLUID, func(r *winipcfg.MibIPforwardRow2) error {
			for j := range destinations {
				nextHop := r.NextHop.Addr()
				err := r.InterfaceLUID.AddRoute(destinations[j], nextHop, 0)
				if err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
					log.Printf("[Proxyguard] Failed to add route %v via %v: %v", destinations[j], nextHop, err)
					continue
				}
				newRoutes[luidRouteData{
					luid:        r.InterfaceLUID,
					destination: destinations[j],
					nextHop:     nextHop,
				}] = true
			}
			return nil
		})
		if err != nil {
			return err
		}

		for r := range ourRoutes {
			_, keepRoute := newRoutes[r]
			if !keepRoute {
				err := r.luid.DeleteRoute(r.destination, r.nextHop)
				if err != nil && err != windows.ERROR_NOT_FOUND {
					log.Printf("[Proxyguard] Failed to delete route %v via %v: %v", r.destination, r.nextHop, err)
				}
			}
		}
		ourRoutes = newRoutes
		return nil
	}
	err := doIt()
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
			doIt()
		}
	}, cleanIt)
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			doIt()
		}
	}, cleanIt)
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}
