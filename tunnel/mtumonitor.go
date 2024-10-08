/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

func iterateForeignDefaultRoutes(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, callback func(r *winipcfg.MibIPforwardRow2) error) error {
	r, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return err
	}
	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == ourLUID {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		err = callback(&r[i])
		if err != nil {
			return err
		}
	}
	return nil
}

func findDefaultLUID(family winipcfg.AddressFamily, ourLUID winipcfg.LUID, lastLUID *winipcfg.LUID, lastIndex *uint32) error {
	lowestMetric := ^uint32(0)
	index := uint32(0)
	luid := winipcfg.LUID(0)
	err := iterateForeignDefaultRoutes(family, ourLUID, func(r *winipcfg.MibIPforwardRow2) error {
		iface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			return nil
		}

		if r.Metric+iface.Metric < lowestMetric {
			lowestMetric = r.Metric + iface.Metric
			index = r.InterfaceIndex
			luid = r.InterfaceLUID
		}
		return nil
	})
	if err != nil {
		return err
	}
	if luid == *lastLUID && index == *lastIndex {
		return nil
	}
	*lastLUID = luid
	*lastIndex = index
	return nil
}

func monitorMTU(family winipcfg.AddressFamily, ourLUID winipcfg.LUID) ([]winipcfg.ChangeCallback, error) {
	var minMTU uint32
	if family == windows.AF_INET {
		minMTU = 576
	} else if family == windows.AF_INET6 {
		minMTU = 1280
	}
	lastLUID := winipcfg.LUID(0)
	lastIndex := ^uint32(0)
	lastMTU := uint32(0)
	doIt := func() error {
		err := findDefaultLUID(family, ourLUID, &lastLUID, &lastIndex)
		if err != nil {
			return err
		}
		mtu := uint32(0)
		if lastLUID != 0 {
			iface, err := lastLUID.Interface()
			if err != nil {
				return err
			}
			if iface.MTU > 0 {
				mtu = iface.MTU
			}
		}
		if mtu > 0 && lastMTU != mtu {
			iface, err := ourLUID.IPInterface(family)
			if err != nil {
				return err
			}
			iface.NLMTU = mtu - 80
			if iface.NLMTU < minMTU {
				iface.NLMTU = minMTU
			}
			err = iface.Set()
			if err != nil {
				return err
			}
			lastMTU = mtu
		}
		return nil
	}
	err := doIt()
	if err != nil {
		return nil, err
	}
	cbr, err := winipcfg.RegisterRouteChangeCallback(func(notificationType winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			doIt()
		}
	}, nil)
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, iface *winipcfg.MibIPInterfaceRow) {
		if notificationType == winipcfg.MibParameterNotification {
			doIt()
		}
	}, nil)
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}
