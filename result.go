package stun

import "net"

type Result struct {
	ipAddr  net.IP
	natType NatType
}

func (result Result) GetNatType() NatType {
	return result.natType
}

func (result Result) GetIpAddr() net.IP {
	return result.ipAddr
}

func NewStunResult(natType NatType, ipAddr net.IP) *Result {
	return &Result{
		natType: natType,
		ipAddr:  ipAddr,
	}
}
