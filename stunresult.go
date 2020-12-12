package stun

import "net"

type StunResult struct {
	ipAddr  net.IP
	natType NatType
}

func (result StunResult) GetNatType() NatType {
	return result.natType
}

func (result StunResult) GetIpAddr() net.IP {
	return result.ipAddr
}

func NewStunResult(natType NatType, ipAddr net.IP) *StunResult {
	return &StunResult{
		natType: natType,
		ipAddr:  ipAddr,
	}
}
