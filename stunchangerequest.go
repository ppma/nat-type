package stun

type StunChangeRequest struct {
	changIp    bool
	changePort bool
}

func (request StunChangeRequest) IsChangeIp() bool {
	return request.changIp
}

func (request StunChangeRequest) IsChangePort() bool {
	return request.changePort
}

func (request StunChangeRequest) setChangeIp(changeIp bool) {
	request.changIp = changeIp
}

func (request StunChangeRequest) setChangePort(changePort bool) {
	request.changePort = changePort
}

func NewStunChangeRequest(changeIp bool, changePort bool) *StunChangeRequest {
	return &StunChangeRequest{
		changIp:    changeIp,
		changePort: changePort,
	}

}
