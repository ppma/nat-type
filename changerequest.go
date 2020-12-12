package stun

type Request struct {
	changIp    bool
	changePort bool
}

func (request Request) IsChangeIp() bool {
	return request.changIp
}

func (request Request) IsChangePort() bool {
	return request.changePort
}

func (request Request) setChangeIp(changeIp bool) {
	request.changIp = changeIp
}

func (request Request) setChangePort(changePort bool) {
	request.changePort = changePort
}

func NewStunChangeRequest(changeIp bool, changePort bool) *Request {
	return &Request{
		changIp:    changeIp,
		changePort: changePort,
	}

}
