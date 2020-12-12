package stun

type StunErrorCode struct {
	code       int
	reasonText string
}

func (errorCode StunErrorCode) GetCode() int {
	return errorCode.code
}

func (errorCode StunErrorCode) GetReasonText() string {
	return errorCode.reasonText
}

func (errorCode StunErrorCode) SetCode(code int) {
	errorCode.code = code
}

func (errorCode StunErrorCode) SetReasonText(reasonText string) {
	errorCode.reasonText = reasonText
}

func NewStunErrorCode(code int, reasonText string) *StunErrorCode {
	return &StunErrorCode{
		code:       code,
		reasonText: reasonText,
	}
}
