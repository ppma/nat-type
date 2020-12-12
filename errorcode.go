package stun

type Code struct {
	code       int
	reasonText string
}

func (errorCode Code) GetCode() int {
	return errorCode.code
}

func (errorCode Code) GetReasonText() string {
	return errorCode.reasonText
}

func (errorCode Code) SetCode(code int) {
	errorCode.code = code
}

func (errorCode Code) SetReasonText(reasonText string) {
	errorCode.reasonText = reasonText
}

func NewStunErrorCode(code int, reasonText string) *Code {
	return &Code{
		code:       code,
		reasonText: reasonText,
	}
}
