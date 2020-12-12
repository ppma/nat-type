package stun

type StunMessageType int

const (
	// STUN message is binding request.
	BindingRequest StunMessageType = 0x0001

	// STUN message is binding request response.
	BindingResponse StunMessageType = 0x0101

	// STUN message is binding request error response.
	BindingErrorResponse StunMessageType = 0x0111

	// STUN message is "shared secret" request.
	SharedSecretRequest StunMessageType = 0x0002

	// STUN message is "shared secret" request response.
	SharedSecretResponse StunMessageType = 0x0102

	// STUN message is "shared secret" request error response.
	SharedSecretErrorResponse StunMessageType = 0x0112
)
