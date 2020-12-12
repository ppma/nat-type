package stun

type MessageType int

const (
	// STUN message is binding request.
	BindingRequest MessageType = 0x0001

	// STUN message is binding request response.
	BindingResponse MessageType = 0x0101

	// STUN message is binding request error response.
	BindingErrorResponse MessageType = 0x0111

	// STUN message is "shared secret" request.
	SharedSecretRequest MessageType = 0x0002

	// STUN message is "shared secret" request response.
	SharedSecretResponse MessageType = 0x0102

	// STUN message is "shared secret" request error response.
	SharedSecretErrorResponse MessageType = 0x0112
)
