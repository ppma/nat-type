package stun

type AttributeType int

const (
	Undefined AttributeType = iota
	MappedAddress
	ResponseAddress
	ChangeRequest
	SourceAddress
	ChangedAddress
	Username
	Password
	MessageIntegrity
	ErrorCode
	UnknownAttribute
	ReflectedFrom
	XorMappedAddress
	XorOnly
	ServerName
)
