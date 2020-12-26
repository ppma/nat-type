package stun

type AttributeType uint

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

var attributeTypeNames = []string{
	"Undefined",
	"MappedAddress",
	"ResponseAddress",
	"ChangeRequest",
	"SourceAddress",
	"ChangedAddress",
	"Username",
	"Password",
	"MessageIntegrity",
	"ErrorCode",
	"UnknownAttribute",
	"ReflectedFrom",
	"XorMappedAddress",
	"XorOnly",
	"ServerName",
}

func (t AttributeType) String() string {
	if t <= ServerName {
		return attributeTypeNames[t]
	}
	return ""
}
