package stun

type AttributeType int

const (
	MappedAddress    AttributeType = 0x0001
	ResponseAddress  AttributeType = 0x0002
	ChangeRequest    AttributeType = 0x0003
	SourceAddress    AttributeType = 0x0004
	ChangedAddress   AttributeType = 0x0005
	Username         AttributeType = 0x0006
	Password         AttributeType = 0x0007
	MessageIntegrity AttributeType = 0x0008
	ErrorCode        AttributeType = 0x0009
	UnknownAttribute AttributeType = 0x000A
	ReflectedFrom    AttributeType = 0x000B
	XorMappedAddress AttributeType = 0x8020
	XorOnly          AttributeType = 0x0021
	ServerName       AttributeType = 0x8022
)
