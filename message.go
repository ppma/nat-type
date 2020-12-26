package stun

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
)

type Message struct {
	transactionId   []byte
	messageType     MessageType
	magicCookie     int
	mappedAddress   *net.UDPAddr
	responseAddress *net.UDPAddr
	sourceAddress   *net.UDPAddr
	changedAddress  *net.UDPAddr
	changeRequest   *Request
	errorCode       *Code
}

func (message *Message) GetTransactionId() []byte {
	return message.transactionId
}

func (message *Message) GetType() MessageType {
	return message.messageType
}

func (message *Message) GetMagicCookie() int {
	return message.magicCookie
}

func (message *Message) GetMappedAddress() *net.UDPAddr {
	return message.mappedAddress
}

func (message *Message) GetResponseAddress() *net.UDPAddr {
	return message.responseAddress
}

func (message *Message) GetSourceAddress() *net.UDPAddr {
	return message.sourceAddress
}

func (message *Message) GetChangedAddress() *net.UDPAddr {
	return message.changedAddress
}

func (message *Message) GetChangeRequest() *Request {
	return message.changeRequest
}

func (message *Message) GetErrorCode() *Code {
	return message.errorCode
}

func NewStunMessage() *Message {
	message := &Message{
		transactionId: make([]byte, 12),
	}
	//rand.Read(message.transactionId)
	copy(message.transactionId, "0123456789ab")
	return message
}

func NewStunMessage1(messageType MessageType) *Message {
	message := NewStunMessage()
	message.messageType = messageType
	return message
}

func NewStunMessage2(messageType MessageType, changeRequest *Request) *Message {
	message := NewStunMessage1(messageType)
	message.changeRequest = changeRequest
	return message
}

// Parses STUN message from raw data packet.
func (message *Message) Parse(data []byte) error {

	if data == nil {
		return errors.New("data is null")
	}

	/* RFC 5389 6.
	    All STUN messages MUST start with a 20-byte header followed by zero
	    or more Attributes.  The STUN header contains a STUN message type,
	    magic cookie, transaction ID, and message length.
	     0                   1                   2                   3
	     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	     |0 0|     STUN Message Type     |         Message Length        |
	     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	     |                         Magic Cookie                          |
	     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	     |                                                               |
	     |                     Transaction ID (96 bits)                  |
	     |                                                               |
	     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   The message length is the count, in bytes, of the size of the
	   message, not including the 20 byte header.
	*/

	if len(data) < 20 {
		return errors.New("Invalid STUN message value !")
	}

	offset := 0

	//--- message header --------------------------------------------------

	// STUN Message Type
	messageType := MessageType(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	switch messageType {
	case BindingErrorResponse, BindingRequest, BindingResponse, SharedSecretErrorResponse, SharedSecretRequest, SharedSecretResponse:
		message.messageType = messageType
	default:
		return errors.New("Invalid STUN message type value !")
	}

	//        System.out.println("MessageType " + type);
	// Message Length
	//messageLength := int(data[offset])<<8 | int(data[offset+1])
	messageLength := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	//        System.out.println("messageLength " + messageLength);
	// Magic Cookie
	//message.magicCookie = int(data[offset])<<24 | int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])
	message.magicCookie = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// Transaction ID
	//message.transactionId = make([]byte, 12)
	//copy(message.transactionId, data[offset:])
	message.transactionId = data[offset : offset+12]
	offset += 12

	//--- Message attributes ---------------------------------------------
	for offset-20 < messageLength {
		//            System.out.println("offset " + offset);
		/* RFC 3489 11.2.
		    Each attribute is TLV encoded, with a 16 bit type, 16 bit length, and variable value:
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |         Type                  |            Length             |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                             Value                             ....
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/

		// Type
		attributeType := AttributeType(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		length := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		switch attributeType {
		case MappedAddress:
			message.mappedAddress = parseIPAddr(data, offset)
			offset += 8
		case ResponseAddress:
			// RESPONSE-ADDRESS
			message.responseAddress = parseIPAddr(data, offset)
			offset += 8
		case ChangeRequest:
			// CHANGE-REQUEST

			/*
			   The CHANGE-REQUEST attribute is used by the client to request that
			   the server use a different address and/or port when sending the
			   response.  The attribute is 32 bits long, although only two bits (A
			   and B) are used:
			    0                   1                   2                   3
			    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   The meaning of the flags is:
			   A: This is the "change IP" flag.  If true, it requests the server
			      to send the Binding Response with a different IP address than the
			      one the Binding Request was received on.
			   B: This is the "change port" flag.  If true, it requests the
			      server to send the Binding Response with a different port than the
			      one the Binding Request was received on.
			*/

			// Skip 3 bytes
			offset += 3

			message.changeRequest = NewStunChangeRequest((data[offset]&4) != 0, (data[offset]&2) != 0)
			offset++
		case SourceAddress:
			// SOURCE-ADDRESS
			message.sourceAddress = parseIPAddr(data, offset)
			offset += 8
		case ChangedAddress:
			// CHANGED-ADDRESS
			message.changedAddress = parseIPAddr(data, offset)
			offset += 8
		case MessageIntegrity:
			// MESSAGE-INTEGRITY
			offset += length
		case ErrorCode:

			// ERROR-CODE
			/* 3489 11.2.9.
			   0                   1                   2                   3
			   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |                   0                     |Class|     Number    |
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			   |      Reason Phrase (variable)                                ..
			   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
			*/

			code := int(data[offset+2]&0x7)*100 + int(data[offset+3])&0xFF

			message.errorCode = NewStunErrorCode(code, string(data[offset+4:offset+length]))
			offset += length
		case UnknownAttribute:
			// UNKNOWN-ATTRIBUTES
			offset += length
		default:
			offset += length
		}
	}
	return nil
}

func (message *Message) ToByteData() []byte {

	msg := make([]byte, 512)

	offset := 0

	msg[offset] = byte((message.messageType >> 8) & 0x3F)
	offset += 1
	msg[offset] = byte(message.messageType & 0xFF)
	offset += 1
	// Message Length (2 bytes) will be assigned at last.
	msg[offset] = 0
	offset += 1
	msg[offset] = 0
	offset += 1

	// Magic Cookie
	binary.BigEndian.PutUint32(msg[offset:], uint32(message.magicCookie))
	offset += 4

	copy(msg[offset:], message.transactionId)
	offset += 12

	if message.mappedAddress != nil {
		storeEndPoint(MappedAddress, message.mappedAddress, msg, offset)
		offset += 12
	} else if message.responseAddress != nil {
		storeEndPoint(ResponseAddress, message.responseAddress, msg, offset)
		offset += 12
	} else if message.changeRequest != nil {
		/*
		   The CHANGE-REQUEST attribute is used by the client to request that
		   the server use a different address and/or port when sending the
		   response.  The attribute is 32 bits long, although only two bits (A
		   and B) are used:
		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   The meaning of the flags is:
		   A: This is the "change IP" flag.  If true, it requests the server
		      to send the Binding Response with a different IP address than the
		      one the Binding Request was received on.
		   B: This is the "change port" flag.  If true, it requests the
		      server to send the Binding Response with a different port than the
		      one the Binding Request was received on.
		*/

		// Attribute header
		binary.BigEndian.PutUint16(msg[offset:], uint16(ChangeRequest))
		offset += 2
		msg[offset] = 0
		offset += 1
		msg[offset] = 4
		offset += 1

		msg[offset] = 0
		offset += 1
		msg[offset] = 0
		offset += 1
		msg[offset] = 0
		offset += 1
		msg[offset] = func() byte {
			var value1 byte
			var value2 byte
			if message.changeRequest.IsChangeIp() {
				value1 = 1
			} else {
				value1 = 0
			}
			value1 <<= 2
			if message.changeRequest.IsChangePort() {
				value2 = 1
			} else {
				value2 = 0
			}
			value2 <<= 1
			return value2 | value1
		}()
		offset += 1
	} else if message.sourceAddress != nil {
		storeEndPoint(SourceAddress, message.sourceAddress, msg, offset)
		offset += 12
	} else if message.changedAddress != nil {
		storeEndPoint(ChangedAddress, message.changedAddress, msg, offset)
		offset += 12
	} else
	//        else if (UserName != null)
	//        {
	//            var userBytes = Encoding.ASCII.GetBytes(UserName);
	//
	//            // Attribute header
	//            msg[offset] = (int)AttributeType.Username >> 8;
	//            msg[offset] = (int)AttributeType.Username & 0xFF;
	//            msg[offset] = (byte)(userBytes.Length >> 8);
	//            msg[offset] = (byte)(userBytes.Length & 0xFF);
	//
	//            Array.Copy(userBytes, 0, msg, offset, userBytes.Length);
	//            offset += userBytes.Length;
	//        }
	//        else if (Password != null)
	//        {
	//            var userBytes = Encoding.ASCII.GetBytes(UserName);
	//
	//            // Attribute header
	//            msg[offset] = (int)AttributeType.Password >> 8;
	//            msg[offset] = (int)AttributeType.Password & 0xFF;
	//            msg[offset] = (byte)(userBytes.Length >> 8);
	//            msg[offset] = (byte)(userBytes.Length & 0xFF);
	//
	//            Array.Copy(userBytes, 0, msg, offset, userBytes.Length);
	//            offset += userBytes.Length;
	//        }
	if message.errorCode != nil {
		/* 3489 11.2.9.
		   0                   1                   2                   3
		   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |                   0                     |Class|     Number    |
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |      Reason Phrase (variable)                                ..
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		*/

		reasonBytes := []byte(message.errorCode.GetReasonText())

		// Header
		msg[offset] = 0
		offset += 1
		msg[offset] = byte(ErrorCode)
		offset += 1
		msg[offset] = 0
		offset += 1
		msg[offset] = byte(4 + len(reasonBytes))
		offset += 1

		// Empty
		msg[offset] = 0
		offset += 1
		msg[offset] = 0
		offset += 1
		// Class
		msg[offset] = byte(math.Floor(float64(message.errorCode.GetCode()) / 100.0))
		offset += 1
		// Number
		msg[offset] = byte(message.errorCode.GetCode() & 0xFF)
		offset += 1
		// ReasonPhrase
		copy(msg[offset:], reasonBytes)
		offset += len(reasonBytes)
	}
	//        else if (ReflectedFrom != null)
	//        {
	//            storeEndPoint(AttributeType.ReflectedFrom, ReflectedFrom, msg, offset);
	//            offset += 12;
	//        }

	// Update Message Length. NOTE: 20 bytes header not included.
	binary.BigEndian.PutUint16(msg[2:], uint16(offset-20))

	return msg[:offset]

}

func storeEndPoint(attributeType AttributeType, endPoint *net.UDPAddr, message []byte, offset int) {
	/*
	   It consists of an eight bit address family, and a sixteen bit
	   port, followed by a fixed length value representing the IP address.
	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |x x x x x x x x|    Family     |           Port                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                             Address                           |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	// Header
	message[offset] = (byte)(attributeType >> 8)
	offset += 1
	message[offset] = (byte)(attributeType & 0xFF)
	offset += 1
	message[offset] = 0
	offset += 1
	message[offset] = 8
	offset += 1

	// Unused
	message[offset] = 0
	offset += 1
	// Family
	message[offset] = 0x01
	offset += 1
	// Port
	message[offset] = (byte)(endPoint.Port >> 8)
	offset += 1
	message[offset] = (byte)(endPoint.Port & 0xFF)
	offset += 1
	// Address
	ipBytes := endPoint.IP
	message[offset] = ipBytes[0]
	offset += 1
	message[offset] = ipBytes[1]
	offset += 1
	message[offset] = ipBytes[2]
	offset += 1
	message[offset] = ipBytes[3]
	offset += 1

	// offset总共加了12
}

func parseIPAddr(data []byte, offset int) *net.UDPAddr {
	/*
	   It consists of an eight bit address family, and a sixteen bit
	   port, followed by a fixed length value representing the IP address.
	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |x x x x x x x x|    Family     |           Port                |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                             Address                           |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	// Skip family
	offset++
	//        System.out.println("地址族 " + data[offset]);
	offset++
	// Port
	//        int port = data[offsset++] << 8 | data[offset++];
	//        int port = data[offset++] << 8 | data[offset++];

	//        System.out.println(conver2HexStr(data[offset++]));
	//        System.out.println(conver2HexStr(data[offset++]));

	port := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	//        String portStr = conver2HexStr(data[offset++]) + conver2HexStr(data[offset++]);
	//        int port = Integer.valueOf(portStr, 2);
	//        System.out.println("parseIPAddr port " + port);
	//        Long a = Integer.toUnsignedLong(port);
	//        System.out.println("parseIPAddr port " + a);

	// Address
	//        byte[] ip = new byte[4];
	//        System.out.println("ip[0] " + byte2Int(data[offset++]));
	//        System.out.println("ip[1] " + byte2Int(data[offset++]));
	//        System.out.println("ip[2] " + byte2Int(data[offset++]));
	//        System.out.println("ip[3] " + byte2Int(data[offset++]));
	//        ip[0] = data[offset++];
	//        ip[1] = data[offset++];
	//        ip[2] = data[offset++];
	//        ip[3] = data[offset];
	return &net.UDPAddr{
		IP:   data[offset : offset+4],
		Port: port,
		Zone: "",
	}

}
