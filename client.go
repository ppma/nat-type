package stun

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	UDP_SEND_COUNT      = 3
	TRANSACTION_TIMEOUT = 1000
)

func getAddr(stun string, local string) (*net.UDPAddr, *net.UDPAddr, error) {
	stunAddr, err := net.ResolveUDPAddr("udp", stun)
	if err != nil {
		return nil, nil, errors.New("stun is invalid")
	}
	localAddr, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return stunAddr, nil, errors.New("local is invalid")
	}
	return stunAddr, localAddr, nil
}

func Query(stun string, local string) (*Result, error) {
	stunAddr, localAddr, err := getAddr(stun, local)
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp", localAddr)
	return Query2(stunAddr, socket, localAddr)
}

func Query1(stun string, socket *net.UDPConn, local string) (*Result, error) {
	stunAddr, localAddr, err := getAddr(stun, local)
	if err != nil {
		return nil, err
	}
	return Query2(stunAddr, socket, localAddr)
}

func Query2(stunAddr *net.UDPAddr, socket *net.UDPConn, localAddr *net.UDPAddr) (*Result, error) {

	/*
	    In test I, the client sends a STUN Binding Request to a server, without any flags set in the
	    CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute. This causes the server
	    to send the response back to the address and port that the request came from.
	    In test II, the client sends a Binding Request with both the "change IP" and "change port" flags
	    from the CHANGE-REQUEST attribute set.
	    In test III, the client sends a Binding Request with only the "change port" flag set.
	                        +--------+
	                        |  Test  |
	                        |   I    |
	                        +--------+
	                             |
	                             |
	                             V
	                            /\              /\
	                         N /  \ Y          /  \ Y             +--------+
	          UDP     <-------/Resp\--------->/ IP \------------->|  Test  |
	          Blocked         \ ?  /          \Same/              |   II   |
	                           \  /            \? /               +--------+
	                            \/              \/                    |
	                                             | N                  |
	                                             |                    V
	                                             V                    /\
	                                         +--------+  Sym.      N /  \
	                                         |  Test  |  UDP    <---/Resp\
	                                         |   II   |  Firewall   \ ?  /
	                                         +--------+              \  /
	                                             |                    \/
	                                             V                     |Y
	                  /\                         /\                    |
	   Symmetric  N  /  \       +--------+   N  /  \                   V
	      NAT  <--- / IP \<-----|  Test  |<--- /Resp\               Open
	                \Same/      |   I    |     \ ?  /               Internet
	                 \? /       +--------+      \  /
	                  \/                         \/
	                  |                           |Y
	                  |                           |
	                  |                           V
	                  |                           Full
	                  |                           Cone
	                  V              /\
	              +--------+        /  \ Y
	              |  Test  |------>/Resp\---->Restricted
	              |   III  |       \ ?  /
	              +--------+        \  /
	                                 \/
	                                  |N
	                                  |       Port
	                                  +------>Restricted
	*/
	test1 := NewStunMessage1(BindingRequest)

	if test1Response, err := doTransaction(test1, socket, stunAddr, 100); err == nil {

		// UDP blocked.
		if test1Response == nil {
			return NewStunResult(UdpBlocked, nil), nil
		} else {
			// Test II
			test2 := NewStunMessage2(BindingRequest, NewStunChangeRequest(true, true))

			// No NAT.
			if localAddr.IP.Equal(test1Response.GetMappedAddress().IP) {
				// IP相同
				if test2Response, err := doTransaction(test2, socket, stunAddr, TRANSACTION_TIMEOUT); err == nil {
					// Open Internet.
					if test2Response != nil {
						return NewStunResult(OpenInternet, test1Response.GetMappedAddress().IP), nil
					} else // Symmetric UDP firewall.
					{
						return NewStunResult(SymmetricUdpFirewall, test1Response.GetMappedAddress().IP), nil
					}
				}
			} else // NAT
			{

				if test2Response, err := doTransaction(test2, socket, stunAddr, TRANSACTION_TIMEOUT); err == nil {

					// Full cone NAT.
					if test2Response != nil {
						return NewStunResult(FullCone, test1Response.GetMappedAddress().IP), nil
					} else {
						/*
						   If no response is received, it performs test I again, but this time, does so to
						   the address and port from the CHANGED-ADDRESS attribute from the response to test I.
						*/

						// Test I(II)
						//                        System.out.println("begin Test I(II)");
						test12 := NewStunMessage1(BindingRequest)
						if test12Response, err := doTransaction(test12, socket, test1Response.changedAddress, TRANSACTION_TIMEOUT); err == nil {
							if test12Response == nil {
								return nil, errors.New("STUN Test I(II) didn't get response !")
							} else {
								// Symmetric NAT
								if !test12Response.GetMappedAddress().IP.Equal(test1Response.GetMappedAddress().IP) && test12Response.GetMappedAddress().Port == test1Response.GetMappedAddress().Port {
									return NewStunResult(Symmetric, test1Response.GetMappedAddress().IP), nil
								} else {
									// Test III
									//                                System.out.println("begin Test III");
									test3 := NewStunMessage2(BindingRequest, NewStunChangeRequest(false, true))

									if test3Response, err := doTransaction(test3, socket, test1Response.mappedAddress, TRANSACTION_TIMEOUT); err == nil {
										// Restricted
										if test3Response != nil {
											return NewStunResult(RestrictedCone, test1Response.GetMappedAddress().IP), nil
										}
										// Port restricted else
										{
											return NewStunResult(PortRestrictedCone, test1Response.GetMappedAddress().IP), nil
										}
									}

								}
							}
						}

					}
				}
			}
		}
	}
	return NewStunResult(Unknown, nil), nil
}

// Does STUN transaction. Returns transaction response or null if transaction failed.
// Returns transaction response or null if transaction failed.
func doTransaction(request *Message, socket *net.UDPConn, remoteEndPoint net.Addr, timeout int) (*Message, error) {
	t1 := time.Now()
	requestBytes := request.ToByteData()
	if request.GetChangeRequest() != nil {
	}

	revResponse := false // 是否接收到数据的标志位
	receiveCount := 0
	receiveBuffer := make([]byte, 512)
	response := NewStunMessage()
	for receiveCount < UDP_SEND_COUNT {
		socket.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
		if _, err := socket.WriteTo(requestBytes, remoteEndPoint); err == nil {
			socket.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))
			if _, err := socket.Read(receiveBuffer); err == nil {
				// parse message
				response.Parse(receiveBuffer)
				// Check that transaction ID matches or not response what we want.
				if bytes.Equal(request.transactionId, response.transactionId) {
					revResponse = true
				} else {
					fmt.Println("TransactionId not match!")
					return nil, errors.New("TransactionId not match!")
				}
			}
		}
		receiveCount += 1
	}
	t2 := time.Now()
	fmt.Println("doTransaction time ", t2.Sub(t1))

	if revResponse {
		return response, nil
	} else {
		return nil, nil
	}

}
