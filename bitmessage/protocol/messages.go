package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"net"
	"unsafe"
)

type messageHeader struct {
	Magic         uint32   // 0xE9BEB4D9
	Command       [12]byte // string
	PayloadLength uint32
	Checksum      [4]byte
}

// Return the size of the message header
func MessageHeaderSize() uint64 {
	return uint64(unsafe.Sizeof(messageHeader{}))
}

/*
Create a message in the format required by the protocol specification.
https://bitmessage.org/wiki/Protocol_specification#Message_structure
*/
func CreateMessage(command string, payload []byte) ([]byte, error) {
	if len(command) > 12 {
		return nil, errors.New("length of command cannot be greater than 12")
	}
	var b bytes.Buffer
	// checksum is first 4 bytes of sha512 of payload
	var checksum [4]byte
	t := sha512.Sum512(payload)
	copy(checksum[:], t[:4])

	// convert to bytes an pad at same time
	var byteCommand [12]byte
	copy(byteCommand[:], command)

	// Write the header
	binary.Write(&b, binary.BigEndian,
		&messageHeader{0xE9BEB4D9, byteCommand, uint32(len(payload)), checksum})

	// Write the payload
	b.Write(payload)

	return b.Bytes(), nil
}

/*
Decodes the header of the received message.
*/
func DecodeMessageHeader(raw []byte) (command string, payloadLength uint32,
	checksum [4]byte, err error) {
	b := bytes.NewReader(raw)
	var header messageHeader

	// Unpack struct
	err = binary.Read(b, binary.BigEndian, &header)
	if err != nil {
		err = errors.New("error unpacking the header: " + err.Error())
		return
	}

	command = string(bytes.TrimRight(header.Command[:], "\x00")) // trim padding
	payloadLength = header.PayloadLength
	checksum = header.Checksum
	return
}

type networkAddressLong struct {
	Time   uint64 // 8 byte UNIX time
	Stream uint32
	networkAddressShort
}

// Only used for version messages
type networkAddressShort struct {
	Services uint64
	IP       net.IP
	Port     uint16
}

type versionMessageFixed struct {
	Version   uint32
	Services  uint64
	Timestamp int64 // UNIX time
	Addr_Recv networkAddressShort
	Addr_From networkAddressShort
	Nonce     uint64 // Random nonce
}

/*
Create a version message based on the input parameters.
*/
func CreateVersionMessage(serviceFlags uint64, nonce uint64, time int64,
	userAgent string, streams []uint64,
	localHost net.IP, localPort uint16, remoteHost net.IP, remotePort uint16) []byte {
	var b bytes.Buffer

	msg := versionMessageFixed{
		3, serviceFlags, time, networkAddressShort{
			serviceFlags, remoteHost, remotePort, // serviceFlags ignored by remote host
		}, networkAddressShort{
			serviceFlags, localHost, localPort, // IP address ignored by host, actual IP connected
		}, nonce,
	}

	binary.Write(&b, binary.BigEndian, &msg)
	b.Write(EncodeVarstring(userAgent))
	b.Write(EncodeVarintList(streams)) // only one stream
	return b.Bytes()
}

/*
Create a response to the version message (verack)
*/
func CreateVerackMessage() []byte {
	// error will always be 0 because verack is a valid, short command
	m, _ := CreateMessage("verack", nil)
	return m
}
