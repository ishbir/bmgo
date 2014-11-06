package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"unsafe"
)

type messageHeader struct {
	Magic         uint32   // 0xE9BEB4D9
	Command       [12]byte // string
	PayloadLength uint32
	Checksum      [4]byte
}

// Return the size of the message header
func MessageHeaderSize() uint8 {
	return unsafe.Sizeof(messageHeader{})
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
	err := binary.Write(&b, binary.BigEndian,
		&packetHeader{0xE9BEB4D9, byteCommand, uint32(len(payload)), checksum})
	if err != nil {
		return nil, errors.New("failed to pack packet header: " + err.Error())
	}
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
	var header packetHeader

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

type networkAddress struct {
	Time     uint64 // 8 byte time
	Stream   uint32
	Services uint64
	IP       [16]byte
	Port     uint16
}

type versionMessageFixed struct {
	Version   uint32
	Services  uint64
	Timestamp uint64
	Addr_Recv networkAddress
	Addr_From networkAddress
	Nonce     uint64 // Random nonce
}
