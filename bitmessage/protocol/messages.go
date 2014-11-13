package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"
)

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
		&messageHeader{MessageMagic, byteCommand, uint32(len(payload)), checksum})

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

	out, _ := CreateMessage("version", b.Bytes())
	return out
}

/*
Unpack a version message from the given byte data of the payload.
*/
func UnpackVersionPayload(raw []byte) (VersionMessage, error) {
	b := bytes.NewReader(raw)
	var msgFixed versionMessageFixed

	// Unpack struct
	err := binary.Read(b, binary.BigEndian, &msgFixed)
	if err != nil {
		return nil, errors.New("error unpacking version message: " + err.Error())
	}

	var msg VersionMessage
	// load initial values
	msg.versionMessageFixed = msgFixed

	// we've already read the header
	bytePos := uint64(unsafe.Sizeof(versionMessageFixed{}))

	var strLen uint64
	msg.UserAgent, strLen, err = DecodeVarstring(raw[bytePos:])
	bytePos += strLen // go on to next items
	if err != nil {
		return nil, errors.New("error unpacking user agent string: " + err.Error())
	}

	msg.Streams, _, err = DecodeVarintList(raw[bytePos:])
	if err != nil {
		return nil, errors.New("error unpacking advertised streams: " + err.Error())
	}

	return msg, nil
}

/*
Create a response to the version message (verack)
*/
func CreateVerackMessage() []byte {
	// error will always be 0 because verack is a valid, short command
	m, _ := CreateMessage("verack", nil)
	return m
}

/*
Create a message containing a list of known nodes
*/
func CreateAddrMessage(addresses []NetworkAddress) []byte {
	var b bytes.Buffer
	b.Write(EncodeVarint(uint64(len(addresses)))) // first item is the count

	for _, addr := range addresses { // write them all!
		binary.Write(&b, binary.BigEndian, &addr)
	}

	msg, _ := CreateMessage("addr", b.Bytes())
	return msg
}

/*
Unpack the payload containing a list of known nodes
*/
func UnpackAddrPayload(raw []byte) ([]NetworkAddress, error) {
	count, start, err := DecodeVarint(raw)
	if err != nil {
		return nil, errors.New("failed to decode number of addresses: " + err.Error())
	}

	addresses := make([]NetworkAddress, count) // init output

	b := bytes.NewReader(raw[start:]) // create reader
	var i uint64
	for i = 0; i < count; i++ { // set them up
		err = binary.Read(b, binary.BigEndian, &addresses[i])
		if err != nil {
			return nil, errors.New("error decoding addr at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return addresses, nil
}
