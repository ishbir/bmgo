package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
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
func CreateMessage(command string, payload []byte) []byte {
	if len(command) > 12 {
		panic("programming error: length of command cannot be greater than 12")
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

	return b.Bytes()
}

/*
Unpack the header of the received message.
*/
func UnpackMessageHeader(raw []byte) (command string, payloadLength uint32,
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
Verify the checksum on the payload of a message to see if it has been correctly
received.
*/
func VerifyMessageChecksum(payload []byte, checksum [4]byte) bool {
	t := sha512.Sum512(payload)
	return bytes.Equal(checksum[:], t[:4]) // check for equality
}

/*
Create a version message based on the input parameters.
*/
func (msg *VersionMessage) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, &msg.versionMessageFixed)
	b.Write(EncodeVarstring(msg.UserAgent))
	b.Write(EncodeVarintList(msg.Streams))

	return CreateMessage("version", b.Bytes())
}

/*
Unpack a version message from the given byte data of the payload.
*/
func (msg *VersionMessage) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)

	// Unpack struct
	err := binary.Read(b, binary.BigEndian, &msg.versionMessageFixed)
	if err != nil {
		return errors.New("error unpacking version message: " + err.Error())
	}

	// we've already read the header
	bytePos := uint64(unsafe.Sizeof(versionMessageFixed{}))

	var strLen uint64
	msg.UserAgent, strLen, err = DecodeVarstring(raw[bytePos:])
	bytePos += strLen // go on to next items
	if err != nil {
		return errors.New("error unpacking user agent string: " + err.Error())
	}

	msg.Streams, _, err = DecodeVarintList(raw[bytePos:])
	if err != nil {
		return errors.New("error unpacking advertised streams: " + err.Error())
	}

	return nil
}

/*
Create a response to the version message (verack)
*/
func CreateVerackMessage() []byte {
	return CreateMessage("verack", nil)
}

/*
Create a message containing a list of known nodes
*/
func (msg *AddrMessage) Serialize() []byte {
	var b bytes.Buffer
	b.Write(EncodeVarint(uint64(len(msg.Addresses)))) // first item is the count

	for _, addr := range msg.Addresses { // write them all!
		binary.Write(&b, binary.BigEndian, &addr)
	}

	return CreateMessage("addr", b.Bytes())
}

/*
Unpack the payload containing a list of known nodes
*/
func (msg *AddrMessage) Deserialize(raw []byte) error {
	count, start, err := DecodeVarint(raw)
	if err != nil {
		return errors.New("failed to decode number of addresses: " + err.Error())
	}

	msg.Addresses = make([]NetworkAddress, count) // init output

	b := bytes.NewReader(raw[start:]) // create reader
	var i uint64
	for i = 0; i < count; i++ { // set them up
		err = binary.Read(b, binary.BigEndian, &msg.Addresses[i])
		if err != nil {
			return errors.New("error decoding addr at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return nil
}
