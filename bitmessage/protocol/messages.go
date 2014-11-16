package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Return the size of the message header
func MessageHeaderSize() int {
	return 24 // unsafe.Sizeof is not reliable, because of alignment, padding etc.
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

	if header.Magic != MessageMagic {
		err = errors.New("invalid message magic: " + fmt.Sprint(header.Magic))
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

func (addr *NetworkAddressShort) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP)
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddressShort) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)
	return addr.DeserializeReader(b)
}

func (addr *NetworkAddressShort) DeserializeReader(b io.Reader) error {
	addr.IP = net.IP(make([]byte, 16))

	err := binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, &addr.IP)
	if err != nil {
		return DeserializeFailedError("IP address")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return DeserializeFailedError("port")
	}

	return nil
}

func (addr *NetworkAddress) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Time)
	binary.Write(&b, binary.BigEndian, addr.Stream)
	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP)
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddress) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)
	return addr.DeserializeReader(b)
}

func (addr *NetworkAddress) DeserializeReader(b io.Reader) error {
	addr.IP = net.IP(make([]byte, 16))

	err := binary.Read(b, binary.BigEndian, &addr.Time)
	if err != nil {
		return DeserializeFailedError("time")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Stream)
	if err != nil {
		return DeserializeFailedError("stream")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, &addr.IP)
	if err != nil {
		return DeserializeFailedError("IP address")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return DeserializeFailedError("port")
	}

	return nil
}

/*
Create a version message based on the input parameters.
*/
func (msg *VersionMessage) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, msg.Version)
	binary.Write(&b, binary.BigEndian, msg.Services)
	binary.Write(&b, binary.BigEndian, msg.Timestamp)
	b.Write(msg.AddrRecv.Serialize())
	b.Write(msg.AddrFrom.Serialize())
	binary.Write(&b, binary.BigEndian, msg.Nonce)
	b.Write(msg.UserAgent.Serialize())
	b.Write(msg.Streams.Serialize())

	return CreateMessage("version", b.Bytes())
}

/*
Unpack a version message from the given byte data of the payload.
*/
func (msg *VersionMessage) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)
	return msg.DeserializeReader(b)
}

func (msg *VersionMessage) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, &msg.Version)
	if err != nil {
		return DeserializeFailedError("version")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Services)
	if err != nil {
		return DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Timestamp)
	if err != nil {
		return DeserializeFailedError("timestamp")
	}
	err = msg.AddrRecv.DeserializeReader(b)
	if err != nil {
		return DeserializeFailedError("addrrecv: " + err.Error())
	}
	err = msg.AddrFrom.DeserializeReader(b)
	if err != nil {
		return DeserializeFailedError("addrfrom: " + err.Error())
	}
	err = binary.Read(b, binary.BigEndian, &msg.Nonce)
	if err != nil {
		return DeserializeFailedError("nonce")
	}
	err = msg.UserAgent.DeserializeReader(b)
	if err != nil {
		return DeserializeFailedError("useragent")
	}
	err = msg.Streams.DeserializeReader(b)
	if err != nil {
		return DeserializeFailedError("streams")
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
	b.Write(Varint(len(msg.Addresses)).Serialize()) // first item is the count

	for _, addr := range msg.Addresses { // write them all!
		b.Write(addr.Serialize())
	}

	return CreateMessage("addr", b.Bytes())
}

/*
Unpack the payload containing a list of known nodes
*/
func (msg *AddrMessage) Deserialize(raw []byte) error {
	buf := bytes.NewReader(raw)
	return msg.DeserializeReader(buf)
}

func (msg *AddrMessage) DeserializeReader(buf io.Reader) error {
	var count Varint

	err := count.DeserializeReader(buf)
	if err != nil {
		return errors.New("failed to decode number of addresses: " + err.Error())
	}

	msg.Addresses = make([]NetworkAddress, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = binary.Read(buf, binary.BigEndian, &msg.Addresses[i])
		if err != nil {
			return errors.New("error decoding addr at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return nil
}
