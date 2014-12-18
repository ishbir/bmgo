package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/ishbir/bmgo/bitmessage/protocol/objects"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// Return the size of the message header
func MessageHeaderSize() int {
	return 24 // unsafe.Sizeof is not reliable, because of alignment, padding etc.
}

// Create a message in the format required by the protocol specification.
// https://bitmessage.org/wiki/Protocol_specification#Message_structure
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

// Unpack the header of the received message.
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

// Verify the checksum on the payload of a message to see if it has been
// correctly received.
func VerifyMessageChecksum(payload []byte, checksum [4]byte) bool {
	t := sha512.Sum512(payload)
	return bytes.Equal(checksum[:], t[:4]) // check for equality
}

func (addr *NetworkAddressShort) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP.To16())
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddressShort) DeserializeReader(b io.Reader) error {
	ip := make([]byte, net.IPv6len)

	err := binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, ip)
	if err != nil {
		return types.DeserializeFailedError("IP address")
	}
	addr.IP = net.IP(ip)
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return types.DeserializeFailedError("port")
	}

	return nil
}

func (addr *NetworkAddress) Serialize() []byte {
	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, addr.Time)
	binary.Write(&b, binary.BigEndian, addr.Stream)
	binary.Write(&b, binary.BigEndian, addr.Services)
	binary.Write(&b, binary.BigEndian, addr.IP.To16())
	binary.Write(&b, binary.BigEndian, addr.Port)

	return b.Bytes()
}

func (addr *NetworkAddress) DeserializeReader(b io.Reader) error {
	ip := make([]byte, net.IPv6len)

	err := binary.Read(b, binary.BigEndian, &addr.Time)
	if err != nil {
		return types.DeserializeFailedError("time")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Stream)
	if err != nil {
		return types.DeserializeFailedError("stream")
	}
	err = binary.Read(b, binary.BigEndian, &addr.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, ip)
	if err != nil {
		return types.DeserializeFailedError("IP address")
	}
	addr.IP = net.IP(ip)
	err = binary.Read(b, binary.BigEndian, &addr.Port)
	if err != nil {
		return types.DeserializeFailedError("port")
	}

	return nil
}

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

func (msg *VersionMessage) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, &msg.Version)
	if err != nil {
		return types.DeserializeFailedError("version")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Services)
	if err != nil {
		return types.DeserializeFailedError("services")
	}
	err = binary.Read(b, binary.BigEndian, &msg.Timestamp)
	if err != nil {
		return types.DeserializeFailedError("timestamp")
	}
	err = msg.AddrRecv.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("addrrecv: " + err.Error())
	}
	err = msg.AddrFrom.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("addrfrom: " + err.Error())
	}
	err = binary.Read(b, binary.BigEndian, &msg.Nonce)
	if err != nil {
		return types.DeserializeFailedError("nonce")
	}
	err = msg.UserAgent.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("useragent: " + err.Error())
	}
	err = msg.Streams.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("streams: " + err.Error())
	}

	return nil
}

// Create a response to the version message (verack)
func CreateVerackMessage() []byte {
	return CreateMessage("verack", nil)
}

func (msg *AddrMessage) Serialize() []byte {
	var b bytes.Buffer
	b.Write(types.Varint(len(msg.Addresses)).Serialize()) // first item is count

	for _, addr := range msg.Addresses { // write them all!
		b.Write(addr.Serialize())
	}

	return CreateMessage("addr", b.Bytes())
}

func (msg *AddrMessage) DeserializeReader(b io.Reader) error {
	var count types.Varint

	err := count.DeserializeReader(b)
	if err != nil {
		return errors.New("failed to decode number of addresses: " + err.Error())
	}

	msg.Addresses = make([]NetworkAddress, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = msg.Addresses[i].DeserializeReader(b)
		if err != nil {
			return errors.New("error decoding addr at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return nil
}

func serializeInvVector(items []InvVector) []byte {
	var b bytes.Buffer
	b.Write(types.Varint(len(items)).Serialize()) // first item is the count

	for _, item := range items { // write them all!
		b.Write(item[:])
	}
	return b.Bytes()
}

func deserializeInvVector(b io.Reader) ([]InvVector, error) {
	var count types.Varint

	err := count.DeserializeReader(b)
	if err != nil {
		return nil, errors.New("failed to decode number of inv items: " + err.Error())
	}

	items := make([]InvVector, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = binary.Read(b, binary.BigEndian, &items[i])
		if err != nil {
			return nil, types.DeserializeFailedError("inv item at pos " +
				fmt.Sprint(i) + ": " + err.Error())
		}
	}

	return items, nil
}

func (msg *InvMessage) Serialize() []byte {
	return CreateMessage("inv", serializeInvVector(msg.Items))
}

func (msg *InvMessage) DeserializeReader(b io.Reader) error {
	var err error
	msg.Items, err = deserializeInvVector(b)
	return err
}

func (msg *GetdataMessage) Serialize() []byte {
	return CreateMessage("getdata", serializeInvVector(msg.Items))
}

func (msg *GetdataMessage) DeserializeReader(b io.Reader) error {
	var err error
	msg.Items, err = deserializeInvVector(b)
	return err
}

func (msg *ObjectMessage) Serialize() []byte {
	// Do pre-serialization stuff (adding signatures, doing POW, etc.)
	msg.preserialize()

	var b bytes.Buffer

	binary.Write(&b, binary.BigEndian, msg.Nonce)
	binary.Write(&b, binary.BigEndian, msg.ExpiresTime)
	binary.Write(&b, binary.BigEndian, msg.ObjectType)
	b.Write(msg.Version.Serialize())
	b.Write(msg.Stream.Serialize())
	b.Write(msg.Payload.Serialize())

	return CreateMessage("object", b.Bytes())
}

func (msg *ObjectMessage) DeserializeReader(b io.Reader) error {
	err := binary.Read(b, binary.BigEndian, &msg.Nonce)
	if err != nil {
		return types.DeserializeFailedError("nonce")
	}
	err = binary.Read(b, binary.BigEndian, &msg.ExpiresTime)
	if err != nil {
		return types.DeserializeFailedError("expiresTime")
	}
	err = binary.Read(b, binary.BigEndian, &msg.ObjectType)
	if err != nil {
		return types.DeserializeFailedError("objectType")
	}
	err = msg.Version.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("version: " + err.Error())
	}
	err = msg.Stream.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("stream: " + err.Error())
	}
	msg.setPayloadType() // set the Payload field
	err = msg.Payload.DeserializeReader(b)
	if err != nil {
		return types.DeserializeFailedError("payload" + err.Error())
	}

	return nil
}

func (msg *ObjectMessage) preserialize() {

}

// setPayloadType sets the Payload field of the ObjectMessage struct according
// to the value of Version and ObjectType.
func (msg *ObjectMessage) setPayloadType() {
	// default value
	msg.Payload = &objects.Unrecognized{}
	// used when the msg version is unknown
	corrupt := &objects.Corrupt{}

	switch msg.ObjectType {
	case 0: // getpubkey object
		switch msg.Version {
		case 2:
			fallthrough
		case 3:
			msg.Payload = &objects.GetpubkeyV3{}
		case 4:
			msg.Payload = &objects.GetpubkeyV4{}
		default:
			msg.Payload = corrupt
		}

	case 1: // pubkey object
		switch msg.Version {
		case 2:
			msg.Payload = &objects.PubkeyV2{}
		case 3:
			msg.Payload = &objects.PubkeyV3{}
		case 4:
			msg.Payload = &objects.PubkeyEncryptedV4{}
		default:
			msg.Payload = corrupt
		}

	case 2: // msg object
		if int(msg.Version) == 1 { // this has been fixed at 1
			msg.Payload = &objects.MsgEncrypted{}
		} else {
			msg.Payload = corrupt
		}

	case 3: // broadcast object
		switch msg.Version {
		case 4:
			msg.Payload = &objects.BroadcastEncryptedV4{}
		case 5:
			msg.Payload = &objects.BroadcastEncryptedV5{}
		default:
			msg.Payload = corrupt
		}
	}
}
