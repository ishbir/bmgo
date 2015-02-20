package protocol

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/ishbir/bmgo/bitmessage/constants"
	"github.com/ishbir/bmgo/bitmessage/protocol/helpers"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

func init() {
	// seed the random number generator
	rand.Seed(time.Now().UnixNano())
}

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
		&messageHeader{constants.MessageMagic, byteCommand,
			uint32(len(payload)), checksum})

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

	if header.Magic != constants.MessageMagic {
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
		return types.DeserializeFailedError("number of addresses: " + err.Error())
	}

	msg.Addresses = make([]NetworkAddress, uint64(count)) // init output

	var i uint64
	for i = 0; i < uint64(count); i++ { // set them up
		err = msg.Addresses[i].DeserializeReader(b)
		if err != nil {
			return types.DeserializeFailedError("addr at pos " +
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
		return nil, types.DeserializeFailedError("number of inv items: " + err.Error())
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

// CalculateInvVector returns an InvVector for the corresponding message.
func CalculateInvVector(message []byte) InvVector {
	hash := helpers.CalculateDoubleSHA512Hash(message)
	var invVector InvVector
	copy(invVector[:], hash[:32])
	return invVector
}
