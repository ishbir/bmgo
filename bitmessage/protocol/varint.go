package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

type Varint uint64
type VarintList []Varint

/*
Serialize the integer according to the protocol specifications.
https://bitmessage.org/wiki/Protocol_specification#Variable_length_integer
*/
func (i Varint) Serialize() []byte {
	buf := new(bytes.Buffer)
	x := uint64(i)

	if x < 253 {
		binary.Write(buf, binary.BigEndian, uint8(x))
	}
	if x >= 253 && x < 65536 {
		binary.Write(buf, binary.BigEndian, uint8(253))
		binary.Write(buf, binary.BigEndian, uint16(x))
	}
	if x >= 65536 && x < 4294967296 {
		binary.Write(buf, binary.BigEndian, uint8(254))
		binary.Write(buf, binary.BigEndian, uint32(x))
	}
	if x >= 4294967296 {
		binary.Write(buf, binary.BigEndian, uint8(255))
		binary.Write(buf, binary.BigEndian, uint64(x))
	}
	return buf.Bytes()
}

func (i *Varint) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)
	return i.DeserializeReader(b)
}

/*
Decode a varint to a uint64. Cannot supply less bytes than required to it. Excess
is fine. Returns: (number as uint64, number of bytes it consumes, error)
https://bitmessage.org/wiki/Protocol_specification#Variable_length_integer
*/
func (i *Varint) DeserializeReader(b io.Reader) error {
	var first [1]byte
	n, err := io.ReadAtLeast(b, first[:], 1)
	if n != 1 || err != nil {
		return errors.New("error reading first byte")
	}

	switch int(first[0]) {
	case 253: // 16 bit integer, encodes 253 to 65535
		var temp uint16
		err = binary.Read(b, binary.BigEndian, &temp)
		if err != nil {
			return NotEnoughBytesError(3) // no other reason for failure
		}
		if temp < 253 {
			return VarintMinimumSizeError{}
		}
		*i = Varint(temp)
		return nil

	case 254: // 32 bit integer, encodes 65536 to 4294967295
		var temp uint32
		err = binary.Read(b, binary.BigEndian, &temp)
		if err != nil {
			return NotEnoughBytesError(5) // no other reason for failure
		}
		if temp < 65536 {
			return VarintMinimumSizeError{}
		}
		*i = Varint(temp)
		return nil

	case 255: // 64 bit integer, encodes 4294967296 to 18446744073709551615
		var temp uint64
		err = binary.Read(b, binary.BigEndian, &temp)
		if err != nil {
			return NotEnoughBytesError(9) // no other reason for failure
		}
		if temp < 4294967296 {
			return VarintMinimumSizeError{}
		}
		*i = Varint(temp)
		return nil

	default: // 8 bit integer, encodes 0 to 252
		*i = Varint(first[0]) // just the first byte
		return nil
	}
}

/*
Encode a list of variable length integers.
https://bitmessage.org/wiki/Protocol_specification#Variable_length_list_of_integers
*/
func (i VarintList) Serialize() []byte {
	var b bytes.Buffer
	b.Write(Varint(len(i)).Serialize()) // first is the count

	for _, x := range i {
		b.Write(x.Serialize())
	}

	return b.Bytes()
}

func (i *VarintList) Deserialize(raw []byte) error {
	b := bytes.NewReader(raw)
	return i.DeserializeReader(b)
}

/*
Decode the list of variable length integers.
Returns: (numbers as []uint64, number of bytes they consume, error)
https://bitmessage.org/wiki/Protocol_specification#Variable_length_list_of_integers
*/
func (i *VarintList) DeserializeReader(b io.Reader) error {
	// get the length of the list
	var length Varint
	err := length.DeserializeReader(b)
	if err != nil {
		return errors.New("failed to decode length of list: " + err.Error())
	}

	*i = make(VarintList, uint64(length))

	var j uint64
	var x Varint

	for j = 0; j < uint64(length); j++ { // decode everything
		err := x.DeserializeReader(b)
		if err != nil {
			return errors.New("failed to decode varint at pos " + fmt.Sprint(j) +
				": " + err.Error())
		}
		(*i)[j] = x
	}

	return nil
}
