package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Integer can be encoded depending on the represented value to save space.
// Variable length integers always precede an array/vector of a type of data
// that may vary in length. Varints MUST use the minimum possible number of
// bytes to encode a value.
//
// For example: the value 6 can be encoded with one byte therefore a varint that
// uses three bytes to encode the value 6 is malformed and the decoding task
// must be aborted.
type Varint uint64

// n integers can be stored using n+1 variable length integers where the first
// var_int equals n.
type VarintList []Varint

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

func (i *Varint) DeserializeReader(b io.Reader) error {
	var first [1]byte
	n, err := io.ReadAtLeast(b, first[:], 1)
	if n != 1 || err != nil {
		return DeserializeFailedError("first byte")
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

func (i VarintList) Serialize() []byte {
	var b bytes.Buffer
	b.Write(Varint(len(i)).Serialize()) // first is the count

	for _, x := range i {
		b.Write(x.Serialize())
	}

	return b.Bytes()
}

func (i *VarintList) DeserializeReader(b io.Reader) error {
	// get the length of the list
	var length Varint
	err := length.DeserializeReader(b)
	if err != nil {
		return DeserializeFailedError("length of list: " + err.Error())
	}

	*i = make(VarintList, uint64(length))

	var j uint64
	var x Varint

	for j = 0; j < uint64(length); j++ { // decode everything
		err := x.DeserializeReader(b)
		if err != nil {
			return DeserializeFailedError("varint at pos " + fmt.Sprint(j) +
				": " + err.Error())
		}
		(*i)[j] = x
	}

	return nil
}
