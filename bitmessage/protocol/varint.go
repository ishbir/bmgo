package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
)

/*
Encode the integer according to the protocol specifications. From addresses.py and
https://bitmessage.org/wiki/Protocol_specification
*/
func EncodeVarint(x uint64) []byte {
	buf := new(bytes.Buffer)
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

/*
Decode a varint (as specified in protocol specifications) to a uint64. Cannot
supply less bytes than required to it. Excess is fine. It will return:
(number as uint64, number of bytes it consumes, error)
*/
func DecodeVarint(b []byte) (uint64, uint64, error) {
	if len(b) < 1 {
		return 0, 0, errors.New("input byte slice cannot be nil")
	}

	switch uint8(b[0]) {
	case 253: // 16 bit integer, encodes 253 to 65535
		if len(b) < 3 {
			return 0, 0, errors.New("for 16 bit int, min length must be 3 bytes")
		}
		var temp uint16
		buf := bytes.NewReader(b[1:3])
		binary.Read(buf, binary.BigEndian, &temp)

		if temp < 253 {
			return 0, 0, errors.New("varint not encoded with minimum size")
		}
		return uint64(temp), 3, nil

	case 254: // 32 bit integer, encodes 65536 to 4294967295
		if len(b) < 5 {
			return 0, 0, errors.New("for 32 bit int, min length must be 5 bytes")
		}
		var temp uint32
		buf := bytes.NewReader(b[1:5])
		binary.Read(buf, binary.BigEndian, &temp)

		if temp < 65536 {
			return 0, 0, errors.New("varint not encoded with minimum size")
		}
		return uint64(temp), 5, nil

	case 255: // 64 bit integer, encodes 4294967296 to 18446744073709551615
		if len(b) < 9 {
			return 0, 0, errors.New("for 64 bit int, min length must be 9 bytes")
		}
		var temp uint64
		buf := bytes.NewReader(b[1:9])
		binary.Read(buf, binary.BigEndian, &temp)

		if temp < 4294967296 {
			return 0, 0, errors.New("varint not encoded with minimum size")
		}
		return uint64(temp), 9, nil

	default: // 8 bit integer, encodes 0 to 252
		return uint64(b[0]), 1, nil // just the first byte
	}
}
