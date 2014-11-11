package protocol

import (
	"bytes"
	"errors"
)

/*
Encode a variable length string according to protocol specifications.
*/
func EncodeVarstring(str string) []byte {
	var b bytes.Buffer
	strByte := []byte(str)
	b.Write(EncodeVarint(uint64(len(strByte))))
	b.Write(strByte)
	return b.Bytes()
}

/*
Decodes the variable length string from a binary buffer to a string.
*/
func DecodeVarstring(buf []byte) (string, uint64, error) {
	length, start, err := DecodeVarint(buf)
	if err != nil {
		return "", 0, errors.New("failed to decode varstring: " + err.Error())
	}
	// check if we have enough bytes
	if len(buf) < int(start+length) {
		return "", start + length, &NotEnoughBytesError{int(start + length), len(buf)}
	}

	// read the next 'length' bytes
	return string(buf[start : start+length]), start + length, nil
}
