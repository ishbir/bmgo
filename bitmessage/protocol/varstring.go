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
func DecodeVarstring(buf []byte) (string, error) {
	length, start, err := DecodeVarint(buf)
	if err != nil {
		return "", errors.New("failed to decode varstring: " + err.Error())
	}
	return string(buf[start : start+length]), nil // read the next 'length' bytes
}
