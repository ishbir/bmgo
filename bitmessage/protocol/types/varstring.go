package types

import (
	"bytes"
	"errors"
	"io"
)

// Variable length string can be stored using a variable length integer followed
// by the string itself.
type Varstring string

func (str Varstring) Serialize() []byte {
	var b bytes.Buffer
	strByte := []byte(string(str))
	b.Write(Varint(len(strByte)).Serialize())
	b.Write(strByte)
	return b.Bytes()
}

func (str *Varstring) DeserializeReader(buf io.Reader) error {
	var length Varint
	err := length.DeserializeReader(buf)
	if err != nil {
		return errors.New("length of varstring: " + err.Error())
	}

	temp := make([]byte, uint64(length))
	n, err := io.ReadAtLeast(buf, temp, int(length))
	if n != int(length) || err != nil { // we don't have enough bytes
		return NotEnoughBytesError(int(length))
	}

	*str = Varstring(temp)
	return nil
}
