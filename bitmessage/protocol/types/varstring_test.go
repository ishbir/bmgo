package types

import (
	"bytes"
	"testing"
)

type varstringTestPair struct {
	strValue  string
	byteValue []byte
}

// Test cases taken by running encodeVarint in addresses.py
var varstringTests = []varstringTestPair{
	{"", []byte{0x00}},
	{"A", []byte{0x01, 0x41}},
	{"a", []byte{0x01, 0x61}},
	{"Hey there, how are you?", []byte{0x17, 0x48, 0x65, 0x79, 0x20, 0x74, 0x68,
		0x65, 0x72, 0x65, 0x2c, 0x20, 0x68, 0x6f, 0x77, 0x20, 0x61, 0x72, 0x65,
		0x20, 0x79, 0x6f, 0x75, 0x3f}},
}

func TestSerializeVarstring(t *testing.T) {
	for _, pair := range varstringTests {
		v := Varstring(pair.strValue).Serialize()
		if !bytes.Equal(v, pair.byteValue) {
			t.Error(
				"For", pair.strValue,
				"expected", pair.byteValue,
				"got", v,
			)
		}
	}
}

func TestDeserializeVarstring(t *testing.T) {
	var v Varstring

	for _, pair := range varstringTests {
		err := v.DeserializeReader(bytes.NewReader(pair.byteValue))
		if err != nil {
			t.Error(
				"For", pair.byteValue,
				"got error:", err.Error(),
			)
			continue
		}
		if string(v) != pair.strValue {
			t.Error(
				"For", pair.byteValue,
				"expected", pair.strValue,
				"got", v,
			)
		}
	}

	// less bytes than are required
	err := v.DeserializeReader(bytes.NewReader([]byte{0x80, 0x65, 0x35, 0x48}))
	if err, ok := err.(NotEnoughBytesError); !ok {
		t.Error(
			"Expected NotEnoughBytesError, got", err.Error(),
		)
	}
}
