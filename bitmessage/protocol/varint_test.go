package protocol

import (
	"bytes"
	"reflect"
	"testing"
)

type varintTestPair struct {
	intValue  uint64
	byteValue []byte
}

// Test cases taken by running encodeVarint in addresses.py
var varintTests = []varintTestPair{
	{0, []byte{0x00}},
	{34, []byte{0x22}},
	{210, []byte{0xD2}},
	{253, []byte{0xFD, 0x00, 0xFD}},
	{553, []byte{0xFD, 0x02, 0x29}},
	{12654, []byte{0xFD, 0x31, 0x6E}},
	{65536, []byte{0xFE, 0x00, 0x01, 0x00, 0x00}},
	{8956216, []byte{0xFE, 0x00, 0x88, 0xA9, 0x38}},
	{4294967296, []byte{0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
	{6554896589946, []byte{0xFF, 0x00, 0x00, 0x05, 0xF6, 0x2E, 0x48, 0x64, 0x7A}},
}

// Checking for correct byte length
var varintInvalidLengthTests = []varintTestPair{
	{34, []byte{0xFD, 0x00, 0x22}},
	{210, []byte{0xFD, 0x00, 0xD2}},
	{553, []byte{0xFE, 0x00, 0x00, 0x02, 0x29}},
	{8956216, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xA9, 0x38}},
}

func TestEncodeVarint(t *testing.T) {
	for _, pair := range varintTests {
		v := EncodeVarint(pair.intValue)
		if !bytes.Equal(v, pair.byteValue) {
			t.Error(
				"For", pair.intValue,
				"expected", pair.byteValue,
				"got", v,
			)
		}
	}
}

func TestDecodeVarint(t *testing.T) {
	for _, pair := range varintTests {
		v, _, err := DecodeVarint(pair.byteValue)
		if err != nil {
			t.Error(
				"For", pair.byteValue,
				"got error:", err.Error(),
			)
			continue
		}
		if v != pair.intValue {
			t.Error(
				"For", pair.byteValue,
				"expected", pair.intValue,
				"got", v,
			)
		}
	}

	// Test for errors
	for _, pair := range varintInvalidLengthTests {
		_, _, err := DecodeVarint(pair.byteValue)
		if err, ok := err.(*VarintMinimumSizeError); !ok {
			t.Error("For", pair.byteValue,
				"expected VarintMinimumSizeError",
				"got error:", err.Error(),
			)
		}
	}

	_, _, err := DecodeVarint([]byte{})
	if err.Error() != "input byte slice cannot be nil" {
		t.Error(
			"For empty byte slice, expected error: input byte slice cannot be nil,",
			"got error:", err.Error(),
		)
	}

	// TODO: We haven't checked if less than ideal lengths are allowed or not
}

func TestEncodeVarintList(t *testing.T) {
	listTest := make([]uint64, len(varintTests))
	var b bytes.Buffer

	for i, pair := range varintTests {
		listTest[i] = pair.intValue
		b.Write(pair.byteValue)
	}

	buf := EncodeVarintList(listTest)

	// Start de-constructing
	length, bytepos, err := DecodeVarint(buf)

	if err != nil {
		t.Error("got error:", err.Error())
	}

	if int(length) != len(listTest) {
		t.Error(
			"expected list length", len(listTest),
			"got", length,
		)
	}

	if !bytes.Equal(b.Bytes(), buf[bytepos:]) {
		t.Error("items mismatch for list")
	}
}

func TestDecodeVarintList(t *testing.T) {
	listTest := make([]uint64, len(varintTests))

	var b bytes.Buffer
	b.Write(EncodeVarint(uint64(len(varintTests)))) // length of list

	for i, pair := range varintTests {
		listTest[i] = pair.intValue
		b.Write(pair.byteValue) // items
	}

	list, length, err := DecodeVarintList(b.Bytes())
	if err != nil {
		t.Error("got error:", err.Error())
	}
	if int(length) != b.Len() {
		t.Error("byte size mismatch")
	}
	if !reflect.DeepEqual(listTest, list) {
		t.Error("list items not equal")
	}
}
