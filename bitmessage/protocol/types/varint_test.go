package types

import (
	"bytes"
	"fmt"
	"io/ioutil"
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

func TestSerializeVarint(t *testing.T) {
	for _, pair := range varintTests {
		v := Varint(pair.intValue).Serialize()
		if !bytes.Equal(v, pair.byteValue) {
			t.Error(
				"For", pair.intValue,
				"expected", pair.byteValue,
				"got", v,
			)
		}
	}
}

func TestDeserializeVarint(t *testing.T) {
	var v Varint

	for _, pair := range varintTests {
		err := v.DeserializeReader(bytes.NewReader(pair.byteValue))
		if err != nil {
			t.Error(
				"For", pair.byteValue,
				"got error:", err.Error(),
			)
			continue
		}
		if uint64(v) != pair.intValue {
			t.Error(
				"For", pair.byteValue,
				"expected", pair.intValue,
				"got", v,
			)
		}
	}

	// Test for errors
	for _, pair := range varintInvalidLengthTests {
		err := v.DeserializeReader(bytes.NewReader(pair.byteValue))
		if _, ok := err.(VarintMinimumSizeError); !ok {
			t.Error("For", pair.byteValue,
				"expected VarintMinimumSizeError",
				"got error:", err.Error(),
			)
		}
	}

	err := v.DeserializeReader(bytes.NewReader([]byte{}))
	if _, ok := err.(DeserializeFailedError); !ok {
		t.Error(
			"For empty byte slice, expected DeserializeFailedError,",
			"got error:", err.Error(),
		)
	}

	// TODO: We haven't checked if less than ideal lengths are allowed or not
}

func TestSerializeVarintList(t *testing.T) {
	listTest := make(VarintList, len(varintTests))
	var b bytes.Buffer

	for i, pair := range varintTests {
		listTest[i] = Varint(pair.intValue)
		b.Write(pair.byteValue)
	}

	byteData := VarintList(listTest).Serialize()

	// Start de-constructing
	buf := bytes.NewReader(byteData)

	var length Varint
	err := length.DeserializeReader(buf)

	if err != nil {
		t.Error("got error:", err.Error())
	}

	if int(length) != len(listTest) {
		t.Error(
			"expected list length", len(listTest),
			"got", length,
		)
	}

	res, _ := ioutil.ReadAll(buf)
	if !bytes.Equal(b.Bytes(), res) {
		t.Error("items mismatch for list")
	}
}

func TestDeserializeVarintList(t *testing.T) {
	listTest := make(VarintList, len(varintTests))

	var b bytes.Buffer
	b.Write(Varint(len(varintTests)).Serialize()) // length of list

	for i, pair := range varintTests {
		listTest[i] = Varint(pair.intValue)
		b.Write(pair.byteValue) // items
	}

	var list VarintList
	err := list.DeserializeReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Error("got error:", err.Error())
	}
	if !reflect.DeepEqual(listTest, list) {
		t.Error(fmt.Sprintf("list items not equal, listTest: %v, list: %v",
			listTest, list))
	}
}
