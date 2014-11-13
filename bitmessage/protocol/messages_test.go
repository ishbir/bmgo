package protocol

import (
	"bytes"
	"testing"
)

type messageTestPair struct {
	command string
	payload []byte
	message []byte
}

var messageTests = []messageTestPair{ // generated using CreatePacket in shared.py
	{"hey", nil, []byte{233, 190, 180, 217, 104, 101, 121, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 207, 131, 225, 53}},
	{"message", []byte("Some huge test message"), []byte{233, 190, 180, 217, 109,
		101, 115, 115, 97, 103, 101, 0, 0, 0, 0, 0, 0, 0, 0, 22, 11, 150, 64, 0, 83,
		111, 109, 101, 32, 104, 117, 103, 101, 32, 116, 101, 115, 116, 32, 109, 101,
		115, 115, 97, 103, 101}},
	{"die", []byte("you don't deserve to live, my friend"), []byte{233, 190, 180,
		217, 100, 105, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 36, 240, 214, 59,
		80, 121, 111, 117, 32, 100, 111, 110, 39, 116, 32, 100, 101, 115, 101, 114,
		118, 101, 32, 116, 111, 32, 108, 105, 118, 101, 44, 32, 109, 121, 32, 102,
		114, 105, 101, 110, 100}},
}

func TestCreateMessage(t *testing.T) {
	for _, pair := range messageTests {
		msg, err := CreateMessage(pair.command, pair.payload)
		if err != nil {
			t.Error("got error:", err.Error())
		}
		if !bytes.Equal(msg, pair.message) {
			t.Error("for command", pair.command, "payload", pair.payload, "expected",
				pair.message, "got", msg)
		}
	}
}

func TestCreateVerackMessage(t *testing.T) {
	b := CreateVerackMessage()
	msgBytes := []byte{233, 190, 180, 217, 118, 101, 114, 97, 99, 107, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 207, 131, 225, 53} // CreatePacket('verack') in shared.py
	if !bytes.Equal(b, msgBytes) {
		t.Error("invalid verack message, got", b)
	}
}

func TestDecodeMessageHeader(t *testing.T) {
	for i, pair := range messageTests {
		command, length, checksum, err := DecodeMessageHeader(pair.message)
		if err != nil {
			t.Error("got error:", err.Error())
		}
		if pair.command != command {
			t.Error("for case", i+1, "expected command", pair.command, "got", command)
		}
		if len(pair.payload) != int(length) {
			t.Error("for case", i+1, "expected payload length", len(pair.payload),
				"got", length)
		}
		// checksum is from bytes 20-24
		if !bytes.Equal(pair.message[20:24], checksum[:]) {
			t.Error("for case", i+1, "expected checksum", pair.message[20:24],
				"got", checksum[:])
		}
	}
}

func TestMessageHeaderSize(t *testing.T) {
	if MessageHeaderSize() != 24 { // our struct definition was altered
		t.Error("message header struct altered, size not 24")
	}
}

func TestCreateVersionMessage(t *testing.T) {

}

func TestUnpackVersionPayload(t *testing.T) {

}

func TestCreateAddrMessage(t *testing.T) {

}

func TestUnpackAddrPayload(t *testing.T) {

}
