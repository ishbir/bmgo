package protocol

import (
	"bytes"
	"fmt"
	"net"
	"reflect"
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
		msg := CreateMessage(pair.command, pair.payload)
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

func TestUnpackMessageHeader(t *testing.T) {
	for i, pair := range messageTests {
		command, length, checksum, err := UnpackMessageHeader(pair.message)
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

// Verify the checksum
func TestVerifyMessageChecksum(t *testing.T) {
	for i, pair := range messageTests {
		// checksum is from bytes 20-24
		var checksum [4]byte
		copy(checksum[:], pair.message[20:24])

		if !VerifyMessageChecksum(pair.message[24:], checksum) {
			t.Error("for case", i+1, "checksum verification failed")
		}
	}
}

func TestNetworkAddressShort(t *testing.T) {

}

func TestNetworkAddress(t *testing.T) {

}

func TestVersionMessage(t *testing.T) {
	var (
		time       int64  = 1416114153
		remoteHost        = net.ParseIP("192.168.0.1")
		remotePort uint16 = 8444
		localPort  uint16 = 8444
		// Ignored by the remote host. The actual remote connected IP used.
		localHost        = net.ParseIP("127.0.0.1")
		nonce     uint64 = 54562198651689
	)

	vMsg := VersionMessage{
		Version:   3,
		Services:  1,
		Timestamp: time,
		AddrRecv: NetworkAddressShort{
			Services: 1,
			IP:       remoteHost,
			Port:     remotePort,
		},
		AddrFrom: NetworkAddressShort{
			Services: 1,
			IP:       localHost,
			Port:     localPort, // local port
		},
		Nonce:     nonce, // Random value
		UserAgent: Varstring("/BM-Go:0.0.1/"),
		Streams:   VarintList{1},
	}

	testRes := vMsg.Serialize()
	res := []byte{233, 190, 180, 217, 118, 101, 114, 115, 105, 111, 110, 0, 0, 0,
		0, 0, 0, 0, 0, 96, 133, 59, 125, 112, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 84, 104, 47, 233, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 255, 255, 192, 168, 0, 1, 32, 252, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1, 32, 252, 0, 0, 49, 159,
		192, 120, 3, 41, 13, 47, 66, 77, 45, 71, 111, 58, 48, 46, 48, 46, 49, 47,
		1, 1} // encoded using Python

	if !bytes.Equal(testRes, res) {
		t.Error("error encoding version message")
	}

	var vMsgTest VersionMessage
	err := vMsgTest.Deserialize(res[MessageHeaderSize():]) // exclude the header
	if err != nil {
		t.Error("error decoding version message: " + err.Error())
	}

	if !reflect.DeepEqual(vMsg, vMsgTest) {
		t.Error("version message not equal to test")
		fmt.Printf("%+v\n", vMsgTest)
	}
}

func TestAddrMessage(t *testing.T) {
	aMsg := AddrMessage{
		Addresses: []NetworkAddress{
			NetworkAddress{
				Time:     7417498612,
				Stream:   16092,
				Services: 7122444285,
				IP:       net.ParseIP("28.53.71.21"),
				Port:     8444,
			},
			NetworkAddress{
				Time:     2178475345,
				Stream:   11001,
				Services: 24253795650,
				IP:       net.ParseIP("218.214.55.2"),
				Port:     8450,
			},
			NetworkAddress{
				Time:     8636460032,
				Stream:   17045,
				Services: 17446225454,
				IP:       net.ParseIP("45.56.1.58"),
				Port:     8002,
			},
			NetworkAddress{
				Time:     7330580752,
				Stream:   26304,
				Services: 23155342079,
				IP:       net.ParseIP("128.26.47.8"),
				Port:     8440,
			},
		},
	}

	testRes := aMsg.Serialize()
	res := []byte{233, 190, 180, 217, 97, 100, 100, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 153, 42, 82, 100, 89, 4, 0, 0, 0, 1, 186, 30, 11, 244, 0, 0, 62, 220,
		0, 0, 0, 1, 168, 135, 223, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 28,
		53, 71, 21, 32, 252, 0, 0, 0, 0, 129, 216, 229, 81, 0, 0, 42, 249, 0, 0, 0,
		5, 165, 163, 141, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 218, 214, 55,
		2, 33, 2, 0, 0, 0, 2, 2, 197, 236, 0, 0, 0, 66, 149, 0, 0, 0, 4, 15, 224,
		70, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 45, 56, 1, 58, 31, 66, 0,
		0, 0, 1, 180, 239, 201, 16, 0, 0, 102, 192, 0, 0, 0, 5, 100, 42, 122, 255,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 128, 26, 47, 8, 32, 248}

	if !bytes.Equal(testRes, res) {
		t.Error("error encoding addr message")
	}

	var aMsgTest AddrMessage
	err := aMsgTest.Deserialize(res[MessageHeaderSize():]) // exclude the header
	if err != nil {
		t.Error("error decoding addr message: " + err.Error())
	}

	if !reflect.DeepEqual(aMsg, aMsgTest) {
		t.Error("address message not equal to test")
		fmt.Printf("%+v\n", aMsgTest)
	}
}

func TestInvMessage(t *testing.T) {

}

func TestGetdataMessage(t *testing.T) {

}

func TestObjectMessage(t *testing.T) {

}
