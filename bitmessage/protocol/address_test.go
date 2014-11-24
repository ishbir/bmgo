package protocol

import (
	"bytes"
	"testing"
)

type addressTestPair struct {
	address string
	version uint64
	stream  uint64
	ripe    []byte
}

var addressTests = []addressTestPair{
	{"BM-2cV9RshwouuVKWLBoyH5cghj3kMfw5G7BJ", 4, 1,
		[]byte{0, 118, 97, 129, 167, 56, 98, 210, 144, 213, 33, 56, 250, 180,
			161, 223, 177, 177, 12, 17}},
	{"BM-2DBXxtaBSV37DsHjN978mRiMbX5rdKNvJ6", 3, 1,
		[]byte{0, 214, 207, 196, 249, 74, 168, 190, 229, 104, 152, 91, 102, 80,
			2, 151, 51, 114, 110, 211}},
	{"BM-omXeTjutKWmYgQJjmoZjAG3u3NmaLEdZK", 2, 1,
		[]byte{0, 1, 171, 150, 119, 221, 37, 192, 14, 238, 192, 25, 255, 242,
			10, 139, 186, 251, 244, 218}},
	{"BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw", 3, 1,
		[]byte{0, 0, 124, 201, 186, 238, 181, 209, 250, 143, 180, 26, 106, 227,
			40, 178, 123, 229, 34, 85}},
	{"BM-2D7YvqcbRSv2j2zXmamTm4C3XGrTkZqdt3", 3, 1,
		[]byte{0, 21, 243, 247, 60, 104, 72, 169, 139, 195, 72, 196, 85, 228,
			167, 173, 177, 1, 165, 242}},
}

func TestEncodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		v, err := EncodeAddress(pair.version, pair.stream, pair.ripe)
		if err != nil {
			t.Error(
				"For", pair.address,
				"got error:", err.Error(),
			)
			continue
		}
		if v != pair.address {
			t.Error(
				"For", pair.version, pair.stream, pair.ripe,
				"expected", pair.address,
				"got", v,
			)
		}
	}
}

func TestDecodeAddress(t *testing.T) {
	for _, pair := range addressTests {
		version, stream, ripe, err := DecodeAddress(pair.address)
		if err != nil {
			t.Error(
				"For", pair.address,
				"got error:", err.Error(),
			)
			continue
		}
		if version != pair.version || stream != pair.stream || !bytes.Equal(ripe,
			pair.ripe) {
			t.Error(
				"For", pair.address,
				"expected", pair,
				"got", version, stream, ripe,
			)
		}
	}
}
