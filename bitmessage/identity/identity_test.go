package identity

import (
	"fmt"
	"testing"
)

type addressImportExportTest struct {
	address       string
	signingkey    string
	encryptionkey string
}

// Taken from https://bitmessage.ch/nuked/
var addressImportExportTests = []addressImportExportTest{
	{"BM-2cVLR8vzEu6QUjGkYAPHQQTUenPVC62f9B",
		"5JvnKKDF1vWDBnnjCPGMVVzsX2EinsXbiiJj7JUwZ9La4xJ9FWt",
		"5JTYsHKSzDx6636UatMppek1QzKYL8b5RLeZdayHoi1Qa5yJjJS"},
	{"BM-2cUuzjWQjDWyDfYHL9C93jcJYKW1B8JyS5",
		"5KWFoFRXVHraujrFWuXfNn1fnP4euVUq79QnMWE2QPv3kWhbjs1",
		"5JYcPUZuMjzgSHmsmcsQcpzFGqM7DdEVtxwNjRZg7KfUTqmepFh"},
}

// Need to figure out a way to improve testing for this.
func TestImportExport(t *testing.T) {
	for _, pair := range addressImportExportTests {
		v, err := Import(pair.address, pair.signingkey, pair.encryptionkey)
		if err != nil {
			t.Error(
				"for", pair.address,
				"got error:", err.Error(),
			)
		}

		address, signingkey, encryptionkey, err := v.Export()
		if err != nil {
			t.Error(
				"for", pair.address,
				"got error:", err,
			)
		}

		if address != pair.address || signingkey != pair.signingkey ||
			encryptionkey != pair.encryptionkey {
			t.Error(
				"for", pair.address,
				"got address:", address,
				"signingkey:", signingkey,
				"encryptionkey:", encryptionkey,
				"expected", pair.address, pair.signingkey, pair.encryptionkey,
			)
		}
	}
}

// Just check if generation of random address was successful
func TestNewRandom(t *testing.T) {
	// At least one zero in the beginning
	_, err := NewRandom(0)
	if err.Error() != "minimum 1 initial zero needed" {
		t.Error(
			"for requiredZeros=0 expected error \"minimum 1 initial zero needed\"",
			"got", err,
		)
	}
	v, err := NewRandom(1)
	if err != nil {
		t.Error(err)
		return
	}
	v.Address.Version = 4
	v.Address.Stream = 1
	address, signingkey, encryptionkey, err := v.Export()
	if err != nil {
		t.Error("export failed, error:", err)
		return
	}
	fmt.Println("Address:", address)
	fmt.Println("Signing Key:", signingkey)
	fmt.Println("Encryption Key:", encryptionkey)
}

type deterministicAddressTest struct {
	password string
	address  string
}

var deterministicAddressTests = []deterministicAddressTest{
	{"hello", "BM-2DB6AzjZvzM8NkS3HMYWMP9R1Rt778mhN8"},
	{"general", "BM-2DAV89w336ovy6BUJnfVRD5B9qipFbRgmr"},
	{"privacy", "BM-2D8hw9EzzMMJUYV44txMFqbtq3T7MCvyz7"},
	{"news", "BM-2D8ZrxtSU1jf7nnfvqVwRfCVh1Q8NW4td5"},
	{"PHP", "BM-2cUvgm9ScCJxig3cAkwNzD5iEw3rKJ7NeG"},
}

func TestNewDeterministic(t *testing.T) {
	for _, pair := range deterministicAddressTests {
		id, err := NewDeterministic(pair.password, 1)
		if err != nil {
			t.Error(
				"for", pair.password,
				"got error:", err.Error(),
			)
			continue
		}
		// Make sure to generate address of same version and stream
		addr, _ := DecodeAddress(pair.address)
		id.Address.Version = addr.Version
		id.Address.Stream = addr.Stream
		address, _, _, _ := id.Export()
		if address != pair.address {
			t.Error(
				"for", pair.password,
				"got", address,
				"expected", pair.address,
			)
		}
	}
}
