package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/ishbir/base58"
	"github.com/ishbir/bmgo/bitmessage/protocol/helpers"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

// Represents a Bitmessage address
type Address struct {
	Version types.Varint
	Stream  types.Varint
	Ripe    [20]byte
}

// Encode the address to a string that begins from BM- based on the hash.
// Output: [Varint(addressVersion) Varint(stream) ripe checksum] where the
// Varints are serialized. Then this byte array is base58 encoded to produce our
// needed address.
func (addr *Address) Encode() (string, error) {
	ripe := addr.Ripe[:]

	switch addr.Version {
	case 2:
		fallthrough
	case 3:
		if ripe[0] == 0x00 {
			ripe = ripe[1:] // exclude first byte
			if ripe[0] == 0x00 {
				ripe = ripe[1:] // exclude second byte as well
			}
		}
	case 4:
		ripe = bytes.TrimLeft(ripe, "\x00")
	default:
		return "", errors.New("unsupported address version")
	}

	var binaryData bytes.Buffer
	binaryData.Write(addr.Version.Serialize())
	binaryData.Write(addr.Stream.Serialize())
	binaryData.Write(ripe)

	sha := sha512.New()
	sha.Write(binaryData.Bytes())
	currentHash := sha.Sum(nil) // calc hash
	sha.Reset()                 // reset hash
	sha.Write(currentHash)
	checksum := sha.Sum(nil)[:4] // calc checksum from another round of SHA512

	totalBin := append(binaryData.Bytes(), checksum...)

	i := new(big.Int).SetBytes(totalBin)
	return "BM-" + string(base58.EncodeBig(nil, i)), nil // done
}

// Decode the Bitmessage address. The assumption is that input address is
// properly formatted (according to specs).
func DecodeAddress(address string) (*Address, error) {
	// if address[:3] == "BM-" { // Clients should accept addresses without BM-
	//	address = address[3:]
	// }
	//
	// decodeAddress says this but then UI checks for a missingbm status from
	// decodeAddress, which doesn't exist. So I choose NOT to accept addresses
	// without the initial "BM-"

	i, err := base58.DecodeToBig([]byte(address[3:]))
	if err != nil {
		return nil, errors.New("input address not valid base58 string")
	}
	data := i.Bytes()

	hashData := data[:len(data)-4]
	checksum := data[len(data)-4:]

	// Take two rounds of SHA512 hashes
	sha := sha512.New()
	sha.Write(hashData)
	currentHash := sha.Sum(nil)
	sha.Reset()
	sha.Write(currentHash)

	if !bytes.Equal(checksum, sha.Sum(nil)[0:4]) {
		return nil, errors.New("checksum failed")
	}
	// create the address
	addr := new(Address)

	buf := bytes.NewReader(data)

	err = addr.Version.DeserializeReader(buf) // get the version
	if err != nil {
		return nil, types.DeserializeFailedError("version: " + err.Error())
	}

	err = addr.Stream.DeserializeReader(buf)
	if err != nil {
		return nil, types.DeserializeFailedError("stream: " + err.Error())
	}

	ripe := make([]byte, buf.Len()-4) // exclude bytes already read and checksum
	n, err := buf.Read(ripe)
	if n != len(ripe) || err != nil {
		return nil, types.DeserializeFailedError("ripe: " + err.Error())
	}

	switch addr.Version {
	case 2:
		fallthrough
	case 3:
		if len(ripe) > 20 || len(ripe) < 18 { // improper size
			return nil, errors.New("version 3, the ripe length is invalid")
		}
	case 4:
		// encoded ripe data MUST have null bytes removed from front
		if ripe[0] == 0x00 {
			return nil, errors.New("version 4, ripe data has null bytes in" +
				" the beginning, not properly encoded")
		}
		if len(ripe) > 20 || len(ripe) < 4 { // improper size
			return nil, errors.New("version 4, the ripe length is invalid")
		}
	default:
		return nil, errors.New("unsupported address version")
	}

	// prepend null bytes to make sure that the total ripe length is 20
	numPadding := 20 - len(ripe)
	ripe = append(make([]byte, numPadding), ripe...)
	copy(addr.Ripe[:], ripe)

	return addr, nil
}

// CalcDoubleHash calculates the double sha512 sum of the address, the first
// half of which is used as private encryption key for the public key object
// and the second half is used as a tag.
func (addr *Address) CalcDoubleHash() []byte {
	var b bytes.Buffer
	b.Write(addr.Version.Serialize())
	b.Write(addr.Stream.Serialize())
	b.Write(addr.Ripe[:])
	return helpers.CalculateDoubleSHA512Hash(b.Bytes())
}

func (addr *Address) Tag() [32]byte {
	var a [32]byte
	copy(a[:], addr.CalcDoubleHash()[32:])
	return a
}
