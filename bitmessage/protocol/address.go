/*
Contains functions that ensure adherence to the Bitmessage v3 Protcol.
https://bitmessage.org/wiki/Protocol_specification
*/
package protocol

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"math/big"
	"strings"

	"github.com/ishbir/bitmessage-go/bitmessage/protocol/base58"
)

/*
Encode the address to a string that begins from BM- based on the hash.
Based on encodeAddress in addresses.py
Output format: [EncodeVarint(addressVersion) EncodeVarint(stream) ripe checksum]
*/
func EncodeAddress(version, stream uint64, ripe []byte) (string, error) {
	if len(ripe) != 20 {
		return "", errors.New("Length of given ripe hash was not 20")
	}

	switch version {
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
	binaryData.Write(EncodeVarint(version))
	binaryData.Write(EncodeVarint(stream))
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

/*
Decode the Bitmessage address to give the address version, stream number and data.
The assumption is that input address is properly formatted (according to specs).
Based on decodeAddress from addresses.py
*/
func DecodeAddress(address string) (version, stream uint64, ripe []byte, err error) {
	/*if address[:3] == "BM-" { // Clients should accept addresses without BM-
		address = address[3:]
	}*/
	/*
		decodeAddress says this but then UI checks for a missingbm status from
		decodeAddress, which doesn't exist. So I choose NOT to accept addresses without
		the initial BM-
	*/
	i, err := base58.DecodeToBig([]byte(address[3:]))
	if err != nil {
		err = errors.New("input address not valid base58 string")
		return
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
		err = errors.New("checksum failed")
		return
	}

	version, x, err := DecodeVarint(data[:9]) // get the version
	if err != nil {
		err = errors.New("failed to decode version of bitmessage address: " +
			err.Error())
		return
	}
	stream, y, err := DecodeVarint(data[x : x+9]) // exclude first x bytes, read next 9 bytes
	if err != nil {
		err = errors.New("failed to decode stream number of bitmessage address: " +
			err.Error())
		return
	}
	ripe = data[x+y : len(data)-4] // exclude bytes already read and checksum

	switch version {
	case 2:
		fallthrough
	case 3:
		if len(ripe) > 20 || len(ripe) < 18 { // improper size
			err = errors.New("the ripe length is invalid (>18 or <4)")
			return
		}
	case 4:
		if ripe[0] == 0x00 { // encoded ripe data MUST have null bytes removed from front
			err = errors.New("ripe data has null bytes in the beginning, not properly encoded")
			return
		}
		if len(ripe) > 20 || len(ripe) < 4 { // improper size
			err = errors.New("the ripe length is invalid (>20 or <4)")
			return
		}
	default:
		err = errors.New("unsupported address version")
		return
	}

	// prepend null bytes to make sure that the total ripe length is 20
	numPadding := 20 - len(ripe)
	ripe = append(make([]byte, numPadding), ripe...)
	err = nil
	return
}
