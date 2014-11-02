/*
Responsible for creation and management of user identities.
*/
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"

	"code.google.com/p/go.crypto/ripemd160"
	"github.com/conformal/btcec"
	"github.com/tv42/base58"
)

/*
The identity of the user, which includes public and private encryption and signing
keys along with the address and WIF format keys.
*/
type Identity struct {
	Address                 string
	PrivateSigningKeyWIF    string
	PrivateEncryptionKeyWIF string

	PublicSigningKey  *btcec.PublicKey
	PrivateSigningKey *btcec.PrivateKey

	PublicEncryptionKey  *btcec.PublicKey
	PrivateEncryptionKey *btcec.PrivateKey
}

/*
Create an Identity object from the Bitmessage address and Wallet Import Format
signing and encryption keys.
*/
func Load(address, signingKeyWif, encryptionKeyWif string) (*Identity, error) {

}

/*
Create an identity based on a random number generator, with the required number of
initial zeros in front (minimum 1). Each initial zero requires exponentially more
work. Corresponding to lines 79-99 of class_addressGenerator.py
*/
func NewRandom(requiredInitialZeros, version, stream uint64) (*Identity, error) {
	if requiredInitialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Declare appropriate variables
	var pubSigningKey, pubEncryptionKey *btcec.PublicKey
	var privSigningKey, privEncryptionKey *btcec.PrivateKey

	sha := sha512.New()
	ripemd := ripemd160.New()
	var hash []byte

	// Create signing keys
	privSigningKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, errors.New("creating private signing key failed: " + err.Error())
	}
	pubSigningKey = privSigningKey.PubKey()
	initialZeroBytes := make([]byte, requiredInitialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Generate encryption keys
		privEncryptionKey, err = btcec.NewPrivateKey(btcec.S256())
		if err != nil { // Some unknown error
			return nil, errors.New("creating private encryption key failed: " + err.Error())
		}
		pubEncryptionKey = privEncryptionKey.PubKey()

		sha.Reset()
		sha.Write(pubSigningKey.SerializeUncompressed())
		sha.Write(pubEncryptionKey.SerializeUncompressed())

		ripemd.Reset()
		ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
		hash = ripemd.Sum(nil)     // Get the hash

		// We found our hash!
		if bytes.Equal(hash[0:requiredInitialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}
	address, err := encodeAddress(version, stream, hash)
	if err != nil {
		return nil, errors.New("error encoding address: " + err.Error())
	}

	return &Identity{
		Address:                 address,
		PrivateSigningKeyWIF:    privkeyToWIF(privSigningKey),
		PrivateEncryptionKeyWIF: privkeyToWIF(privEncryptionKey),
		PublicEncryptionKey:     pubEncryptionKey,
		PublicSigningKey:        pubSigningKey,
		PrivateEncryptionKey:    privEncryptionKey,
		PrivateSigningKey:       privSigningKey,
	}, nil
}

/*
Create identities based on a deterministic passphrase. Corresponding to lines
*/
func NewDeterministic(passphrase string,
	requiredInitialZeros, version, stream uint64) (*Identity, error) {
	if requiredInitialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Declare appropriate variables
	var pubSigningKey, pubEncryptionKey *btcec.PublicKey
	var privSigningKey, privEncryptionKey *btcec.PrivateKey

	sha := sha512.New()
	ripemd := ripemd160.New()
	var hash, temp []byte

	// set the nonces
	var signingKeyNonce, encryptionKeyNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, requiredInitialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Create signing keys
		temp = append([]byte(passphrase), encodeVarint(signingKeyNonce)...)
		privSigningKey, pubSigningKey = btcec.PrivKeyFromBytes(btcec.S256(), temp[:32])

		// Create encryption keys
		temp = append([]byte(passphrase), encodeVarint(encryptionKeyNonce)...)
		privEncryptionKey, pubEncryptionKey = btcec.PrivKeyFromBytes(btcec.S256(), temp[:32])

		// Increment nonces
		signingKeyNonce += 2
		encryptionKeyNonce += 2

		sha.Reset()
		sha.Write(pubSigningKey.SerializeUncompressed())
		sha.Write(pubEncryptionKey.SerializeUncompressed())

		ripemd.Reset()
		ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
		hash = ripemd.Sum(nil)     // Get the hash

		// We found our hash!
		if bytes.Equal(hash[0:requiredInitialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}
	address, err := encodeAddress(version, stream, hash)
	if err != nil {
		return nil, errors.New("error encoding address: " + err.Error())
	}

	return &Identity{
		Address:                 address,
		PrivateSigningKeyWIF:    privkeyToWIF(privSigningKey),
		PrivateEncryptionKeyWIF: privkeyToWIF(privEncryptionKey),
		PublicEncryptionKey:     pubEncryptionKey,
		PublicSigningKey:        pubSigningKey,
		PrivateEncryptionKey:    privEncryptionKey,
		PrivateSigningKey:       privSigningKey,
	}, nil
}

/*
Converts the private key to wallet import format compatible key
Code taken from:
https://github.com/vsergeev/gimme-bitcoin-address/blob/master/gimme-bitcoin-address.go#L315
*/
func privkeyToWIF(prikey *btcec.PrivateKey) (wifstr string) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* Convert the private key to a byte sequence */
	prikey_bytes := prikey.D.Bytes()

	/* 1. Prepend 0x80 */
	wif_bytes := append([]byte{0x80}, prikey_bytes...)

	/* 2. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(wif_bytes)
	prikey_hash_1 := sha256_h.Sum(nil)

	/* 3. SHA256 Hash */
	sha256_h.Reset()
	sha256_h.Write(prikey_hash_1)
	prikey_hash_2 := sha256_h.Sum(nil)

	/* 4. Checksum is first 4 bytes of second hash */
	checksum := prikey_hash_2[0:4]

	/* 5. Append the checksum */
	wif_bytes = append(wif_bytes, checksum...)

	/* 6. Base58 the byte sequence */
	i := new(big.Int).SetBytes(wif_bytes)
	wifstr = string(base58.EncodeBig(nil, i))

	return wifstr
}

/*
Encode the address to a string that begins from BM- based on the hash.
Based on encodeAddress in addresses.py
*/
func encodeAddress(version, stream uint64, ripe []byte) (string, error) {
	// Do some sanity checks
	if version >= 2 && version <= 4 {
		if len(ripe) != 20 {
			return "", errors.New("Length of given ripe hash was not 20")
		}
	}
	if version >= 2 && version < 4 {
		if bytes.Equal(ripe[0:2], []byte{0x00, 0x00}) {
			ripe = ripe[2:]
		}
		if bytes.Equal(ripe[:1], []byte{0x00}) {
			ripe = ripe[1:]
		}
	}
	if version == 4 {
		ripe = bytes.TrimLeft(ripe, string([]byte{0x00}))
	}

	var binaryData bytes.Buffer
	binaryData.Write(encodeVarint(version))
	binaryData.Write(encodeVarint(stream))
	binaryData.Write(ripe)

	sha := sha512.New()
	sha.Write(binaryData.Bytes())
	currentHash := sha.Sum(nil) // calc hash
	sha.Write(currentHash)
	checksum := sha.Sum(nil)[0:4] // calc checksum from another round of SHA512

	totalBin := append(currentHash, checksum...)
	i := new(big.Int).SetBytes(totalBin)
	return "BM-" + string(base58.EncodeBig(nil, i)), nil // done
}

/*
Decode the Bitmessage address to give the address version, stream number and data.
*/
func decodeAddress(address string) (version, stream uint64, ripe []byte, error) {
	
}

/*
Encode the integer according to the protocol specifications. From addresses.py and
https://bitmessage.org/wiki/Protocol_specification
*/
func encodeVarint(x uint64) ([]byte) {
	buf := new(bytes.Buffer)
	if x < 253 {
		binary.Write(buf, binary.BigEndian, uint8(x))
	}
	if x >= 253 && x < 65536 {
		binary.Write(buf, binary.BigEndian, uint8(253))
		binary.Write(buf, binary.BigEndian, uint16(x))
	}
	if x >= 65536 && x < 4294967296 {
		binary.Write(buf, binary.BigEndian, uint8(254))
		binary.Write(buf, binary.BigEndian, uint32(x))
	}
	if x >= 4294967296 {
		binary.Write(buf, binary.BigEndian, uint8(255))
		binary.Write(buf, binary.BigEndian, uint64(x))
	}
	return buf.Bytes()
}

/*
Decode a varint (as specified in protocol specifications) to a uint64
*/
func decodeVarint([]byte buf) (uint64) {
	
}