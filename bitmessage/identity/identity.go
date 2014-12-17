// Responsible for creation and management of user identities.
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/ishbir/elliptic"
	"golang.org/x/crypto/ripemd160"

	"github.com/ishbir/bmgo/bitmessage/protocol"
	"github.com/ishbir/bmgo/bitmessage/protocol/base58"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

var curve = elliptic.Secp256k1

// The identity of the user, which includes public and private encryption and
// signing keys.
type Identity struct {
	SigningKey    *elliptic.PrivateKey
	EncryptionKey *elliptic.PrivateKey
}

// Create an Identity object from the Bitmessage address and Wallet Import Format
// signing and encryption keys.
func Import(address, signingKeyWif, encryptionKeyWif string) (*Identity, error) {
	// (Try to) decode address
	_, err := protocol.DecodeAddress(address)
	if err != nil {
		return nil, err
	}
	// Don't need an address version check here because DecodeAddress handles it

	privSigningKey, err := wifToPrivkey(signingKeyWif)
	if err != nil {
		err = errors.New("signing key decode failed: " + err.Error())
		return nil, err
	}
	privEncryptionKey, err := wifToPrivkey(encryptionKeyWif)
	if err != nil {
		err = errors.New("encryption key decode failed: " + err.Error())
		return nil, err
	}

	return &Identity{
		SigningKey:    privSigningKey,
		EncryptionKey: privEncryptionKey,
	}, nil
}

func (id *Identity) Export(version, stream int) (address, signingKeyWif,
	encryptionKeyWif string, err error) {
	addr := &protocol.Address{
		Version: types.Varint(version),
		Stream:  types.Varint(stream),
		Ripe:    id.Hash(),
	}

	address, err = addr.Encode()
	if err != nil {
		err = errors.New("error encoding address: " + err.Error())
		return
	}
	signingKeyWif = privkeyToWIF(id.SigningKey)
	encryptionKeyWif = privkeyToWIF(id.EncryptionKey)
	return
}

func (id *Identity) Hash() []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(id.SigningKey.PublicKey.SerializeUncompressed())
	sha.Write(id.EncryptionKey.PublicKey.SerializeUncompressed())

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

// Create an identity based on a random number generator, with the required
// number of initial zeros in front (minimum 1). Each initial zero requires
// exponentially more work.
func NewRandom(initialZeros uint64) (*Identity, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Identity)

	var err error

	// Create signing keys
	id.SigningKey, err = elliptic.GeneratePrivateKey(curve)
	if err != nil {
		return nil, errors.New("creating private signing key failed: " + err.Error())
	}

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Generate encryption keys
		id.EncryptionKey, err = elliptic.GeneratePrivateKey(curve)
		if err != nil { // Some unknown error
			return nil, errors.New("creating private encryption key failed: " + err.Error())
		}

		// We found our hash!
		if bytes.Equal(id.Hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	return id, nil
}

// Create identities based on a deterministic passphrase.
func NewDeterministic(passphrase string, initialZeros uint64) (*Identity, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Identity)

	// temp variable
	var temp []byte
	var err error

	// set the nonces
	var signingKeyNonce, encryptionKeyNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	sha := sha512.New()

	// Go through loop to encryption keys with required num. of zeros
	for {
		// Create signing keys
		temp = append([]byte(passphrase),
			types.Varint(signingKeyNonce).Serialize()...)
		sha.Reset()
		sha.Write(temp)
		id.SigningKey, err = elliptic.PrivateKeyFromRawBytes(curve,
			sha.Sum(nil)[:32])
		if err != nil {
			return nil, errors.New("private key generation failed: " + err.Error())
		}

		// Create encryption keys
		temp = append([]byte(passphrase),
			types.Varint(encryptionKeyNonce).Serialize()...)
		sha.Reset()
		sha.Write(temp)
		id.EncryptionKey, err = elliptic.PrivateKeyFromRawBytes(curve,
			sha.Sum(nil)[:32])
		if err != nil {
			return nil, errors.New("private key generation failed: " + err.Error())
		}

		// Increment nonces
		signingKeyNonce += 2
		encryptionKeyNonce += 2

		// We found our hash!
		if bytes.Equal(id.Hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}
	return id, nil
}

/*
Decrypt data intended for the receipient.
*
func (id *Identity) DecryptData(data []byte) []byte {

}*/

// Converts the private key to wallet import format compatible key.
// Code taken from:
// https://github.com/vsergeev/gimme-bitcoin-address/blob/master/gimme-bitcoin-address.go#L315
func privkeyToWIF(prikey *elliptic.PrivateKey) (wifstr string) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	/* Create a new SHA256 context */
	sha256_h := sha256.New()

	/* Convert the private key to a byte sequence */
	prikey_bytes := prikey.Key

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

// Converts the wallet import format compatible key back to a private key
func wifToPrivkey(wifstr string) (prikey *elliptic.PrivateKey, err error) {
	/* See https://en.bitcoin.it/wiki/Wallet_import_format */

	// Convert the WIF key to a byte sequence
	i, err := base58.DecodeToBig([]byte(wifstr))
	if err != nil {
		err = errors.New("base58 decoding of the private key failed")
		return
	}
	wif_bytes := i.Bytes()

	// Preliminary check
	if wif_bytes[0] != 0x80 {
		err = errors.New("invalid key, first byte not 0x80")
		return
	}

	// Remove the initial 0x80 and the last 4 bytes of checksum
	prikey_bytes := wif_bytes[1 : len(wif_bytes)-4]

	// Start verifying the checksum of the key
	checksum := wif_bytes[len(wif_bytes)-4:]

	// Create a new SHA256 context
	sha256_h := sha256.New()

	// SHA256 Hash
	sha256_h.Reset()
	sha256_h.Write(wif_bytes[:len(wif_bytes)-4]) // exclude the checksum
	prikey_hash_1 := sha256_h.Sum(nil)

	// Second round of hash
	sha256_h.Reset()
	sha256_h.Write(prikey_hash_1)
	prikey_hash_2 := sha256_h.Sum(nil)

	// Check if checksum matches
	if !bytes.Equal(prikey_hash_2[0:4], checksum) {
		err = errors.New("invalid checksum on key")
		return
	}

	// All good, so create private key
	prikey, err = elliptic.PrivateKeyFromRawBytes(curve, prikey_bytes)
	if err != nil {
		err = errors.New("creating private key from bytes failed: " + err.Error())
		return
	}

	return prikey, nil
}
