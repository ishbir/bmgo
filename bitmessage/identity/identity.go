/*
Responsible for creation and management of user identities.
*/
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"

	"code.google.com/p/go.crypto/ripemd160"
	"github.com/conformal/btcec"

	"github.com/ishbir/bitmessage-go/bitmessage/protocol"
	"github.com/ishbir/bitmessage-go/bitmessage/protocol/base58"
)

/*
The identity of the user, which includes public and private encryption and signing
keys.
*/
type Identity struct {
	PublicSigningKey  *btcec.PublicKey
	PrivateSigningKey *btcec.PrivateKey

	PublicEncryptionKey  *btcec.PublicKey
	PrivateEncryptionKey *btcec.PrivateKey
}

/*
Create an Identity object from the Bitmessage address and Wallet Import Format
signing and encryption keys.
*/
func Import(address, signingKeyWif, encryptionKeyWif string) (*Identity, error) {
	// (Try to) decode address
	_, _, _, err := protocol.DecodeAddress(address)
	if err != nil {
		return nil, err
	}
	// We don't need an address version check here because DecodeAddress handles it

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
		PrivateSigningKey:    privSigningKey,
		PublicSigningKey:     privSigningKey.PubKey(),
		PrivateEncryptionKey: privEncryptionKey,
		PublicEncryptionKey:  privEncryptionKey.PubKey(),
	}, nil
}

func (id *Identity) Export(version, stream uint64) (address, signingKeyWif, encryptionKeyWif string, err error) {
	address, err = protocol.EncodeAddress(version, stream, id.Hash())
	if err != nil {
		err = errors.New("error encoding address: " + err.Error())
		return
	}
	signingKeyWif = privkeyToWIF(id.PrivateSigningKey)
	encryptionKeyWif = privkeyToWIF(id.PrivateEncryptionKey)
	return
}

func (id *Identity) Hash() []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(id.PublicSigningKey.SerializeUncompressed())
	sha.Write(id.PublicEncryptionKey.SerializeUncompressed())

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

/*
Create an identity based on a random number generator, with the required number of
initial zeros in front (minimum 1). Each initial zero requires exponentially more
work. Corresponding to lines 79-99 of class_addressGenerator.py
*/
func NewRandom(initialZeros uint64) (*Identity, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Identity)

	var err error

	// Create signing keys
	id.PrivateSigningKey, err = btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, errors.New("creating private signing key failed: " + err.Error())
	}
	id.PublicSigningKey = id.PrivateSigningKey.PubKey()
	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	// Go through loop to encryption keys with required num. of zeros
	for {
		// Generate encryption keys
		id.PrivateEncryptionKey, err = btcec.NewPrivateKey(btcec.S256())
		if err != nil { // Some unknown error
			return nil, errors.New("creating private encryption key failed: " + err.Error())
		}
		id.PublicEncryptionKey = id.PrivateEncryptionKey.PubKey()

		// We found our hash!
		if bytes.Equal(id.Hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	return id, nil
}

/*
Create identities based on a deterministic passphrase. Corresponding to lines
155-195
*/
func NewDeterministic(passphrase string, initialZeros uint64) (*Identity, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Identity)

	// temp variable
	var temp []byte

	// set the nonces
	var signingKeyNonce, encryptionKeyNonce uint64 = 0, 1

	initialZeroBytes := make([]byte, initialZeros) // used for comparison
	sha := sha512.New()

	// Go through loop to encryption keys with required num. of zeros
	for {
		// Create signing keys
		temp = append([]byte(passphrase), protocol.EncodeVarint(signingKeyNonce)...)
		sha.Reset()
		sha.Write(temp)
		id.PrivateSigningKey, id.PublicSigningKey = btcec.PrivKeyFromBytes(btcec.S256(), sha.Sum(nil)[:32])

		// Create encryption keys
		temp = append([]byte(passphrase), protocol.EncodeVarint(encryptionKeyNonce)...)
		sha.Reset()
		sha.Write(temp)
		id.PrivateEncryptionKey, id.PublicEncryptionKey = btcec.PrivKeyFromBytes(btcec.S256(), sha.Sum(nil)[:32])

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
Converts the wallet import format compatible key back to a private key
*/
func wifToPrivkey(wifstr string) (prikey *btcec.PrivateKey, err error) {
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
	prikey, _ = btcec.PrivKeyFromBytes(btcec.S256(), prikey_bytes)

	return prikey, nil
}
