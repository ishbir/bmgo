// Responsible for creation and management of user identities.
package identity

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"

	"github.com/ishbir/base58"
	"github.com/ishbir/elliptic"
	"golang.org/x/crypto/ripemd160"

	"github.com/ishbir/bmgo/bitmessage/constants"
	"github.com/ishbir/bmgo/bitmessage/protocol/types"
)

var curve = elliptic.Secp256k1

// Own contains the identity of the user, which includes public and private
// encryption and signing keys, as well as the address that contains information
// about stream number and address version.
type Own struct {
	Address
	SigningKey         *elliptic.PrivateKey
	EncryptionKey      *elliptic.PrivateKey
	NonceTrialsPerByte types.Varint
	ExtraBytes         types.Varint
}

// Foreign contains the identity of the remote user, which includes the public
// encryption and signing keys, the address that contains information
// about stream number and address version and information determining the POW
// accepted by the identity.
type Foreign struct {
	Address
	SigningKey         *elliptic.PublicKey
	EncryptionKey      *elliptic.PublicKey
	NonceTrialsPerByte types.Varint
	ExtraBytes         types.Varint
}

// ToForeign turns the Own identity object into Foreign identity object that can
// then be used in broadcasts and wherever else is required.
func (id *Own) ToForeign() *Foreign {
	return &Foreign{
		Address:            id.Address,
		SigningKey:         &id.SigningKey.PublicKey,
		EncryptionKey:      &id.EncryptionKey.PublicKey,
		NonceTrialsPerByte: id.NonceTrialsPerByte,
		ExtraBytes:         id.ExtraBytes,
	}
}

// Import creates an Identity object from the Bitmessage address and Wallet
// Import Format (WIF) signing and encryption keys.
func Import(address, signingKeyWif, encryptionKeyWif string) (*Own, error) {
	// (Try to) decode address
	addr, err := DecodeAddress(address)
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

	return &Own{
		SigningKey:         privSigningKey,
		EncryptionKey:      privEncryptionKey,
		Address:            *addr,
		NonceTrialsPerByte: constants.POWDefaultNonceTrialsPerByte,
		ExtraBytes:         constants.POWDefaultExtraBytes,
	}, nil
}

// Export is responsible for exporting an identity to WIF and generating an
// address on the basis of the stored version and stream numbers.
func (id *Own) Export() (address, signingKeyWif, encryptionKeyWif string,
	err error) {

	copy(id.Address.Ripe[:], id.hash())
	address, err = id.Address.Encode()
	if err != nil {
		err = errors.New("error encoding address: " + err.Error())
		return
	}
	signingKeyWif = privkeyToWIF(id.SigningKey)
	encryptionKeyWif = privkeyToWIF(id.EncryptionKey)
	return
}

// CreateAddress populates the Address object within the identity based on the
// provided version and stream values and also generates the ripe.
func (id *Own) CreateAddress(version, stream types.Varint) {
	id.Address.Version = version
	id.Address.Stream = stream
	copy(id.Address.Ripe[:], id.hash())
}

// hash returns the ripemd160 hash used in the address
func (id *Own) hash() []byte {
	sha := sha512.New()
	ripemd := ripemd160.New()

	sha.Write(id.SigningKey.PublicKey.SerializeUncompressed())
	sha.Write(id.EncryptionKey.PublicKey.SerializeUncompressed())

	ripemd.Write(sha.Sum(nil)) // take ripemd160 of required elements
	return ripemd.Sum(nil)     // Get the hash
}

// Create an identity based on a random number generator, with the required
// number of initial zeros in front (minimum 1). Each initial zero requires
// exponentially more work. Note that this does not create an address.
func NewRandom(initialZeros int) (*Own, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Own)

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
		if bytes.Equal(id.hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	id.NonceTrialsPerByte = constants.POWDefaultNonceTrialsPerByte
	id.ExtraBytes = constants.POWDefaultExtraBytes

	return id, nil
}

// Create identities based on a deterministic passphrase. Note that this does
// not create an address.
func NewDeterministic(passphrase string, initialZeros uint64) (*Own, error) {
	if initialZeros < 1 { // Cannot take this
		return nil, errors.New("minimum 1 initial zero needed")
	}

	// Create identity struct
	var id = new(Own)

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
		if bytes.Equal(id.hash()[0:initialZeros], initialZeroBytes) {
			break // stop calculations
		}
	}

	id.NonceTrialsPerByte = constants.POWDefaultNonceTrialsPerByte
	id.ExtraBytes = constants.POWDefaultExtraBytes

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
