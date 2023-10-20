package sw

import (
	//rainbowC "pqc/rainbow/rainbowVClassic"
	rainbowC "pqc/rainbow/rainbowVClassic"
	"crypto/sha256"
	"errors"

	"github.com/hyperledger/fabric/bccsp"
)

const (
	//sigName        = "Dilithium2"
	sigName        = "Ranibow5Classic"
	PublicKeySize  = 1312
	PrivateKeySize = 2528
)

// rainbowPrivateKey implements a bccsp.Key interface
type rainbowPrivateKey struct {
	privKey *rainbowC.PrivateKey
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (k *rainbowPrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

// SKI returns the subject key identifier of this key.
func (k *rainbowPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}
	algBytes := []byte(sigName)

	// Hash public key with algorithm
	hash := sha256.New()
	hash.Write(append(k.privKey.Sk, algBytes...))
	return hash.Sum(nil)
}

func (k *rainbowPrivateKey) Symmetric() bool {
	return false
}

func (k *rainbowPrivateKey) Private() bool {
	return true
}

func (k *rainbowPrivateKey) PublicKey() (bccsp.Key, error) {
	return &rainbowPublicKey{&k.privKey.PublicKey}, nil
}

// rainbowPublicKey implements a bccsp.Key interface
type rainbowPublicKey struct {
	pubKey *rainbowC.PublicKey
}

func (k *rainbowPublicKey) Bytes() ([]byte, error) {
	return k.pubKey.Pk, nil
}

// SKI returns the subject key identifier of this key.
func (k *rainbowPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	algBytes := []byte(sigName)

	// Hash public key with algorithm
	hash := sha256.New()
	hash.Write(append(k.pubKey.Pk, algBytes...))
	return hash.Sum(nil)
} //TODO not used

func (k *rainbowPublicKey) Symmetric() bool {
	return false
}

func (k *rainbowPublicKey) Private() bool {
	return false
}

func (k *rainbowPublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
