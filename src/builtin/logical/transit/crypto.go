package transit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Supported key types.
const (
	typeAES256GCM96 = "aes256-gcm96"
	typeChaCha20    = "chacha20-poly1305"
	typeED25519     = "ed25519"
	typeECDSAP256   = "ecdsa-p256"
)

func isSymmetric(t string) bool  { return t == typeAES256GCM96 || t == typeChaCha20 }
func isAsymmetric(t string) bool { return t == typeED25519 || t == typeECDSAP256 }

func supportedType(t string) bool { return isSymmetric(t) || isAsymmetric(t) }

// newVersionMaterial generates the key material for a new version of typ:
// a symmetric key or an asymmetric private key (plus its public key), and a
// per-version HMAC key used by the hmac endpoint.
func newVersionMaterial(typ string) (key, hmacKey, pub []byte, err error) {
	hmacKey = make([]byte, 32)
	if _, err = rand.Read(hmacKey); err != nil {
		return nil, nil, nil, err
	}
	switch typ {
	case typeAES256GCM96, typeChaCha20:
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, nil, nil, err
		}
	case typeED25519:
		pubKey, priv, gerr := ed25519.GenerateKey(rand.Reader)
		if gerr != nil {
			return nil, nil, nil, gerr
		}
		key = priv.Seed()
		pub = pubKey
	case typeECDSAP256:
		pk, gerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if gerr != nil {
			return nil, nil, nil, gerr
		}
		if key, gerr = pk.Bytes(); gerr != nil {
			return nil, nil, nil, gerr
		}
		if pub, gerr = pk.PublicKey.Bytes(); gerr != nil {
			return nil, nil, nil, gerr
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type %q", typ)
	}
	return key, hmacKey, pub, nil
}

// aeadFor returns an AEAD for a symmetric key type.
func aeadFor(typ string, key []byte) (cipher.AEAD, error) {
	switch typ {
	case typeAES256GCM96:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case typeChaCha20:
		return chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("key type %q does not support encryption", typ)
	}
}

// symEncrypt seals plaintext and returns nonce||ciphertext.
func symEncrypt(typ string, key, plaintext []byte) ([]byte, error) {
	aead, err := aeadFor(typ, key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, nil)...), nil
}

// symDecrypt opens a nonce||ciphertext blob.
func symDecrypt(typ string, key, blob []byte) ([]byte, error) {
	aead, err := aeadFor(typ, key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return aead.Open(nil, blob[:ns], blob[ns:], nil)
}

// signInput signs input with an asymmetric private key.
func signInput(typ string, key, input []byte) ([]byte, error) {
	switch typ {
	case typeED25519:
		return ed25519.Sign(ed25519.NewKeyFromSeed(key), input), nil
	case typeECDSAP256:
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), key)
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(input)
		return ecdsa.SignASN1(rand.Reader, priv, h[:])
	default:
		return nil, fmt.Errorf("key type %q does not support signing", typ)
	}
}

// verifySig verifies a signature over input using a public key.
func verifySig(typ string, pub, input, sig []byte) bool {
	switch typ {
	case typeED25519:
		return ed25519.Verify(ed25519.PublicKey(pub), input, sig)
	case typeECDSAP256:
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pub)
		if err != nil {
			return false
		}
		h := sha256.Sum256(input)
		return ecdsa.VerifyASN1(pk, h[:], sig)
	default:
		return false
	}
}

func hmacSum(hmacKey, input []byte) []byte {
	m := hmac.New(sha256.New, hmacKey)
	m.Write(input)
	return m.Sum(nil)
}

// hmacEqual compares two HMACs in constant time.
func hmacEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// randRead fills b with cryptographically-random bytes.
func randRead(b []byte) (int, error) { return rand.Read(b) }
