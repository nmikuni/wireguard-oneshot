package wireguard

import (
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type CookieGenerator struct {
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		cookie        [blake2s.Size128]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [blake2s.Size128]byte
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

const (
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

func (st *CookieGenerator) init(pk NoisePublicKey) {
	st.initMac1(pk)
	st.initMac2(pk)
	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) initMac1(pk NoisePublicKey) {
	hash, _ := blake2s.New256(nil)
	hash.Write([]byte(WGLabelMAC1))
	hash.Write(pk[:])
	hash.Sum(st.mac1.key[:0])
}

func (st *CookieGenerator) initMac2(pk NoisePublicKey) {
	hash, _ := blake2s.New256(nil)
	hash.Write([]byte(WGLabelCookie))
	hash.Write(pk[:])
	hash.Sum(st.mac2.encryptionKey[:0])
}

func (st *CookieGenerator) addMacs(msg []byte) {
	size := len(msg)

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	mac3, _ := blake2s.New128(st.mac1.key[:])
	mac3.Write(msg[:smac1])
	mac3.Sum(mac1[:0])

	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	mac4, _ := blake2s.New128(st.mac2.cookie[:])
	mac4.Write(msg[:smac2])
	mac4.Sum(mac2[:0])
}