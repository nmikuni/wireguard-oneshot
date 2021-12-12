package wireguard

import (
	"crypto/subtle"
	"encoding/base64"

	"golang.org/x/crypto/blake2s"
)

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	kdf1(dst, c[:], data)
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

func decodeBase64(dst []byte, src string) error {
	slice, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return err
	}

	copy(dst, slice)
	return nil
}