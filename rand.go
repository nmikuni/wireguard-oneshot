package wireguard

import (
	"crypto/rand"
	"encoding/binary"
)

func randUint16() (uint16) {
	var integer [2]byte
	rand.Read(integer[:])
	return binary.LittleEndian.Uint16(integer[:])
}

func randUint32() (uint32) {
	var integer [4]byte
	rand.Read(integer[:])
	return binary.LittleEndian.Uint32(integer[:])
}