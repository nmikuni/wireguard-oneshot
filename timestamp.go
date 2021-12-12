package wireguard

import (
	"encoding/binary"
	"time"
)

type Timestamp [timestampSize]byte

const timestampSize = 12
const timestampBase = uint64(0x400000000000000a)
const whitenerMask = uint32(0x1000000 - 1)

func stamp(t time.Time) Timestamp {
	var tai64n Timestamp
	secs := timestampBase + uint64(t.Unix())
	nano := uint32(t.Nanosecond()) &^ whitenerMask
	binary.BigEndian.PutUint64(tai64n[:], secs)
	binary.BigEndian.PutUint32(tai64n[8:], nano)
	return tai64n
}