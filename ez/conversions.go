/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package ez

import (
	"encoding/hex"
	"encoding/json"
	"github.com/gofrs/uuid"
	"strconv"
	"time"
)

func UUIDFromString(s string) uuid.UUID {
	if s == "" {
		return uuid.Nil
	}
	u, err := uuid.FromString(s)
	if err != nil {
		panic("cannot get uuid from string " + s)
	}
	return u
}

func HexUUID(u uuid.UUID) string {
	buf := make([]byte, 32)
	hex.Encode(buf, u.Bytes())
	return string(buf)
}

func ShardUUID(u uuid.UUID, n int) int {
	if n > 4 || n <= 0 {
		panic("n must be between 1 and 4")
	}
	buf := make([]byte, 4)
	hex.Encode(buf, u[0:2])
	value, err := strconv.ParseInt(string(buf[:n]), 16, n*8)
	if err != nil {
		panic("cannot get shard for " + u.String())
	}
	return int(value)
}

func Bool2bytes(b bool) []byte {
	if b {
		return []byte("true")
	}
	return []byte("false")
}

func ParseBool(b string) bool {
	if b == "true" || b == "1" || b == "t" || b == "True" || b == "TRUE" {
		return true
	}
	return false
}

func Us2Time(us string) time.Time {
	u, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		panic("cannot get time from " + us)
	}
	return time.Unix(u/1000000, (u%1000000)*1000).UTC()
}

func Us2Int(us string) int64 {
	u, err := strconv.ParseInt(us, 10, 64)
	if err != nil {
		panic("cannot get time from " + us)
	}
	return u
}

func SerializeMap(m map[string]any) string {
	b, err := json.Marshal(m)
	if err != nil {
		return RandSeq(64)
	}
	return string(b)
}

func _() {
	_ = Us2Time
}
