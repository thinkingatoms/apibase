/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package ez

import (
	"math/rand"
)

var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandSeq(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func StringSliceIndex(strs []string, s string) int {
	for i, str := range strs {
		if str == s {
			return i
		}
	}
	return -1
}
