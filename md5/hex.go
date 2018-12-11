package md5

import (
	"fmt"
	"crypto/md5"
)

func HexBB(str []byte) []byte {
	return []byte(fmt.Sprintf("%x", md5.Sum(str)))
}

func HexBS(str []byte) string {
	return fmt.Sprintf("%x", md5.Sum(str))
}

func HexSS(str string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(str)))
}

func HexSB(str string) []byte {
	return []byte(fmt.Sprintf("%x", md5.Sum([]byte(str))))
}