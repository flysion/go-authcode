package authcode

import (
	"encoding/base64"
	"strings"
	"strconv"
	"time"
	"os"
	"math/rand"
	"fmt"
	"github.com/a328496647/go-authcode/md5"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func base64Encode(str []byte) string {
	s := base64.StdEncoding.EncodeToString(str)
	s = strings.Replace(s, "+", "_", -1)
	s = strings.Replace(s, "/", "-", -1)
	s = strings.Replace(s, "=", "", -1)
	return s
}

func base64Decode(str string) ([]byte, error) {
	str = strings.Replace(str, "_", "+", -1)
	str = strings.Replace(str, "-", "/", -1)

	if len(str) % 4 > 0 {
		str = str + strings.Repeat("=", 4 - len(str) % 4)
	}

	s, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println(str, err)
		return nil, err
	}

	return s, nil
}

func uuid(salt...string) string {
	str := strings.Join(salt, "+") + strconv.Itoa(time.Now().Nanosecond()) + strconv.Itoa(rand.Int()) + strconv.Itoa(os.Getpid())
	return base64Encode(md5.HexSB(str))
}

func authcode(str string, key string, encrypt bool, expiry int64) (result string, ok bool) {
	sl := 4
	k := md5.HexSB(key)
	a := md5.HexBS(k[:16])
	b := md5.HexBS(k[16:])
	c := ""

	if encrypt {
		c = uuid(str)[0:sl]
	} else {
		c = str[0:sl]
	}

	kk := []byte(a + md5.HexSS(a + c))
	kl := len(kk)

	s := ""
	if !encrypt {
		if res, err := base64Decode(str[sl:]); err != nil {
			return "", false
		} else {
			s = string(res)
		}
	} else {
		if expiry > 0 {
			expiry = time.Now().Unix() + expiry
		} else {
			expiry = 0
		}

		s = fmt.Sprintf("%010d%s%s", expiry, md5.HexSB(str + b)[:16], str)
	}

	l := len(s)

	rk := make([]byte, 256)
	for i := 0; i < 256; i++ {
		rk[i] = byte(kk[i % kl])
	}

	box := make([]byte, 256)
	for i := 0; i < 256; i++ {
		box[i] = byte(i)
	}

	for i, j := 0, 0; i < 256; i++ {
		j = (j + int(box[i]) + int(rk[i])) % 256
		t := box[i]
		box[i] = box[j]
		box[j] = t
	}

	r := make([]byte, l)

	for a, j, i := 0, 0, 0; i < l; i++ {
		a = (a + 1) % 256
		j = (j + int(box[a])) % 256
		t := box[a]
		box[a] = box[j]
		box[j] = t

		r[i] = byte(s[i]) ^ (box[int(box[a] + box[j]) % 256])
	}

	if !encrypt {
		if expiry, err := strconv.ParseInt(string(r[0:10]), 10, 64); err == nil {
			if expiry > 0 && expiry < time.Now().Unix() {
				return "", false
			}
		} else {
			return "", false
		}

		if string(md5.HexSB(string(r[26:]) + b)[:16]) != string(r[10:26]) {
			return "", false
		}

		return string(r[26:]), true
	} else {
		return c + base64Encode(r), true
	}
}

