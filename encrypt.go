package authcode

func Encrypt(str string, key string, expiry int64) (string, bool) {
	return authcode(str, key, true, expiry)
}