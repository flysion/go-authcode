package authcode

func Decrypt(str string, key string) (string, bool) {
	return authcode(str, key, false, 0)
}