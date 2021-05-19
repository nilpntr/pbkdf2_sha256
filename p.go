package p

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
)

var (
	saltLength = 8
	iterations = 150000
	saltCharts = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func genSalt() string {
	var bytes = make([]byte, saltLength)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	for k, v := range bytes {
		bytes[k] = saltCharts[v%byte(len(saltCharts))]
	}
	return string(bytes)
}

func hashInternal(salt string, password string) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	return hex.EncodeToString(hash)
}

func GeneratePasswordHash(password string) string {
	salt := genSalt()
	hash := hashInternal(salt, password)
	return fmt.Sprintf("pbkdf2:sha256:%v$%s$%s", iterations, salt, hash)
}

func CheckPasswordHash(password string, hash string) bool {
	if strings.Count(hash, "$") < 2 {
		return false
	}
	pwdHashList := strings.Split(hash, "$")
	return pwdHashList[2] == hashInternal(pwdHashList[1], password)
}
