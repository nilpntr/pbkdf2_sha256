package p

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
	"strings"
)

var (
	saltLength = 8
	iterations = 15000
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

func hashInternal(salt string, password string, args ...int) string {
	_iterations := iterations
	if len(args) > 0 {
		_iterations = args[0]
	}
	hash := pbkdf2.Key([]byte(password), []byte(salt), _iterations, 32, sha256.New)
	return hex.EncodeToString(hash)
}

func GeneratePasswordHash(password string, args ...int) string {
	_iterations := iterations
	if len(args) > 0 {
		_iterations = args[0]
	}
	salt := genSalt()
	hash := hashInternal(salt, password)
	return fmt.Sprintf("pbkdf2:sha256:%v$%s$%s", _iterations, salt, hash)
}

func CheckPasswordHash(password string, hash string) bool {
	if strings.Count(hash, "$") < 2 {
		return false
	}
	pwdHashList := strings.Split(hash, "$")
	_split := strings.Split(pwdHashList[0], ":")
	return pwdHashList[2] == hashInternal(pwdHashList[1], password, parseIterations(_split[len(_split)-1]))
}

func parseIterations(val string) int {
	p, err := strconv.Atoi(val)
	if err != nil {
		return iterations
	}
	return p
}
