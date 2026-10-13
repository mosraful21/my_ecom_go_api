package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"
)

func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid random byte length")
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func RandomHex(n int) (string, error) {
	b, err := RandomBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func RandomToken() (string, error) {
	return RandomHex(64)
}

func RandomRecoverySessionID() (string, error) {
	return RandomHex(64)
}

func RandomOTP(length int) (string, error) {
	if length <= 0 {
		return "", errors.New("invalid otp length")
	}

	var result strings.Builder
	for i := 0; i < length; i++ {
		n, err := rand.Int(
			rand.Reader,
			big.NewInt(10),
		)
		if err != nil {
			return "", err
		}
		result.WriteByte(byte('0' + n.Int64()))
	}
	return result.String(), nil
}

func HMACSHA256(secret, value string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func HashOTP(secret, sessionID, otp string) string {
	value := "otp:" + sessionID + ":" + otp
	return HMACSHA256(secret, value)
}

func HashResetToken(secret, sessionID, token string) string {
	value := "reset:" + sessionID + ":" + token
	return HMACSHA256(secret, value)
}

func HashPhone(secret, phone string) string {
	return HMACSHA256(secret, "phone:"+phone)
}

func ConstantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func SetRecoveryCookie(w http.ResponseWriter, name string, sessionID string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func ClearRecoveryCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func GetRecoveryCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}
	if cookie.Value == "" {
		return "", errors.New("empty recovery cookie")
	}
	return cookie.Value, nil
}

func ValidateOTPFormat(otp string) bool {
	if len(otp) != 6 {
		return false
	}
	for _, c := range otp {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
