package utils

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

func JSON(w http.ResponseWriter, status int, response Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(response)
}

func Success(w http.ResponseWriter, status int, message string, data any) {
	JSON(w, status, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, Response{
		Success: false,
		Message: message,
	})
}

func ValidatePhone(phone string) error {
	if !regexp.MustCompile(`^01[3-9][0-9]{8}$`).MatchString(strings.TrimSpace(phone)) {
		return fmt.Errorf("invalid phone number: must be a valid 11-digit Bangladesh mobile number")
	}
	return nil
}

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if len([]byte(password)) > 72 {
		return fmt.Errorf("password must not exceed 72 bytes")
	}
	return nil
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	)
	return err == nil
}

// IMAGE
func SaveImage(file multipart.File, header *multipart.FileHeader, storagePath string, folder string) (string, error) {
	if file == nil || header == nil {
		return "", fmt.Errorf("invalid image")
	}

	ext := strings.ToLower(filepath.Ext(header.Filename))

	switch ext {
	case ".jpg", ".jpeg", ".png", ".webp", ".gif":
	default:
		return "", fmt.Errorf("unsupported image format")
	}

	randomBytes := make([]byte, 16)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	filename := hex.EncodeToString(randomBytes) + ext

	dir := filepath.Join(storagePath, folder)

	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	path := filepath.Join(dir, filename)

	dst, err := os.Create(path)
	if err != nil {
		return "", err
	}

	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		_ = os.Remove(path)
		return "", err
	}

	return filename, nil
}

func DeleteImage(storagePath string, folder string, filename string) error {
	filename = strings.TrimSpace(filename)

	if filename == "" {
		return nil
	}

	filename = filepath.Base(filename)

	path := filepath.Join(
		storagePath,
		folder,
		filename,
	)

	err := os.Remove(path)

	if os.IsNotExist(err) {
		return nil
	}

	return err
}
