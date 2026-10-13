package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"my_ecom_api/config"
	"my_ecom_api/database"
	"my_ecom_api/utils"
)

func main() {
	name := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_NAME"))
	phone := strings.TrimSpace(os.Getenv("BOOTSTRAP_ADMIN_PHONE"))
	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if name == "" || phone == "" || password == "" {
		log.Fatal("BOOTSTRAP_ADMIN_NAME, BOOTSTRAP_ADMIN_PHONE, and BOOTSTRAP_ADMIN_PASSWORD are required")
	}
	if err := utils.ValidatePhone(phone); err != nil {
		log.Fatalf("invalid bootstrap admin phone: %v", err)
	}
	if err := utils.ValidatePassword(password); err != nil {
		log.Fatalf("invalid bootstrap admin password: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var count int64
	if err := db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count); err != nil {
		log.Fatalf("failed to inspect admin table: %v", err)
	}
	if count != 0 {
		log.Fatal("bootstrap refused: an administrator already exists")
	}

	passwordHash, err := utils.HashPassword(password)
	if err != nil {
		log.Fatalf("failed to hash bootstrap password: %v", err)
	}

	now := time.Now().Unix()
	_, err = db.Exec(
		`INSERT INTO admin
		 (name, phone, password, type, role, status, version, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		name, phone, passwordHash,
		config.TypeAdmin, config.AdminRoleAdmin, config.StatusActive, 1, now, now,
	)
	if err != nil {
		// The count check and insert can race; a unique phone constraint still protects duplicates.
		log.Fatalf("failed to create bootstrap administrator: %v", err)
	}

	fmt.Println("Bootstrap administrator created. Remove BOOTSTRAP_ADMIN_PASSWORD from the environment.")
}
