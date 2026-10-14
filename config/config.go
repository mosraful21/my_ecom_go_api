package config

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

const (
	TypeAdmin = 1
	TypeUser  = 2

	AdminRoleAdmin     = 1
	AdminRoleManager   = 2
	AdminRoleModerator = 3

	StatusActive   = 1
	StatusInactive = 2
	StatusBan      = 3

	MaxForgotPasswordRequests = 5
	MaxOTPAttempts            = 5
	OTPExpirySeconds          = 5 * 60
	ResetTokenTTL             = 5 * 60
	RecoverySessionTTL        = 5 * 60
	ForgotPasswordCooldown    = 24 * 60 * 60

	ForgotPasswordIPWindowSeconds  = 10 * 60
	MaxForgotPasswordRequestsPerIP = 20
)

type Config struct {
	AppName string
	AppEnv  string
	AppPort string

	DBName     string
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	CookieName      string
	StoragePath     string
	PaginationLimit int

	SMSEnabled bool
	SMSAPIKey  string
	SMSAPIURL  string

	RecoverySecret       string
	RecoveryCookieSecure bool
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	c := &Config{
		AppName: get("APP_NAME", "my_ecom_api"),
		AppEnv:  get("APP_ENV", "development"),
		AppPort: get("APP_PORT", "4000"),

		DBName:     get("DB_NAME", "my_ecom_go"),
		DBHost:     get("DB_HOST", "127.0.0.1"),
		DBPort:     get("DB_PORT", "3306"),
		DBUser:     get("DB_USER", "root"),
		DBPassword: os.Getenv("DB_PASSWORD"),

		RedisAddr:     get("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword: get("REDIS_PASSWORD", ""),
		RedisDB:       getIntAllowZero("REDIS_DB", 0),

		CookieName:      get("COOKIE_NAME", "my_shop_session"),
		StoragePath:     get("STORAGE_PATH", "./storage"),
		PaginationLimit: getInt("PAGINATION_LIMIT", 50),

		SMSEnabled: getBool("SMS_ENABLED", false),
		SMSAPIKey:  os.Getenv("SMS_API_KEY"),
		SMSAPIURL:  os.Getenv("SMS_API_URL"),

		RecoverySecret:       os.Getenv("RECOVERY_SECRET"),
		RecoveryCookieSecure: getBool("RECOVERY_COOKIE_SECURE", true),
	}

	if strings.EqualFold(c.AppEnv, "production") {
		if len(c.RecoverySecret) < 32 {
			return nil, errors.New("RECOVERY_SECRET must be at least 32 bytes in production")
		}
		if !c.RecoveryCookieSecure {
			return nil, errors.New("RECOVERY_COOKIE_SECURE must be true in production")
		}
		if c.SMSEnabled && (strings.TrimSpace(c.SMSAPIURL) == "" || strings.TrimSpace(c.SMSAPIKey) == "") {
			return nil, errors.New("SMS_API_URL and SMS_API_KEY are required when SMS_ENABLED=true")
		}
	}

	return c, nil
}

func get(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getInt(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		n, err := strconv.Atoi(v)

		if err == nil && n > 0 {
			return n
		}
	}
	return d
}

func getIntAllowZero(k string, d int) int {
	if v := os.Getenv(k); v != "" {
		n, err := strconv.Atoi(v)

		if err == nil && n >= 0 {
			return n
		}
	}
	return d
}

func getBool(k string, d bool) bool {
	if v := os.Getenv(k); v != "" {
		b, err := strconv.ParseBool(v)

		if err == nil {
			return b
		}
	}
	return d
}
