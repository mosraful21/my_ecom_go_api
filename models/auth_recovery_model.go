package models

type RecoverySession struct {
	OwnerType           string `json:"owner_type"`
	OwnerID             int64  `json:"owner_id"`
	Phone               string `json:"phone"`
	OTPHash             string `json:"otp_hash"`
	OTPExpiresAt        int64  `json:"otp_expires_at"`
	OTPAttempts         int    `json:"otp_attempts"`
	OTPVerified         bool   `json:"otp_verified"`
	ResetTokenHash      string `json:"reset_token_hash"`
	ResetTokenExpiresAt int64  `json:"reset_token_expires_at"`
}
