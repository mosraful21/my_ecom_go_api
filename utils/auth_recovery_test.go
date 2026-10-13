package utils

import "testing"

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name    string
		password string
		wantErr bool
	}{
		{name: "minimum accepted", password: "abcd1234", wantErr: false},
		{name: "too short", password: "abc1234", wantErr: true},
		{name: "bcrypt byte limit", password: string(make([]byte, 73)), wantErr: true},
		{name: "maximum accepted", password: string(make([]byte, 72)), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOTPFormat(t *testing.T) {
	tests := []struct {
		otp  string
		want bool
	}{
		{otp: "012345", want: true},
		{otp: "12345", want: false},
		{otp: "1234567", want: false},
		{otp: "12a456", want: false},
		{otp: "", want: false},
	}
	for _, tt := range tests {
		if got := ValidateOTPFormat(tt.otp); got != tt.want {
			t.Errorf("ValidateOTPFormat(%q) = %v, want %v", tt.otp, got, tt.want)
		}
	}
}

func TestOTPHashIsScopedToRecoverySession(t *testing.T) {
	const secret = "test-only-secret"
	first := HashOTP(secret, "session-a", "012345")
	second := HashOTP(secret, "session-b", "012345")
	if first == second {
		t.Fatal("OTP hash must be scoped to the recovery session")
	}
	if !ConstantTimeEqual(first, HashOTP(secret, "session-a", "012345")) {
		t.Fatal("same session and OTP should produce the same HMAC")
	}
}
