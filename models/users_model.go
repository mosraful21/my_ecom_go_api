package models

type User struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Phone      string  `json:"phone"`
	Email      *string `json:"email"`
	Image      *string `json:"image"`
	Gender     *string `json:"gender"`
	Division   *string `json:"division"`
	District   *string `json:"district"`
	Thana      *string `json:"thana"`
	PostOffice *string `json:"post_office"`
	Address    *string `json:"address"`
	Type       int     `json:"type"`
	Status     int     `json:"status"`
	Version    int64   `json:"version"`
	CreatedAt  int64   `json:"created_at"`
	UpdatedAt  int64   `json:"updated_at"`
	Password   string  `json:"-"`
}

type UserRegisterRequest struct {
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type UserLoginRequest struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type UserProfileResponse struct {
	Name       string  `json:"name"`
	Phone      string  `json:"phone"`
	Email      *string `json:"email"`
	Image      *string `json:"image"`
	Gender     *string `json:"gender"`
	Division   *string `json:"division"`
	District   *string `json:"district"`
	Thana      *string `json:"thana"`
	PostOffice *string `json:"post_office"`
	Address    *string `json:"address"`
}

type UserUpdateRequest struct {
	Name       *string `json:"name"`
	Phone      *string `json:"phone"`
	Email      *string `json:"email"`
	Image      *string `json:"image"`
	Gender     *string `json:"gender"`
	Division   *string `json:"division"`
	District   *string `json:"district"`
	Thana      *string `json:"thana"`
	PostOffice *string `json:"post_office"`
	Address    *string `json:"address"`
}

type UserStatusRequest struct {
	Status int `json:"status"`
}

type UserChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type UserForgotPasswordRequest struct {
	Phone string `json:"phone"`
}

type UserVerifyOTPRequest struct {
	OTP string `json:"otp"`
}

type UserResetPasswordRequest struct {
	ResetToken string `json:"reset_token"`
	Password   string `json:"password"`
}

type UserResetTokenResponse struct {
	ResetToken string `json:"reset_token"`
}
