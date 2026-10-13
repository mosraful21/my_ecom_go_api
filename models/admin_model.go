package models

type Admin struct {
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
	Role       int     `json:"role"`
	Status     int     `json:"status"`
	Version    int64   `json:"version"`
	CreatedAt  int64   `json:"created_at"`
	UpdatedAt  int64   `json:"updated_at"`
	Password   string  `json:"-"`
}

type AdminLoginRequest struct {
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type AdminCreateRequest struct {
	Name     string `json:"name"`
	Role     int    `json:"role"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
}

type AdminUpdateMeRequest struct {
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

type AdminUpdateRequest struct {
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
	Role       *int    `json:"role"`
}

type AdminStatusRequest struct {
	Status int `json:"status"`
}

type AdminChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type AdminForgotPasswordRequest struct {
	Phone string `json:"phone"`
}

type AdminVerifyOTPRequest struct {
	OTP string `json:"otp"`
}

type AdminResetPasswordRequest struct {
	ResetToken string `json:"reset_token"`
	Password   string `json:"password"`
}

type AdminResetTokenResponse struct {
	ResetToken string `json:"reset_token"`
}
