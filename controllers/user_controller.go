package controllers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-sql-driver/mysql"

	"my_ecom_api/config"
	"my_ecom_api/middleware"
	"my_ecom_api/models"
	"my_ecom_api/utils"
)

type UserController struct {
	DB  *sql.DB
	Cfg *config.Config
	*AuthRecoveryController
}

type rowScanner interface {
	Scan(dest ...any) error
}

const userSelect = `
	SELECT
    id,
    name,
    phone,
    email,
    image,
    gender,
    division,
    district,
    thana,
    post_office,
    address,
    type,
    status,
    version,
    created_at,
    updated_at
	FROM users
`

func scanUser(s rowScanner, u *models.User) error {
	return s.Scan(
		&u.ID,
		&u.Name,
		&u.Phone,
		&u.Email,
		&u.Image,
		&u.Gender,
		&u.Division,
		&u.District,
		&u.Thana,
		&u.PostOffice,
		&u.Address,
		&u.Type,
		&u.Status,
		&u.Version,
		&u.CreatedAt,
		&u.UpdatedAt,
	)
}

func (c *UserController) Register(w http.ResponseWriter, r *http.Request) {
	var req models.UserRegisterRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	name := strings.TrimSpace(req.Name)
	phone := strings.TrimSpace(req.Phone)
	password := req.Password

	if name == "" || phone == "" || password == "" {
		utils.Error(w, http.StatusBadRequest, "name, phone and password are required")
		return
	}

	if err := utils.ValidatePhone(phone); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := utils.ValidatePassword(password); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	hash, err := utils.HashPassword(password)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "password hashing failed")
		return
	}

	now := time.Now().Unix()

	result, err := c.DB.ExecContext(
		r.Context(),
		`INSERT INTO users (
            name,
            phone,
            password,
            type,
            status,
            version,
            created_at,
            updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		name,
		phone,
		hash,
		config.TypeUser,
		config.StatusActive,
		1,
		now,
		now,
	)
	if err != nil {
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			utils.Error(w, http.StatusConflict, "phone number already exists")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to register user")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get user id")
		return
	}

	utils.Success(w, http.StatusCreated, "user registered successfully",
		map[string]any{
			"id": id,
		},
	)
}

func (c *UserController) Login(w http.ResponseWriter, r *http.Request) {
	var req models.UserLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	phone := strings.TrimSpace(req.Phone)
	password := req.Password

	if phone == "" || password == "" {
		utils.Error(w, http.StatusBadRequest, "phone and password are required")
		return
	}

	ip := getClientIP(r)
	blocked, rateErr := c.loginBlocked(r.Context(), "user", phone, ip)

	if rateErr != nil {
		utils.Error(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}

	if blocked {
		utils.Error(w, http.StatusTooManyRequests, "too many login attempts; try again later")
		return
	}

	var (
		id     int64
		hash   string
		status int
	)

	err := c.DB.QueryRowContext(
		r.Context(),
		`SELECT id, password, status
         FROM users
         WHERE phone = ?`,
		phone,
	).Scan(&id, &hash, &status)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if rateErr := c.recordFailedLogin(r.Context(), "user", phone, ip); rateErr != nil {
				fmt.Printf("user login throttle update failed: %v\n", rateErr)
			}
			utils.Error(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "login failed")
		return
	}

	if !utils.CheckPassword(hash, password) {
		if rateErr := c.recordFailedLogin(r.Context(), "user", phone, ip); rateErr != nil {
			fmt.Printf("user login throttle update failed: %v\n", rateErr)
		}
		utils.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if status != config.StatusActive {
		utils.Error(w, http.StatusForbidden, "account is not active")
		return
	}

	token, err := middleware.CreateSession(c.DB, config.TypeUser, id)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "session creation failed")
		return
	}

	if err := c.clearLoginPhoneFailures(r.Context(), "user", phone); err != nil {
		fmt.Printf("user login throttle reset failed: %v\n", err)
	}

	middleware.SetCookie(w, c.Cfg.CookieName, token, c.Cfg.RecoveryCookieSecure)
	utils.Success(w, http.StatusOK, "login successful", nil)
}

func (c *UserController) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(c.Cfg.CookieName)

	if err == nil && cookie.Value != "" {
		_, dbErr := c.DB.ExecContext(
			r.Context(),
			`UPDATE auth_sessions
             SET revoked_at = ?
             WHERE token_hash = ?
               AND revoked_at IS NULL`,
			time.Now().Unix(),
			utils.HashToken(cookie.Value),
		)

		if dbErr != nil {
			middleware.ClearCookie(w, c.Cfg.CookieName, c.Cfg.RecoveryCookieSecure)
			utils.Error(w, http.StatusInternalServerError, "failed to terminate session")
			return
		}
	} else if err != nil && !errors.Is(err, http.ErrNoCookie) {
		middleware.ClearCookie(w, c.Cfg.CookieName, c.Cfg.RecoveryCookieSecure)
		utils.Error(w, http.StatusBadRequest, "invalid session cookie")
		return
	}

	middleware.ClearCookie(w, c.Cfg.CookieName, c.Cfg.RecoveryCookieSecure)
	utils.Success(w, http.StatusOK, "logged out successfully", nil)
}

func (c *UserController) GetMe(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var user models.User

	err := scanUser(
		c.DB.QueryRowContext(
			r.Context(),
			userSelect+` WHERE id = ?`,
			id,
		),
		&user,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "user not found")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to get user profile")
		return
	}

	utils.Success(w, http.StatusOK, "user profile retrieved successfully", user)
}

func (c *UserController) UpdateMe(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var q models.UserUpdateRequest
	var newImage string
	var oldImage sql.NullString
	var imageChanged bool
	var removeImage bool

	err := c.DB.QueryRowContext(
		r.Context(),
		`SELECT image FROM users WHERE id=?`,
		id,
	).Scan(&oldImage)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.Error(w, http.StatusNotFound, "user not found")
		} else {
			utils.Error(w, http.StatusInternalServerError, "failed to get user")
		}
		return
	}

	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/json") {
		if !decodeJSON(w, r, &q) {
			return
		}

		if q.Image != nil && strings.TrimSpace(*q.Image) == "" {
			removeImage = true
		}

	} else if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			utils.Error(w, http.StatusBadRequest, "invalid form data")
			return
		}

		if _, ok := r.Form["name"]; ok {
			v := r.FormValue("name")
			q.Name = &v
		}

		if _, ok := r.Form["email"]; ok {
			v := r.FormValue("email")
			q.Email = &v
		}

		if _, ok := r.Form["gender"]; ok {
			v := r.FormValue("gender")
			q.Gender = &v
		}

		if _, ok := r.Form["division"]; ok {
			v := r.FormValue("division")
			q.Division = &v
		}

		if _, ok := r.Form["district"]; ok {
			v := r.FormValue("district")
			q.District = &v
		}

		if _, ok := r.Form["thana"]; ok {
			v := r.FormValue("thana")
			q.Thana = &v
		}

		if _, ok := r.Form["post_office"]; ok {
			v := r.FormValue("post_office")
			q.PostOffice = &v
		}

		if _, ok := r.Form["address"]; ok {
			v := r.FormValue("address")
			q.Address = &v
		}

		file, header, err := r.FormFile("image")

		if err == nil {
			defer file.Close()

			newImage, err = utils.SaveImage(
				file,
				header,
				c.Cfg.StoragePath,
				"user",
			)

			if err != nil {
				utils.Error(w, http.StatusBadRequest, err.Error())
				return
			}

			imageChanged = true
			q.Image = &newImage

		} else if _, exists := r.Form["image"]; exists {
			removeImage = true

			empty := ""
			q.Image = &empty
		}

	} else {
		utils.Error(w, http.StatusUnsupportedMediaType, "unsupported content type")
		return
	}

	fields := make([]string, 0, 10)
	args := make([]any, 0, 11)

	add := func(column string, value *string) {
		if value != nil {
			fields = append(fields, column+"=?")
			args = append(args, *value)
		}
	}

	add("name", q.Name)
	add("email", q.Email)
	add("gender", q.Gender)
	add("division", q.Division)
	add("district", q.District)
	add("thana", q.Thana)
	add("post_office", q.PostOffice)
	add("address", q.Address)

	if removeImage {
		fields = append(fields, "image=NULL")
	} else if imageChanged {
		fields = append(fields, "image=?")
		args = append(args, newImage)
	} else if q.Image != nil {
		fields = append(fields, "image=?")
		args = append(args, *q.Image)
	}

	if len(fields) == 0 {
		if imageChanged {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"user",
				newImage,
			)
		}

		utils.Error(w, http.StatusBadRequest, "nothing to update")
		return
	}

	fields = append(fields, "updated_at=?")
	args = append(args, time.Now().Unix(), id)

	result, err := c.DB.ExecContext(
		r.Context(),
		`UPDATE users SET `+
			strings.Join(fields, ", ")+
			` WHERE id=?`,
		args...,
	)

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"user",
				newImage,
			)
		}

		utils.Error(w, http.StatusConflict, "update failed")
		return
	}

	affected, err := result.RowsAffected()

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"user",
				newImage,
			)
		}

		utils.Error(w, http.StatusInternalServerError, "failed to check update")
		return
	}

	if affected == 0 {
		if imageChanged {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"user",
				newImage,
			)
		}

		utils.Error(w, http.StatusNotFound, "user not found")
		return
	}

	if imageChanged || removeImage {
		if oldImage.Valid && oldImage.String != "" {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"user",
				oldImage.String,
			)
		}
	}

	var updatedUser models.User

	err = scanUser(
		c.DB.QueryRowContext(
			r.Context(),
			userSelect+` WHERE id=?`,
			id,
		),
		&updatedUser,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get updated user")
		return
	}

	utils.Success(w, http.StatusOK, "user profile updated", updatedUser)
}

func (c *UserController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var req models.UserChangePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		utils.Error(w, http.StatusBadRequest, "old_password and new_password are required")
		return
	}

	if err := utils.ValidatePassword(req.NewPassword); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	var currentHash string

	err := c.DB.QueryRowContext(
		r.Context(),
		`SELECT password FROM users WHERE id = ?`,
		id,
	).Scan(&currentHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "user not found")
			return
		}

		utils.Error(w, http.StatusInternalServerError, "failed to verify user credentials")
		return
	}

	if !utils.CheckPassword(currentHash, req.OldPassword) {
		utils.Error(w, http.StatusUnauthorized, "old password is incorrect")
		return
	}

	newHash, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "password hashing failed")
		return
	}

	cookie, err := r.Cookie(c.Cfg.CookieName)
	if err != nil || cookie.Value == "" {
		utils.Error(w, http.StatusUnauthorized, "current session not found")
		return
	}

	currentTokenHash := utils.HashToken(cookie.Value)
	now := time.Now().Unix()

	tx, err := c.DB.BeginTx(r.Context(), nil)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "password change failed")
		return
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(
		r.Context(),
		`UPDATE users
         SET password = ?,
             version = version + 1,
             updated_at = ?
         WHERE id = ? AND password = ?`,
		newHash,
		now,
		id,
		currentHash,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "password update failed")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to verify password update")
		return
	}

	if rowsAffected != 1 {
		utils.Error(w, http.StatusConflict, "password was changed concurrently; please try again")
		return
	}

	_, err = tx.ExecContext(
		r.Context(),
		`UPDATE auth_sessions
         SET revoked_at = ?
         WHERE user_id = ?
           AND token_hash <> ?
           AND revoked_at IS NULL`,
		now,
		id,
		currentTokenHash,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to revoke other sessions")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "password change failed")
		return
	}

	utils.Success(w, http.StatusOK, "user password changed successfully", nil)
}

func (c *UserController) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}

	var req models.UserForgotPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	phone := strings.TrimSpace(req.Phone)
	if phone == "" {
		utils.Error(w, http.StatusBadRequest, "phone is required")
		return
	}

	const (
		ownerType  = "user"
		cookieName = "user_password_recovery"
	)

	genericResponse := func() {
		utils.Success(w, http.StatusOK, "if the account exists, an OTP has been sent", nil)
	}

	ip := getClientIP(r)
	userAgent := r.UserAgent()

	allowed, rateErr := c.allowForgotPassword(ctx, ownerType, phone, ip)
	if rateErr != nil {
		fmt.Printf("forgot password rate limiter failed: %v\n", rateErr)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	if !allowed {
		utils.Error(w, http.StatusTooManyRequests, "too many password recovery requests")
		return
	}

	var userID int64
	err := c.DB.QueryRowContext(
		ctx,
		`SELECT id
		 FROM users
		 WHERE phone = ?
		 LIMIT 1`,
		phone,
	).Scan(&userID)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if auditErr := c.auditPasswordReset(
				ctx,
				ownerType,
				nil,
				phone,
				"requested",
				ip,
				userAgent,
			); auditErr != nil {
				fmt.Printf("password reset audit failed: %v\n", auditErr)
			}
			genericResponse()
			return
		}

		fmt.Printf("user lookup failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	var requestCount int
	err = c.DB.QueryRowContext(
		ctx,
		`SELECT COUNT(*)
		 FROM password_reset_audits
		 WHERE owner_type = ?
		   AND owner_id = ?
		   AND event_type = 'requested'
		   AND created_at >= ?`,
		ownerType,
		userID,
		time.Now().Unix()-config.ForgotPasswordCooldown,
	).Scan(&requestCount)

	if err != nil {
		fmt.Printf("password reset request count failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	if requestCount >= config.MaxForgotPasswordRequests {
		if auditErr := c.auditPasswordReset(
			ctx,
			ownerType,
			&userID,
			phone,
			"rate_limited",
			ip,
			userAgent,
		); auditErr != nil {
			fmt.Printf("password reset audit failed: %v\n", auditErr)
		}

		utils.Error(w, http.StatusTooManyRequests, "too many password recovery requests")
		return
	}

	sessionID, err := utils.RandomRecoverySessionID()
	if err != nil {
		fmt.Printf("recovery session ID generation failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	otp, err := utils.RandomOTP(6)
	if err != nil {
		fmt.Printf("OTP generation failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	now := time.Now().Unix()

	session := models.RecoverySession{
		OwnerType:           ownerType,
		OwnerID:             userID,
		Phone:               phone,
		OTPHash:             utils.HashOTP(c.Cfg.RecoverySecret, sessionID, otp),
		OTPExpiresAt:        now + config.OTPExpirySeconds,
		OTPAttempts:         0,
		OTPVerified:         false,
		ResetTokenHash:      "",
		ResetTokenExpiresAt: 0,
	}

	if err := c.saveRecoverySession(ctx, sessionID, session); err != nil {
		fmt.Printf("recovery session save failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	if err := c.auditPasswordReset(
		ctx,
		ownerType,
		&userID,
		phone,
		"requested",
		ip,
		userAgent,
	); err != nil {
		_ = c.deleteRecoverySession(ctx, sessionID)

		fmt.Printf("password reset audit failed: %v\n", err)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	message := fmt.Sprintf("My Shop: Your password reset OTP is %s. Valid for 5 minutes.", otp)

	if c.Cfg.SMSEnabled {
		_, err = utils.SendSMS(
			c.Cfg.SMSAPIURL,
			c.Cfg.SMSAPIKey,
			phone,
			message,
		)
		if err != nil {
			fmt.Printf("password reset SMS delivery failed: %v\n", err)
			_ = c.deleteRecoverySession(ctx, sessionID)
			genericResponse()
			return
		}
	} else if strings.EqualFold(c.Cfg.AppEnv, "development") {
		fmt.Printf(
			"[DEV ONLY] user password reset OTP: %s (expires in %d seconds)\n",
			otp,
			config.OTPExpirySeconds,
		)
	} else {
		_ = c.deleteRecoverySession(ctx, sessionID)
		genericResponse()
		return
	}

	utils.SetRecoveryCookie(w, cookieName, sessionID, c.Cfg.RecoveryCookieSecure, config.RecoverySessionTTL)
	genericResponse()
}

func (c *UserController) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}

	var req models.UserVerifyOTPRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	otp := strings.TrimSpace(req.OTP)
	if !utils.ValidateOTPFormat(otp) {
		utils.Error(w, http.StatusBadRequest, "otp must be 6 digits")
		return
	}

	const ownerType = "user"
	const cookieName = "user_password_recovery"

	sessionID, err := utils.GetRecoveryCookie(r, cookieName)
	if err != nil {
		utils.Error(w, http.StatusUnauthorized, "recovery session required")
		return
	}

	now := time.Now().Unix()
	resetToken, err := utils.RandomToken()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "reset token creation failed")
		return
	}

	inputHash := utils.HashOTP(c.Cfg.RecoverySecret, sessionID, otp)
	resetHash := utils.HashResetToken(c.Cfg.RecoverySecret, sessionID, resetToken)

	status, session, err := c.verifyOTPAtomic(
		ctx, sessionID, ownerType, inputHash, resetHash, now, now+config.ResetTokenTTL,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to verify otp")
		return
	}

	switch status {
	case 1:
		if err := c.auditPasswordReset(ctx, ownerType, &session.OwnerID, session.Phone, "otp_verified", getClientIP(r), r.UserAgent()); err != nil {
			fmt.Printf("user password reset audit failed: %v\n", err)
		}
		utils.Success(w, http.StatusOK, "otp verified successfully", models.UserResetTokenResponse{ResetToken: resetToken})
	case 0:
		if err := c.auditPasswordReset(ctx, ownerType, &session.OwnerID, session.Phone, "otp_failed", getClientIP(r), r.UserAgent()); err != nil {
			fmt.Printf("user password reset audit failed: %v\n", err)
		}
		utils.Error(w, http.StatusUnauthorized, "invalid otp")
	case -1:
		utils.Error(w, http.StatusUnauthorized, "invalid or expired recovery session")
	case -2:
		utils.Error(w, http.StatusUnauthorized, "invalid recovery session")
	case -3:
		utils.Error(w, http.StatusUnauthorized, "otp already verified")
	case -4:
		utils.Error(w, http.StatusUnauthorized, "otp expired")
	case -5:
		utils.Error(w, http.StatusUnauthorized, "maximum otp attempts exceeded")
	default:
		utils.Error(w, http.StatusInternalServerError, "failed to verify otp")
	}
}

func (c *UserController) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}

	var req models.UserResetPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	resetToken := strings.TrimSpace(req.ResetToken)
	password := req.Password
	if resetToken == "" {
		utils.Error(w, http.StatusBadRequest, "reset_token is required")
		return
	}

	if err := utils.ValidatePassword(password); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	const ownerType = "user"
	const cookieName = "user_password_recovery"

	sessionID, err := utils.GetRecoveryCookie(r, cookieName)
	if err != nil {
		utils.Error(w, http.StatusUnauthorized, "recovery session required")
		return
	}

	tokenHash := utils.HashResetToken(c.Cfg.RecoverySecret, sessionID, resetToken)

	now := time.Now().Unix()

	status, session, err := c.claimResetTokenAtomic(ctx, sessionID, ownerType, tokenHash, now)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to validate reset token")
		return
	}

	if status != 1 {
		if session.OwnerID > 0 {
			if auditErr := c.auditPasswordReset(ctx, ownerType, &session.OwnerID, session.Phone, "reset_failed", getClientIP(r), r.UserAgent()); auditErr != nil {
				fmt.Printf("user password reset audit failed: %v\n", auditErr)
			}
		}
		switch status {
		case -1, -2, -3, -5:
			utils.Error(w, http.StatusUnauthorized, "invalid recovery session or reset token")
		case -4:
			utils.Error(w, http.StatusUnauthorized, "reset token expired")
		case -6:
			utils.Error(w, http.StatusConflict, "password reset is already in progress")
		default:
			utils.Error(w, http.StatusUnauthorized, "invalid recovery session or reset token")
		}
		return
	}

	releaseClaim := func() {
		if releaseErr := c.releaseResetClaim(ctx, sessionID, tokenHash); releaseErr != nil {
			fmt.Printf("user password reset claim release failed: %v\n", releaseErr)
		}
	}

	passwordHash, err := utils.HashPassword(password)
	if err != nil {
		releaseClaim()
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		releaseClaim()
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE users SET password = ?, version = version + 1, updated_at = ? WHERE id = ?`,
		passwordHash, now, session.OwnerID,
	)
	if err != nil {
		tx.Rollback()
		releaseClaim()
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected != 1 {
		tx.Rollback()
		releaseClaim()
		utils.Error(w, http.StatusUnauthorized, "invalid recovery session")
		return
	}

	if _, err = tx.ExecContext(ctx,
		`UPDATE auth_sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		now, session.OwnerID,
	); err != nil {
		tx.Rollback()
		releaseClaim()
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO password_reset_audits
		 (owner_type, owner_id, phone_hash, event_type, ip_address, user_agent, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ownerType, session.OwnerID, utils.HashPhone(c.Cfg.RecoverySecret, session.Phone),
		"reset_success", getClientIP(r), r.UserAgent(), now,
	); err != nil {
		tx.Rollback()
		releaseClaim()
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	if err := c.consumeResetClaim(ctx, sessionID, tokenHash); err != nil {
		fmt.Printf("user recovery session consumption failed: %v\n", err)
	}

	utils.ClearRecoveryCookie(w, cookieName, c.Cfg.RecoveryCookieSecure)
	utils.Success(w, http.StatusOK, "password reset successful", nil)
}

func (c *UserController) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if middleware.Type(r) != config.TypeAdmin {
		utils.Error(w, http.StatusForbidden, "admin access required")
		return false
	}
	return true
}

func (c *UserController) GetUsers(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	params := utils.GetQueryParams(r, c.Cfg.PaginationLimit)
	qb := utils.NewQueryBuilder()

	allowedSort := map[string]string{
		"id":         "id",
		"name":       "name",
		"phone":      "phone",
		"email":      "email",
		"status":     "status",
		"created_at": "created_at",
		"updated_at": "updated_at",
	}

	if params.Search != "" {
		search := "%" + params.Search + "%"
		qb.Add(`(name LIKE ? OR phone LIKE ?)`, search, search)
	}

	where := qb.Where()

	var total int

	countQuery := `SELECT COUNT(*) FROM users` + where

	if err := c.DB.QueryRowContext(
		r.Context(),
		countQuery,
		qb.Args...,
	).Scan(&total); err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to count users")
		return
	}

	orderBy := utils.GetOrder(params.Sort, params.Order, allowedSort, "id")

	query := userSelect + where + orderBy + ` LIMIT ? OFFSET ?`

	args := append(qb.Args, params.Limit, params.Offset)

	rows, err := c.DB.QueryContext(r.Context(), query, args...)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to fetch users")
		return
	}

	defer rows.Close()

	users := make([]models.User, 0)

	for rows.Next() {
		var u models.User
		if err := scanUser(rows, &u); err != nil {
			utils.Error(w, http.StatusInternalServerError, "failed to read users")
			return
		}
		users = append(users, u)
	}

	if err := rows.Err(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to read users")
		return
	}

	pagination := utils.CalculatePagination(params.Page, params.Limit, total)

	utils.Success(w, http.StatusOK, "users fetched successfully",
		map[string]interface{}{
			"users":      users,
			"pagination": pagination,
		},
	)
}

func (c *UserController) GetUserById(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var user models.User

	if err = scanUser(
		c.DB.QueryRowContext(r.Context(), userSelect+` WHERE id=?`, id), &user,
	); err != nil {
		if err == sql.ErrNoRows {
			utils.Error(w, http.StatusNotFound, "user not found")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	utils.Success(w, http.StatusOK, "user profile", user)
}

func (c *UserController) Update(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	ctx := r.Context()

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var q models.UserUpdateRequest
	var newImage string
	var oldImage sql.NullString
	var imageChanged, removeImage bool

	err = c.DB.QueryRowContext(ctx,
		`SELECT image FROM users WHERE id=?`, id).Scan(&oldImage)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "user not found")
		} else {
			utils.Error(w, http.StatusInternalServerError, "failed to get user")
		}
		return
	}

	contentType := r.Header.Get("Content-Type")

	if strings.HasPrefix(contentType, "application/json") {
		if !decodeJSON(w, r, &q) {
			return
		}

		if q.Image != nil && strings.TrimSpace(*q.Image) == "" {
			removeImage = true
		}

	} else if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			utils.Error(w, http.StatusBadRequest, "invalid form data")
			return
		}

		if _, ok := r.Form["name"]; ok {
			v := r.FormValue("name")
			q.Name = &v
		}

		if _, ok := r.Form["phone"]; ok {
			v := r.FormValue("phone")
			q.Phone = &v
		}

		if _, ok := r.Form["email"]; ok {
			v := r.FormValue("email")
			q.Email = &v
		}

		if _, ok := r.Form["gender"]; ok {
			v := r.FormValue("gender")
			q.Gender = &v
		}

		if _, ok := r.Form["division"]; ok {
			v := r.FormValue("division")
			q.Division = &v
		}

		if _, ok := r.Form["district"]; ok {
			v := r.FormValue("district")
			q.District = &v
		}

		if _, ok := r.Form["thana"]; ok {
			v := r.FormValue("thana")
			q.Thana = &v
		}

		if _, ok := r.Form["post_office"]; ok {
			v := r.FormValue("post_office")
			q.PostOffice = &v
		}

		if _, ok := r.Form["address"]; ok {
			v := r.FormValue("address")
			q.Address = &v
		}

		file, header, fileErr := r.FormFile("image")

		if fileErr == nil {
			newImage, err = utils.SaveImage(
				file,
				header,
				c.Cfg.StoragePath,
				"user",
			)
			_ = file.Close()

			if err != nil {
				utils.Error(w, http.StatusBadRequest, err.Error())
				return
			}

			imageChanged = true
			q.Image = &newImage
			removeImage = false

		} else if _, exists := r.Form["image"]; exists {
			removeImage = true
			q.Image = nil
		}

	} else {
		utils.Error(w, http.StatusUnsupportedMediaType, "unsupported content type")
		return
	}

	if q.Phone != nil {
		*q.Phone = strings.TrimSpace(*q.Phone)
		if err := utils.ValidatePhone(*q.Phone); err != nil {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "user", newImage)
			}
			utils.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	fields := make([]string, 0, 11)
	args := make([]any, 0, 12)

	add := func(column string, value *string) {
		if value != nil {
			fields = append(fields, column+"=?")
			args = append(args, *value)
		}
	}

	add("name", q.Name)
	add("phone", q.Phone)
	add("email", q.Email)
	add("gender", q.Gender)
	add("division", q.Division)
	add("district", q.District)
	add("thana", q.Thana)
	add("post_office", q.PostOffice)
	add("address", q.Address)

	if removeImage {
		fields = append(fields, "image=NULL")
	} else if imageChanged {
		fields = append(fields, "image=?")
		args = append(args, newImage)
	} else if q.Image != nil {
		fields = append(fields, "image=?")
		args = append(args, *q.Image)
	}

	if len(fields) == 0 {
		utils.Error(w, http.StatusBadRequest, "nothing to update")
		return
	}

	fields = append(fields, "updated_at=?")
	args = append(args, time.Now().Unix(), id)

	result, err := c.DB.ExecContext(ctx,
		`UPDATE users SET `+strings.Join(fields, ", ")+` WHERE id=?`,
		args...,
	)

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "user", newImage)
		}
		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			utils.Error(w, http.StatusConflict, "phone number already exists")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "user", newImage)
		}
		utils.Error(w, http.StatusInternalServerError, "failed to check update")
		return
	}

	if affected == 0 {
		var exists bool
		err = c.DB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE id=?)`, id,
		).Scan(&exists)

		if err != nil {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "user", newImage)
			}
			utils.Error(w, http.StatusInternalServerError, "failed to verify user")
			return
		}

		if !exists {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "user", newImage)
			}
			utils.Error(w, http.StatusNotFound, "user not found")
			return
		}
	}

	if (imageChanged || removeImage) && oldImage.Valid && oldImage.String != "" {
		if err := utils.DeleteImage(
			c.Cfg.StoragePath,
			"user",
			oldImage.String,
		); err != nil {
			utils.Error(w, http.StatusInternalServerError, "user updated but old image deletion failed")
			return
		}
	}

	var updatedUser models.User

	err = scanUser(
		c.DB.QueryRowContext(ctx, userSelect+` WHERE id=?`, id),
		&updatedUser,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get updated user")
		return
	}

	utils.Success(w, http.StatusOK, "user updated successfully", updatedUser)
}

func (c *UserController) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var q models.UserStatusRequest
	if !decodeJSON(w, r, &q) {
		return
	}

	if q.Status != config.StatusActive &&
		q.Status != config.StatusInactive &&
		q.Status != config.StatusBan {
		utils.Error(w, http.StatusBadRequest, "invalid status")
		return
	}

	now := time.Now().Unix()

	result, err := c.DB.ExecContext(
		r.Context(),
		`UPDATE users
		 SET status = ?,
		 		version = version + 1, 
		 		updated_at = ?
		 WHERE id = ?`,
		q.Status, now, id,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "status update failed")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check update")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "user not found")
		return
	}

	if q.Status != config.StatusActive {
		_, err = c.DB.ExecContext(
			r.Context(),
			`UPDATE auth_sessions 
			 SET revoked_at = ?
			 WHERE user_id = ? 
			 	AND revoked_at IS NULL`,
			now, id,
		)
		if err != nil {
			utils.Error(w, http.StatusInternalServerError, "status updated but session revocation failed")
			return
		}
	}

	var u models.User
	if err := scanUser(
		c.DB.QueryRowContext(
			r.Context(),
			userSelect+` WHERE id = ?`,
			id,
		),
		&u); err != nil {
		utils.Error(w, http.StatusInternalServerError, "status updated but could not be loaded")
		return
	}

	utils.Success(w, http.StatusOK, "user status updated successfully", u)
}

func (c *UserController) Delete(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid user id")
		return
	}

	var image sql.NullString
	err = c.DB.QueryRowContext(
		r.Context(),
		`SELECT image FROM users WHERE id = ?`,
		id,
	).Scan(&image)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "user not found")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to get user")
		return
	}

	tx, err := c.DB.BeginTx(r.Context(), nil)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "delete failed")
		return
	}

	defer tx.Rollback()

	now := time.Now().Unix()

	_, err = tx.ExecContext(
		r.Context(),
		`UPDATE auth_sessions
		 SET revoked_at = ?
		 WHERE user_id = ?
		   AND revoked_at IS NULL`,
		now,
		id,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to revoke user sessions")
		return
	}

	result, err := tx.ExecContext(
		r.Context(),
		`DELETE FROM users WHERE id = ?`,
		id,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "user delete failed")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check delete")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "user not found")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "delete failed")
		return
	}

	if image.Valid && image.String != "" {
		_ = utils.DeleteImage(c.Cfg.StoragePath, "user", image.String)
	}

	utils.Success(w, http.StatusOK, "user deleted successfully", nil)
}

func (c *UserController) ForceAllLogout(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}

	result, err := c.DB.ExecContext(
		r.Context(),
		`UPDATE auth_sessions
		 SET revoked_at = ?
		 WHERE user_id IS NOT NULL
		   AND revoked_at IS NULL`,
		time.Now().Unix(),
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to force logout all users")
		return
	}

	_, err = result.RowsAffected()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check revoked sessions")
		return
	}

	utils.Success(w, http.StatusOK, "all user sessions revoked", nil)
}
