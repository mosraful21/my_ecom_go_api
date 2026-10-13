package controllers

import (
	"database/sql"
	"encoding/json"
	"io"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"my_ecom_api/config"
	"my_ecom_api/middleware"
	"my_ecom_api/models"
	"my_ecom_api/utils"

	"github.com/go-chi/chi/v5"
	"github.com/go-sql-driver/mysql"
)

type AdminController struct {
	DB  *sql.DB
	Cfg *config.Config
	*AuthRecoveryController
}

const adminSelect = `
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
		role,
		status,
		version,
		created_at,
		updated_at
	FROM admin
`

func scanAdmin(s rowScanner, a *models.Admin) error {
	return s.Scan(
		&a.ID,
		&a.Name,
		&a.Phone,
		&a.Email,
		&a.Image,
		&a.Gender,
		&a.Division,
		&a.District,
		&a.Thana,
		&a.PostOffice,
		&a.Address,
		&a.Type,
		&a.Role,
		&a.Status,
		&a.Version,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		utils.Error(w, http.StatusBadRequest, "invalid request")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		utils.Error(w, http.StatusBadRequest, "request must contain a single JSON object")
		return false
	}
	return true
}

func (c *AdminController) Login(w http.ResponseWriter, r *http.Request) {
	var q models.AdminLoginRequest
	if !decodeJSON(w, r, &q) {
		return
	}

	q.Phone = strings.TrimSpace(q.Phone)

	if q.Phone == "" || q.Password == "" {
		utils.Error(w, http.StatusBadRequest, "phone and password are required")
		return
	}

	var a models.Admin

	err := c.DB.QueryRowContext(
		r.Context(),
		`SELECT id,password,type,role,status
		 FROM admin
		 WHERE phone=?
		 LIMIT 1`,
		q.Phone,
	).Scan(
		&a.ID,
		&a.Password,
		&a.Type,
		&a.Role,
		&a.Status,
	)

	if err != nil || !utils.CheckPassword(a.Password, q.Password) {
		utils.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if a.Status != config.StatusActive {
		utils.Error(w, http.StatusForbidden, "admin is not active")
		return
	}

	token, err := middleware.CreateSession(c.DB, config.TypeAdmin, a.ID)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "session creation failed")
		return
	}

	middleware.SetCookie(w, c.Cfg.CookieName, token, c.Cfg.RecoveryCookieSecure)

	utils.Success(w, http.StatusOK, "login successful", nil)
}

func (c *AdminController) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(c.Cfg.CookieName)
	if err == nil && cookie.Value != "" {
		_, _ = c.DB.ExecContext(
			r.Context(),
			`UPDATE auth_sessions 
			 SET revoked_at=? 
			 WHERE token_hash=? 
			 AND revoked_at IS NULL`,
			time.Now().Unix(),
			utils.HashToken(cookie.Value))
	}
	middleware.ClearCookie(w, c.Cfg.CookieName, c.Cfg.RecoveryCookieSecure)

	utils.Success(w, http.StatusOK, "logged out", nil)
}

func (c *AdminController) GetMe(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var a models.Admin
	err := scanAdmin(
		c.DB.QueryRowContext(
			r.Context(),
			adminSelect+` WHERE id=?`,
			id,
		),
		&a,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "admin not found")
			return
		}

		utils.Error(w, http.StatusInternalServerError, "failed to get admin")
		return
	}

	utils.Success(w, http.StatusOK, "admin profile", a)
}

func (c *AdminController) UpdateMe(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var q models.AdminUpdateMeRequest
	var newImage string
	var oldImage sql.NullString
	var imageChanged bool
	var removeImage bool

	err := c.DB.QueryRowContext(
		r.Context(),
		`SELECT image FROM admin WHERE id = ?`,
		id,
	).Scan(&oldImage)

	if err != nil {
		if err == sql.ErrNoRows {
			utils.Error(w, http.StatusNotFound, "admin not found")
		} else {
			utils.Error(w, http.StatusInternalServerError, "failed to get admin")
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

			newImage, err = utils.SaveImage(file, header, c.Cfg.StoragePath, "admin")

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
			fields = append(fields, column+" = ?")
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
		fields = append(fields, "image = NULL")
	} else if imageChanged {
		fields = append(fields, "image = ?")
		args = append(args, newImage)
	} else if q.Image != nil {
		fields = append(fields, "image = ?")
		args = append(args, *q.Image)
	}

	if len(fields) == 0 {
		if imageChanged {
			_ = utils.DeleteImage(
				c.Cfg.StoragePath,
				"admin",
				newImage,
			)
		}

		utils.Error(w, http.StatusBadRequest, "nothing to update")
		return
	}

	fields = append(fields, "version = version + 1")
	fields = append(fields, "updated_at = ?")
	args = append(args, time.Now().Unix(), id)

	result, err := c.DB.ExecContext(
		r.Context(),
		`UPDATE admin SET `+
			strings.Join(fields, ", ")+
			` WHERE id = ?`,
		args...,
	)

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		utils.Error(w, http.StatusConflict, "update failed")
		return
	}

	affected, err := result.RowsAffected()

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		utils.Error(w, http.StatusInternalServerError, "failed to check update")
		return
	}

	if affected == 0 {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		utils.Error(w, http.StatusNotFound, "admin not found")
		return
	}

	if oldImage.Valid && oldImage.String != "" {
		if removeImage ||
			(imageChanged && oldImage.String != newImage) {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", oldImage.String)
		}
	}

	var updatedAdmin models.Admin

	err = scanAdmin(
		c.DB.QueryRowContext(
			r.Context(),
			adminSelect+` WHERE id = ?`,
			id,
		),
		&updatedAdmin,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get updated admin")
		return
	}

	utils.Success(w, http.StatusOK, "admin profile updated", updatedAdmin)
}

func (c *AdminController) ChangePassword(w http.ResponseWriter, r *http.Request) {
	id := middleware.ID(r)

	var req models.AdminChangePasswordRequest
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
		`SELECT password FROM admin WHERE id = ?`,
		id,
	).Scan(&currentHash)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "admin not found")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to verify admin credentials")
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
		`UPDATE admin
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
         WHERE admin_id = ?
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

	utils.Success(w, http.StatusOK, "admin password changed successfully", nil)
}

func (c *AdminController) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}

	var req models.AdminForgotPasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	phone := strings.TrimSpace(req.Phone)
	if phone == "" {
		utils.Error(w, http.StatusBadRequest, "phone is required")
		return
	}

	const (
		ownerType  = "admin"
		cookieName = "admin_password_recovery"
	)

	genericResponse := func() {
		utils.Success(w, http.StatusOK, "if the account exists, an OTP has been sent", nil)
	}

	ip := getClientIP(r)
	userAgent := r.UserAgent()

	allowed, rateErr := c.allowForgotPassword(ctx, ownerType, phone, ip)
	if rateErr != nil || !allowed {
		genericResponse()
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
				ctx, ownerType, nil, phone, "requested", ip, userAgent,
			); auditErr != nil {
				fmt.Printf("password reset audit failed: %v", auditErr)
			}
			genericResponse()
			return
		}
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
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	if requestCount >= config.MaxForgotPasswordRequests {
		if auditErr := c.auditPasswordReset(
			ctx, ownerType, &userID, phone, "rate_limited", ip, userAgent,
		); auditErr != nil {
			fmt.Printf("password reset audit failed: %v", auditErr)
		}
		genericResponse()
		return
	}

	sessionID, err := utils.RandomRecoverySessionID()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	otp, err := utils.RandomOTP(6)
	if err != nil {
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
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	if err := c.auditPasswordReset(
		ctx, ownerType, &userID, phone, "requested", ip, userAgent,
	); err != nil {
		_ = c.deleteRecoverySession(ctx, sessionID)
		utils.Error(w, http.StatusInternalServerError, "failed to process request")
		return
	}

	message := fmt.Sprintf(
		"My Shop: Your password reset OTP is %s. Valid for 5 minutes.",
		otp,
	)

	if c.Cfg.SMSEnabled {
		_, err = utils.SendSMS(
			c.Cfg.SMSAPIURL,
			c.Cfg.SMSAPIKey,
			phone,
			message,
		)
		if err != nil {
			_ = c.deleteRecoverySession(ctx, sessionID)
			genericResponse()
			return
		}
	} else if strings.EqualFold(c.Cfg.AppEnv, "development") {
		fmt.Printf("[DEV ONLY] user password reset OTP: %s (expires in %d seconds)\n", otp, config.OTPExpirySeconds)
	} else {
		// Never log OTPs outside development. Without an SMS provider, fail closed.
		_ = c.deleteRecoverySession(ctx, sessionID)
		genericResponse()
		return
	}

	utils.SetRecoveryCookie(w, cookieName, sessionID, c.Cfg.RecoveryCookieSecure, config.RecoverySessionTTL)
	genericResponse()
}

func (c *AdminController) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}
	var req models.AdminVerifyOTPRequest
	if !decodeJSON(w, r, &req) { return }

	otp := strings.TrimSpace(req.OTP)
	if !utils.ValidateOTPFormat(otp) {
		utils.Error(w, http.StatusBadRequest, "otp must be 6 digits")
		return
	}

	const ownerType = "admin"
	const cookieName = "admin_password_recovery"
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
			fmt.Printf("admin password reset audit failed: %v\n", err)
		}
		utils.Success(w, http.StatusOK, "otp verified successfully", models.AdminResetTokenResponse{ResetToken: resetToken})
	case 0:
		if err := c.auditPasswordReset(ctx, ownerType, &session.OwnerID, session.Phone, "otp_failed", getClientIP(r), r.UserAgent()); err != nil {
			fmt.Printf("admin password reset audit failed: %v\n", err)
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

func (c *AdminController) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if len(c.Cfg.RecoverySecret) < 32 {
		utils.Error(w, http.StatusServiceUnavailable, "password recovery is not configured")
		return
	}
	var req models.AdminResetPasswordRequest
	if !decodeJSON(w, r, &req) { return }

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

	const ownerType = "admin"
	const cookieName = "admin_password_recovery"
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
				fmt.Printf("admin password reset audit failed: %v\n", auditErr)
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
			fmt.Printf("admin password reset claim release failed: %v\n", releaseErr)
		}
	}
	// Only a valid reset token should trigger the expensive password hash.
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
		`UPDATE admin SET password = ?, version = version + 1, updated_at = ? WHERE id = ?`,
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
		`UPDATE auth_sessions SET revoked_at = ? WHERE admin_id = ? AND revoked_at IS NULL`,
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
		// Commit errors can be ambiguous: keep the claim locked to prevent token replay.
		utils.Error(w, http.StatusInternalServerError, "password reset failed")
		return
	}

	// The token is claimed before the DB transaction, so concurrent reset requests
	// cannot use it. Deleting the Redis key after commit makes it permanently one-time.
	if err := c.consumeResetClaim(ctx, sessionID, tokenHash); err != nil {
		fmt.Printf("admin recovery session consumption failed: %v\n", err)
	}
	utils.ClearRecoveryCookie(w, cookieName, c.Cfg.RecoveryCookieSecure)
	utils.Success(w, http.StatusOK, "password reset successful", nil)
}

func (c *AdminController) CreateAdmin(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin ||
		middleware.Role(r) != config.AdminRoleAdmin {
		utils.Error(w, http.StatusForbidden, "admin role required")
		return
	}

	var q models.AdminCreateRequest
	if !decodeJSON(w, r, &q) {
		return
	}

	if q.Name == "" || q.Phone == "" || q.Password == "" {
		utils.Error(w, http.StatusBadRequest, "name, phone and password are required")
		return
	}

	if err := utils.ValidatePhone(q.Phone); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := utils.ValidatePassword(q.Password); err != nil {
		utils.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	if q.Role != config.AdminRoleAdmin &&
		q.Role != config.AdminRoleManager &&
		q.Role != config.AdminRoleModerator {
		utils.Error(w, http.StatusBadRequest, "invalid admin role")
		return
	}

	hash, err := utils.HashPassword(q.Password)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "password hash failed")
		return
	}

	now := time.Now().Unix()

	result, err := c.DB.ExecContext(
		r.Context(),
		`INSERT INTO admin
		(name,phone,password,type,role,status,version,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`,
		q.Name,
		q.Phone,
		hash,
		config.TypeAdmin,
		q.Role,
		config.StatusActive,
		1,
		now,
		now,
	)

	if err != nil {
		utils.Error(w, http.StatusConflict, "phone already exists")
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get admin id")
		return
	}

	var a models.Admin

	err = scanAdmin(
		c.DB.QueryRowContext(
			r.Context(),
			adminSelect+` WHERE id=?`,
			id,
		),
		&a,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "admin created but could not be loaded")
		return
	}

	utils.Success(w, http.StatusCreated, "admin created", a)
}

func (c *AdminController) GetAdmin(w http.ResponseWriter, r *http.Request) {

	params := utils.GetQueryParams(r, c.Cfg.PaginationLimit)
	qb := utils.NewQueryBuilder()

	allowedSort := map[string]string{
		"id":         "id",
		"name":       "name",
		"phone":      "phone",
		"email":      "email",
		"role":       "role",
		"created_at": "created_at",
		"updated_at": "updated_at",
	}

	if params.Search != "" {
		search := "%" + params.Search + "%"
		qb.Add(`(name LIKE ? OR phone LIKE ? OR email LIKE ?)`,
			search, search, search,
		)
	}

	where := qb.Where()

	var total int

	countQuery := `SELECT COUNT(*) FROM admin` + where

	if err := c.DB.QueryRowContext(
		r.Context(),
		countQuery,
		qb.Args...,
	).Scan(&total); err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to count admins")
		return
	}

	orderBy := utils.GetOrder(params.Sort, params.Order, allowedSort, "id")

	query := adminSelect + where + orderBy + ` LIMIT ? OFFSET ?`
	args := append(qb.Args, params.Limit, params.Offset)

	rows, err := c.DB.QueryContext(
		r.Context(),
		query,
		args...,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to fetch admins")
		return
	}
	defer rows.Close()

	admins := make([]models.Admin, 0)

	for rows.Next() {
		var a models.Admin

		if err := scanAdmin(rows, &a); err != nil {
			utils.Error(w, http.StatusInternalServerError, "failed to read admins")
			return
		}

		admins = append(admins, a)
	}

	if err := rows.Err(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to read admins")
		return
	}

	pagination := utils.CalculatePagination(params.Page, params.Limit, total)

	utils.Success(w, http.StatusOK, "admins fetched successfully",
		map[string]interface{}{
			"admins":     admins,
			"pagination": pagination,
		},
	)
}

func (c *AdminController) GetAdminByID(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")

	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid admin id")
		return
	}

	var a models.Admin

	err = scanAdmin(
		c.DB.QueryRowContext(r.Context(), adminSelect+` WHERE id=?`, id), &a,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "admin not found")
			return
		}

		utils.Error(w, http.StatusInternalServerError, "failed to get admin")
		return
	}

	utils.Success(w, http.StatusOK, "admin fetched successfully", a)
}

func (c *AdminController) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	adminID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || adminID <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid admin id")
		return
	}

	var q models.AdminUpdateRequest
	var newImage string
	var oldImage sql.NullString
	var imageChanged, removeImage bool

	err = c.DB.QueryRowContext(ctx,
		`SELECT image FROM admin WHERE id = ?`,
		adminID).Scan(&oldImage)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "admin not found")
		} else {
			utils.Error(w, http.StatusInternalServerError, "failed to get admin")
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

		if _, ok := r.Form["role"]; ok {
			v := r.FormValue("role")
			if v != "" {
				role, err := strconv.Atoi(v)
				if err != nil {
					utils.Error(w, http.StatusBadRequest, "invalid role")
					return
				}
				q.Role = &role
			}
		}

		file, header, fileErr := r.FormFile("image")

		if fileErr == nil {
			newImage, err = utils.SaveImage(
				file,
				header,
				c.Cfg.StoragePath,
				"admin",
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
				_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
			}
			utils.Error(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if q.Role != nil {
		if *q.Role < config.AdminRoleAdmin ||
			*q.Role > config.AdminRoleModerator {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
			}
			utils.Error(w, http.StatusBadRequest, "invalid admin role")
			return
		}
	}

	fields := make([]string, 0, 11)
	args := make([]any, 0, 12)

	add := func(column string, value *string) {
		if value != nil {
			fields = append(fields, column+" = ?")
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

	if q.Role != nil {
		fields = append(fields, "role = ?")
		args = append(args, *q.Role)
	}

	if removeImage {
		fields = append(fields, "image = NULL")
	} else if imageChanged {
		fields = append(fields, "image = ?")
		args = append(args, newImage)
	} else if q.Image != nil {
		fields = append(fields, "image = ?")
		args = append(args, *q.Image)
	}

	if len(fields) == 0 {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		utils.Error(w, http.StatusBadRequest, "nothing to update")
		return
	}

	fields = append(fields, "updated_at = ?")
	args = append(args, time.Now().Unix(), adminID)

	result, err := c.DB.ExecContext(ctx,
		`UPDATE admin SET `+strings.Join(fields, ", ")+` WHERE id = ?`,
		args...,
	)

	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		var mysqlErr *mysql.MySQLError
		if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
			utils.Error(w, http.StatusConflict, "phone number already exists")
			return
		}

		utils.Error(w, http.StatusInternalServerError, "failed to update admin")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		if imageChanged {
			_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
		}

		utils.Error(w, http.StatusInternalServerError, "failed to check update")
		return
	}

	if affected == 0 {
		var exists bool

		err = c.DB.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM admin WHERE id = ?)`,
			adminID).Scan(&exists)

		if err != nil {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
			}

			utils.Error(w, http.StatusInternalServerError, "failed to verify admin")
			return
		}

		if !exists {
			if imageChanged {
				_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", newImage)
			}

			utils.Error(w, http.StatusNotFound, "admin not found")
			return
		}
	}

	if (imageChanged || removeImage) && oldImage.Valid && oldImage.String != "" {
		if err := utils.DeleteImage(
			c.Cfg.StoragePath,
			"admin",
			oldImage.String,
		); err != nil {
			utils.Error(w, http.StatusInternalServerError, "admin updated but old image deletion failed")
			return
		}
	}

	var updatedAdmin models.Admin

	err = scanAdmin(
		c.DB.QueryRowContext(ctx, adminSelect+` WHERE id = ?`, adminID),
		&updatedAdmin,
	)

	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to get updated admin")
		return
	}

	utils.Success(w, http.StatusOK, "admin updated successfully", updatedAdmin)
}

func (c *AdminController) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin ||
		middleware.Role(r) != config.AdminRoleAdmin {
		utils.Error(w, http.StatusForbidden, "admin role required")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid admin id")
		return
	}

	currentAdminID := middleware.ID(r)
	if currentAdminID == id {
		utils.Error(w, http.StatusForbidden, "you cannot change your own status")
		return
	}

	var q models.AdminStatusRequest
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
		`UPDATE admin
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
		utils.Error(w, http.StatusNotFound, "admin not found")
		return
	}

	if q.Status != config.StatusActive {
		_, err = c.DB.ExecContext(
			r.Context(),
			`UPDATE auth_sessions
			 SET revoked_at = ?
			 WHERE admin_id = ?
			   AND revoked_at IS NULL`,
			now, id,
		)
		if err != nil {
			utils.Error(w, http.StatusInternalServerError, "status updated but session revocation failed")
			return
		}
	}

	var a models.Admin
	if err := scanAdmin(
		c.DB.QueryRowContext(
			r.Context(),
			adminSelect+` WHERE id = ?`,
			id,
		),
		&a,
	); err != nil {
		utils.Error(w, http.StatusInternalServerError, "status updated but could not be loaded")
		return
	}

	utils.Success(w, http.StatusOK, "admin status updated successfully", a)
}

func (c *AdminController) Delete(w http.ResponseWriter, r *http.Request) {
	if middleware.Type(r) != config.TypeAdmin ||
		middleware.Role(r) != config.AdminRoleAdmin {
		utils.Error(w, http.StatusForbidden, "admin role required")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		utils.Error(w, http.StatusBadRequest, "invalid admin id")
		return
	}

	currentAdminID := middleware.ID(r)
	if currentAdminID == id {
		utils.Error(w, http.StatusForbidden, "you cannot delete your own admin account")
		return
	}

	var image sql.NullString
	err = c.DB.QueryRowContext(
		r.Context(),
		`SELECT image FROM admin WHERE id = ?`,
		id,
	).Scan(&image)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.Error(w, http.StatusNotFound, "admin not found")
			return
		}
		utils.Error(w, http.StatusInternalServerError, "failed to get admin")
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
		 WHERE admin_id = ?
		   AND revoked_at IS NULL`,
		now,
		id,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to revoke admin sessions")
		return
	}

	result, err := tx.ExecContext(
		r.Context(),
		`DELETE FROM admin WHERE id = ?`,
		id,
	)
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "admin delete failed")
		return
	}

	affected, err := result.RowsAffected()
	if err != nil {
		utils.Error(w, http.StatusInternalServerError, "failed to check delete")
		return
	}

	if affected == 0 {
		utils.Error(w, http.StatusNotFound, "admin not found")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.Error(w, http.StatusInternalServerError, "delete failed")
		return
	}

	if image.Valid && image.String != "" {
		_ = utils.DeleteImage(c.Cfg.StoragePath, "admin", image.String)
	}

	utils.Success(w, http.StatusOK, "admin deleted successfully", nil)
}
