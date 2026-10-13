package routes

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"

	"my_ecom_api/config"
	"my_ecom_api/controllers"
	"my_ecom_api/middleware"
	"my_ecom_api/redis"
)

func Setup(db *sql.DB, cfg *config.Config, redisClient *redis.Client) http.Handler {

	r := chi.NewRouter()

	AuthRecoveryController := &controllers.AuthRecoveryController{DB: db, Cfg: cfg, RDB: redisClient.RDB}
	userController := &controllers.UserController{DB: db, Cfg: cfg, AuthRecoveryController: AuthRecoveryController}
	adminController := &controllers.AdminController{DB: db, Cfg: cfg, AuthRecoveryController: AuthRecoveryController}
	productController := &controllers.ProductController{DB: db, Cfg: cfg}

	auth := middleware.Require(cfg, db)
	userOnly := middleware.RequireType(config.TypeUser)

	onlyAdmin := middleware.RequireAdminRole(config.AdminRoleAdmin)
	adminAndManager := middleware.RequireAdminRole(config.AdminRoleAdmin, config.AdminRoleManager)
	allAdminRoles := middleware.RequireAdminRole(config.AdminRoleAdmin, config.AdminRoleManager, config.AdminRoleModerator)

	r.Route("/api/v1", func(r chi.Router) {

		r.Route("/users", func(r chi.Router) {
			r.Post("/register", userController.Register)
			r.Post("/login", userController.Login)
			r.Post("/logout", userController.Logout)

			r.Post("/forgot-password", userController.ForgotPassword)
			r.Post("/verify-otp", userController.VerifyOTP)
			r.Post("/reset-password", userController.ResetPassword)

			r.With(auth, userOnly).Get("/me", userController.GetMe)
			r.With(auth, userOnly).Put("/me", userController.UpdateMe)
			r.With(auth, userOnly).Post("/password/change", userController.ChangePassword)

			r.With(auth, allAdminRoles).Get("/", userController.GetUsers)
			r.With(auth, allAdminRoles).Get("/{id}", userController.GetUserById)
			r.With(auth, adminAndManager).Put("/{id}", userController.Update)
			r.With(auth, adminAndManager).Patch("/{id}/status", userController.UpdateStatus)
			r.With(auth, onlyAdmin).Delete("/{id}", userController.Delete)
			r.With(auth, onlyAdmin).Post("/force-logout", userController.ForceAllLogout)
		})

		r.Route("/admin", func(r chi.Router) {
			r.Post("/login", adminController.Login)
			r.Post("/logout", adminController.Logout)

			r.Post("/forgot-password", adminController.ForgotPassword)
			r.Post("/verify-otp", adminController.VerifyOTP)
			r.Post("/reset-password", adminController.ResetPassword)

			r.With(auth, allAdminRoles).Get("/me", adminController.GetMe)
			r.With(auth, allAdminRoles).Put("/me", adminController.UpdateMe)
			r.With(auth, allAdminRoles).Post("/password/change", adminController.ChangePassword)

			r.With(auth, adminAndManager).Get("/", adminController.GetAdmin)
			r.With(auth, adminAndManager).Get("/{id}", adminController.GetAdminByID)
			r.With(auth, onlyAdmin).Post("/create", adminController.CreateAdmin)
			r.With(auth, onlyAdmin).Put("/{id}", adminController.Update)
			r.With(auth, onlyAdmin).Patch("/{id}/status", adminController.UpdateStatus)
			r.With(auth, onlyAdmin).Delete("/{id}", adminController.Delete)
		})

		r.Route("/products", func(r chi.Router) {
			r.Get("/", productController.GetAll)
			r.Get("/{id}", productController.GetByID)
			r.With(auth, adminAndManager).Post("/", productController.Create)
			r.With(auth, adminAndManager).Put("/{id}", productController.Update)
			r.With(auth, adminAndManager).Patch("/{id}/status", productController.UpdateStatus)
			r.With(auth, adminAndManager).Delete("/{id}", productController.Delete)
		})
	})

	return r
}
