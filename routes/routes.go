package routes

import (
	"database/sql"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"my_ecom_api/config"
	"my_ecom_api/controllers"
	appmw "my_ecom_api/middleware"
	"my_ecom_api/redis"
)

func Setup(db *sql.DB, cfg *config.Config, redisClient *redis.Client) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(securityHeaders)

	authRecoveryController := &controllers.AuthRecoveryController{
		DB:  db,
		Cfg: cfg,
		RDB: redisClient.RDB,
	}

	userController := &controllers.UserController{
		DB:                     db,
		Cfg:                    cfg,
		AuthRecoveryController: authRecoveryController,
	}

	adminController := &controllers.AdminController{
		DB:                     db,
		Cfg:                    cfg,
		AuthRecoveryController: authRecoveryController,
	}

	productController := &controllers.ProductController{
		DB:  db,
		Cfg: cfg,
	}

	auth := appmw.Require(cfg, db)
	userOnly := appmw.RequireType(config.TypeUser)

	onlyAdmin := appmw.RequireAdminRole(
		config.AdminRoleAdmin,
	)

	adminAndManager := appmw.RequireAdminRole(
		config.AdminRoleAdmin,
		config.AdminRoleManager,
	)

	allAdminRoles := appmw.RequireAdminRole(
		config.AdminRoleAdmin,
		config.AdminRoleManager,
		config.AdminRoleModerator,
	)

	r.Route("/api/v1", func(r chi.Router) {

		r.Route("/admin", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Post("/login", adminController.Login)
				r.Post("/forgot-password", adminController.ForgotPassword)
				r.Post("/verify-otp", adminController.VerifyOTP)
				r.Post("/reset-password", adminController.ResetPassword)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, allAdminRoles)
				r.Post("/logout", adminController.Logout)
				r.Get("/me", adminController.GetMe)
				r.Put("/me", adminController.UpdateMe)
				r.Post("/password/change", adminController.ChangePassword)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, adminAndManager)
				r.Get("/", adminController.GetAdmin)
				r.Get("/{id}", adminController.GetAdminByID)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, onlyAdmin)
				r.Post("/create", adminController.CreateAdmin)
				r.Put("/{id}", adminController.Update)
				r.Patch("/{id}/status", adminController.UpdateStatus)
				r.Delete("/{id}", adminController.Delete)
			})
		})

		r.Route("/users", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Post("/register", userController.Register)
				r.Post("/login", userController.Login)
				r.Post("/forgot-password", userController.ForgotPassword)
				r.Post("/verify-otp", userController.VerifyOTP)
				r.Post("/reset-password", userController.ResetPassword)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, userOnly)
				r.Post("/logout", userController.Logout)
				r.Get("/me", userController.GetMe)
				r.Put("/me", userController.UpdateMe)
				r.Post("/password/change", userController.ChangePassword)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, allAdminRoles)
				r.Get("/", userController.GetUsers)
				r.Get("/{id}", userController.GetUserById)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, adminAndManager)
				r.Put("/{id}", userController.Update)
				r.Patch("/{id}/status", userController.UpdateStatus)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, onlyAdmin)
				r.Delete("/{id}", userController.Delete)
				r.Post("/force-logout", userController.ForceAllLogout)
			})
		})

		r.Route("/products", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Get("/", productController.GetAll)
				r.Get("/{id}", productController.GetByID)
			})

			r.Group(func(r chi.Router) {
				r.Use(auth, allAdminRoles)
				r.Post("/", productController.Create)
				r.Put("/{id}", productController.Update)
				r.Patch("/{id}/status", productController.UpdateStatus)
				r.Delete("/{id}", productController.Delete)
			})
		})
	})

	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
