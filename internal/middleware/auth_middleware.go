package middleware

import (
	"net/http"
	"strings"

	"github.com/jas-4484/ctd-backend/internal/auth"
)

func AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := auth.ValidateJWT(tokenString)
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the user is an admin
		if claims.Role != "admin" {
			http.Error(w, "Access denied: Admins only", http.StatusForbidden)
			return
		}

		// Call next handler
		next.ServeHTTP(w, r)
	})
}
