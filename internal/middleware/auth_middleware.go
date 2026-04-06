package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Arisgod1/zkp_rkp_go/internal/auth"
)

func AuthMiddleware(jwtManager *auth.JWTManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		username, err := jwtManager.ParseToken(tokenStr)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Set("username", username)
		c.Next()
	}
}
