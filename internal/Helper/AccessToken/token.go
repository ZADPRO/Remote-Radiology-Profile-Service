package accesstoken

import (
	logger "ProfileService/internal/Helper/Logger"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// CreateToken generates a JWT token for a given user ID and expiration duration.
func CreateToken(id any, roleId any, branchid any) string {
	jwtKey := []byte(os.Getenv("ACCESS_TOKEN"))
	claims := jwt.MapClaims{
		"id":       id,
		"roleId":   roleId,
		"branchId": branchid,
		"exp":      time.Now().Add(20 * time.Minute).Unix(), // expires after 'exp' duration
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("Error creating token:", err)
		return "Invalid Token"
	}

	return tokenString
}

// ValidateJWT validates the JWT token and checks if it is expired.
func ValidateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(os.Getenv("ACCESS_TOKEN")), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		expFloat, ok := claims["exp"].(float64)
		if !ok {
			return nil, fmt.Errorf("invalid exp type")
		}

		expTime := time.Unix(int64(expFloat), 0)
		if time.Now().After(expTime) {
			return nil, fmt.Errorf("token expired at %s", expTime.Format(time.RFC3339))
		}

		fmt.Println("Token valid for user ID:", claims["id"])
	}

	return token, nil
}

// JWTMiddleware protects routes by validating JWT tokens from the Authorization header.
func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		log := logger.InitLogger()

		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			log.Error("Missing Token")
			c.JSON(200, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		// Validate the JWT token
		token, err := ValidateJWT(tokenString)
		if err != nil {
			if strings.Contains(err.Error(), "token expired") {
				log.Error("Token Expired")
				c.JSON(200, gin.H{"error": "Token expired"})
				c.Abort()
				return
			}
			log.Error("Invalid Token")
			c.JSON(200, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Extract the claims (user info) and set it in the context
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Set the claims in the context
			c.Set("id", claims["id"])
			c.Set("roleId", claims["roleId"])
			c.Set("branchId", claims["branchId"])
			c.Set("token", tokenString)
		}

		// Proceed to the next handler if the token is valid
		c.Next()
	}
}
