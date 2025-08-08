package service

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"time"

	openapi "github.com/PhyuSinKhantAung/go-auth-server/go"
	"github.com/PhyuSinKhantAung/go-auth-server/go/database"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	jwtSecret []byte
}

func NewAuthService() *AuthService {
	return &AuthService{
		jwtSecret: []byte("your-secret-key"), // In production, use environment variable
	}
}

func (s *AuthService) SignupPost(ctx context.Context, request openapi.SignupPostRequest) (openapi.ImplResponse, error) {
	db := database.GetDB()

	// Check if user already exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", request.Email).Scan(&exists)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		return openapi.Response(500, nil), err
	}

	if exists {
		return openapi.Response(400, map[string]string{
			"error": "User already exists",
		}), errors.New("user already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return openapi.Response(500, nil), err
	}

	// Insert user
	_, err = db.Exec("INSERT INTO users (email, password_hash) VALUES ($1, $2)", request.Email, string(hashedPassword))
	if err != nil {
		log.Printf("Error inserting user: %v", err)
		return openapi.Response(500, nil), err
	}

	return openapi.Response(201, nil), nil
}

func (s *AuthService) SigninPost(ctx context.Context, request openapi.SigninPostRequest) (openapi.ImplResponse, error) {
	db := database.GetDB()

	var user struct {
		ID           int
		Email        string
		PasswordHash string
	}

	err := db.QueryRow("SELECT id, email, password_hash FROM users WHERE email = $1", request.Email).
		Scan(&user.ID, &user.Email, &user.PasswordHash)

	if err == sql.ErrNoRows {
		return openapi.Response(401, map[string]string{
			"error": "Invalid credentials",
		}), errors.New("invalid credentials")
	} else if err != nil {
		log.Printf("Error querying user: %v", err)
		return openapi.Response(500, nil), err
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password))
	if err != nil {
		return openapi.Response(401, map[string]string{
			"error": "Invalid credentials",
		}), errors.New("invalid credentials")
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(s.jwtSecret)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		return openapi.Response(500, nil), err
	}

	response := openapi.SigninPost200Response{
		Token: tokenString,
	}

	return openapi.Response(200, response), nil
}

func (s *AuthService) ResetPasswordPost(ctx context.Context, request openapi.ResetPasswordPostRequest) (openapi.ImplResponse, error) {
	db := database.GetDB()

	// In a real application, you would:
	// 1. Generate a password reset token
	// 2. Send it to user's email
	// 3. Create a separate endpoint to handle the actual password reset with the token

	// For this example, we'll just check if the user exists
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)", request.Email).Scan(&exists)
	if err != nil {
		log.Printf("Error checking user existence: %v", err)
		return openapi.Response(500, nil), err
	}

	if !exists {
		return openapi.Response(404, map[string]string{
			"error": "User not found",
		}), errors.New("user not found")
	}

	return openapi.Response(200, map[string]string{
		"message": "Password reset initiated. Please check your email.",
	}), nil
}
