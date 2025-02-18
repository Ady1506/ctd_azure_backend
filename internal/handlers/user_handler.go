package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jas-4484/ctd-backend/internal/auth"
	"github.com/jas-4484/ctd-backend/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	collection *mongo.Collection
}

func NewUserHandler(client *mongo.Client, dbName string) *UserHandler {
	return &UserHandler{
		collection: client.Database(dbName).Collection("users"),
	}
}

// Signup handles user registration
func (h *UserHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var newUser models.User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newUser.Email == "" || newUser.DisplayName == "" || newUser.Password == "" {
		http.Error(w, "Email, display name, and password are required", http.StatusBadRequest)
		return
	}

	// Check if the email already exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var existingUser models.User
	err := h.collection.FindOne(ctx, bson.M{"email": newUser.Email}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Email already exists", http.StatusConflict)
		return
	} else if err != mongo.ErrNoDocuments {
		http.Error(w, "Failed to check email availability", http.StatusInternalServerError)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	newUser.Password = string(hashedPassword)

	// Set default values
	newUser.ID = primitive.NewObjectID()
	newUser.CreatedAt = time.Now()
	newUser.UpdatedAt = time.Now()
	newUser.Settings = models.UserSettings{
		Theme:         "light", // Default theme
		Notifications: true,    // Enable notifications by default
	}

	// Insert the new user into the database
	_, err = h.collection.InsertOne(ctx, newUser)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Generate JWT on user signup
	token, _ := auth.GenerateJWT(newUser.ID.Hex(), string(newUser.Role))
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newUser)
}

// Signin handles user login
func (h *UserHandler) Signin(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Find the user by email
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := h.collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Compare the provided password with the stored hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT on user login
	token, _ := auth.GenerateJWT(user.ID.Hex(), string(user.Role))
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find all users
	cursor, err := h.collection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch users", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		http.Error(w, "Error decoding users", http.StatusInternalServerError)
		return
	}

	// Return users as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}
