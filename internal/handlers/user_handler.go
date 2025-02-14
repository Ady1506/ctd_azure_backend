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
	if newUser.Email == "" || newUser.DisplayName == "" {
		http.Error(w, "Email and display name are required", http.StatusBadRequest)
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

	// Return the created user
	// Generate JWT on user signup or login
	token, _ := auth.GenerateJWT(newUser.ID.Hex(), string(newUser.Role))
	w.Header().Set("Authorization", "Bearer "+token)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newUser)
}

// GetUsers retrieves all users from the database
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
