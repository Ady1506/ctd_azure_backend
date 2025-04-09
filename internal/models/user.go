package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleStudent UserRole = "student"
)

type UserSettings struct {
	Theme         string `json:"theme" bson:"theme"`
	Notifications bool   `json:"notifications" bson:"notifications"`
}
type User struct {
	ID                primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email             string             `json:"email" bson:"email"`
	Roll              int                `json:"roll" bson:"roll"`
	Branch            string             `json:"branch" bson:"branch"`
	Year              int                `json:"year" bson:"year"`
	Mobile            int                `json:"mobile" bson:"mobile"`
	DisplayName       string             `json:"display_name" bson:"display_name"`
	Password          string             `json:"password" bson:"password"`
	ProfileURL        string             `json:"profile_url" bson:"profile_url"`
	Role              UserRole           `json:"role" bson:"role"`
	CreatedAt         time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at" bson:"updated_at"`
	Settings          UserSettings       `json:"settings" bson:"settings"`
	IsVerified        bool               `json:"is_verified" bson:"is_verified"`
	VerificationToken string             `json:"verification_token" bson:"verification_token"`
}
