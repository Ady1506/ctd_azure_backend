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
	collection  *mongo.Collection
	enrollments *mongo.Collection
}

func NewUserHandler(client *mongo.Client, dbName string) *UserHandler {
	return &UserHandler{
		collection:  client.Database(dbName).Collection("users"),
		enrollments: client.Database(dbName).Collection("enrollments"),
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
		Secure:   false,
		// Path:     "/api",
		Path:     "/",
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
		Secure:   false,
		// Path:     "/api",
		Path:     "/",
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

// EnrollCourse handles student enrollment in a course
func (h *UserHandler) EnrollCourse(w http.ResponseWriter, r *http.Request) {
	var enrollment struct {
		CourseID string `json:"course_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&enrollment); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Get the student ID from the context
	studentID, ok := r.Context().Value("userID").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Convert studentID and courseID to ObjectID
	studentObjID, err := primitive.ObjectIDFromHex(studentID)
	if err != nil {
		http.Error(w, "Invalid student ID", http.StatusBadRequest)
		return
	}
	courseObjID, err := primitive.ObjectIDFromHex(enrollment.CourseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Check if the course exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var course models.Course
	err = h.collection.Database().Collection("courses").FindOne(ctx, bson.M{"_id": courseObjID}).Decode(&course)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Course not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to check course existence", http.StatusInternalServerError)
		}
		return
	}

	// Check if the student is already enrolled in the course
	var existingEnrollment models.Enrollment
	err = h.enrollments.FindOne(ctx, bson.M{"student_id": studentObjID, "course_id": courseObjID}).Decode(&existingEnrollment)
	if err == nil {
		http.Error(w, "Student is already enrolled in this course", http.StatusConflict)
		return
	} else if err != mongo.ErrNoDocuments {
		http.Error(w, "Failed to check enrollment status", http.StatusInternalServerError)
		return
	}

	// Create the enrollment
	newEnrollment := models.Enrollment{
		StudentID:  studentObjID,
		CourseID:   courseObjID,
		EnrolledAt: time.Now(),
		Status:     models.StatusActive,
	}

	// Insert the enrollment into the database
	_, err = h.enrollments.InsertOne(ctx, newEnrollment)
	if err != nil {
		http.Error(w, "Failed to enroll in course", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newEnrollment)
}

// MarkAttendance handles marking attendance for a student in a session
func (h *UserHandler) MarkAttendance(w http.ResponseWriter, r *http.Request) {
	var attendanceRequest struct {
		CourseID string `json:"course_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&attendanceRequest); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Get the student ID from the context
	studentID, ok := r.Context().Value("userID").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Convert studentID and courseID to ObjectID
	studentObjID, err := primitive.ObjectIDFromHex(studentID)
	if err != nil {
		http.Error(w, "Invalid student ID", http.StatusBadRequest)
		return
	}
	courseObjID, err := primitive.ObjectIDFromHex(attendanceRequest.CourseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Find the current session for the course
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var session models.Session
	err = h.collection.Database().Collection("sessions").FindOne(ctx, bson.M{
		"course_id":  courseObjID,
		"start_time": bson.M{"$lte": time.Now()},
		"end_time":   bson.M{"$gte": time.Now()},
	}).Decode(&session)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "No current session found for the course", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to find current session", http.StatusInternalServerError)
		}
		return
	}

	// Check if attendance is already marked for the student in the session
	var existingAttendance models.Attendance
	err = h.collection.Database().Collection("attendances").FindOne(ctx, bson.M{
		"session_id": session.ID,
		"student_id": studentObjID,
	}).Decode(&existingAttendance)
	if err == nil {
		http.Error(w, "Attendance already marked for this session", http.StatusConflict)
		return
	} else if err != mongo.ErrNoDocuments {
		http.Error(w, "Failed to check attendance status", http.StatusInternalServerError)
		return
	}

	// Mark attendance
	newAttendance := models.Attendance{
		SessionID: session.ID,
		StudentID: studentObjID,
		Status:    models.StatusPresent,
		MarkedBy:  studentObjID, // Assuming self-marking for simplicity
		MarkedAt:  time.Now(),
	}

	// Insert the attendance into the database
	_, err = h.collection.Database().Collection("attendances").InsertOne(ctx, newAttendance)
	if err != nil {
		http.Error(w, "Failed to mark attendance", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newAttendance)
}
