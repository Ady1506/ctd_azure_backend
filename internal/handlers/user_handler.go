package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jas-4484/ctd-backend/internal/auth"
	"github.com/jas-4484/ctd-backend/internal/models"
	"github.com/jas-4484/ctd-backend/internal/utils"
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

func GenerateVerificationToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Signup handles user registration
// Signup handles user registration
func (h *UserHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var newUser models.User
	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newUser.Email == "" || newUser.DisplayName == "" || newUser.Password == "" || newUser.Roll == 0 || newUser.Branch == "" || newUser.Year == 0 || newUser.Mobile == 0 || newUser.Role == "" {
		http.Error(w, "Email, display name, password, roll, branch, year, and mobile are required", http.StatusBadRequest)
		return
	}

	if !strings.HasSuffix(newUser.Email, "@thapar.edu") {
		http.Error(w, "Email must end with @thapar.edu", http.StatusBadRequest)
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

	// Generate a verification token
	verificationToken, err := GenerateVerificationToken()
	if err != nil {
		http.Error(w, "Failed to generate verification token", http.StatusInternalServerError)
		return
	}
	newUser.VerificationToken = verificationToken
	newUser.IsVerified = false

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

	// Send verification email
	verificationURL := "http://localhost:8000/api/users/verify?token=" + verificationToken
	emailBody := `
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f4f4f9;
                color: #333;
                line-height: 1.6;
                margin: 0;
                padding: 0;
            }
            .container {
                max-width: 600px;
                margin: 20px auto;
                background: #ffffff;
                border-radius: 8px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }
            .header {
                background-color: #003366; /* Primary dark blue */
                color: #ffffff;
                padding: 20px;
                text-align: center;
            }
            .header h1 {
                margin: 0;
                font-size: 24px;
            }
            .content {
                padding: 20px;
            }
            .content p {
                margin: 10px 0;
            }
            .button {
                display: inline-block;
                background-color: #0073e6; /* Light blue accent */
                color: #ffffff;
                font-weight:bold;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                font-size: 16px;
                margin-top: 20px;
            }
            .footer {
                background-color: #f4f4f9;
                color: #666;
                text-align: center;
                padding: 10px;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Email Verification</h1>
            </div>
            <div class="content">
                <p>Hi ` + newUser.DisplayName + `,</p>
                <p>Thank you for signing up! Please verify your email by clicking the button below:</p>
                <a href="` + verificationURL + `" class="button">Verify Email</a>
                <p>If you did not sign up for this account, you can safely ignore this email.</p>
            </div>
            <div class="footer">
                <p>&copy; Centre For Training & Development. All rights reserved.</p>
            </div>
        </div>
    </body>
    </html>`
	go func() {
		if err := utils.SendEmail(newUser.Email, "Email Verification", emailBody); err != nil {
			http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		}
	}()

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newUser)
}

func (h *UserHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Verification token is required", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Find the user with the given token
	var user models.User
	err := h.collection.FindOne(ctx, bson.M{"verification_token": token}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Invalid or expired verification token", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		}
		return
	}

	// Update the user's verification status
	_, err = h.collection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$set": bson.M{
			"is_verified":        true,
			"verification_token": "",
		},
	})
	if err != nil {
		http.Error(w, "Failed to update verification status", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Email verified successfully"))
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

	// Check if the user is verified
	if !user.IsVerified {
		http.Error(w, "Email not verified", http.StatusForbidden)
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
		Path: "/",
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// ForgotPassword handles password reset requests
func (h *UserHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Check if the user exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := h.collection.FindOne(ctx, bson.M{"email": request.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Email not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to process request", http.StatusInternalServerError)
		}
		return
	}

	// Generate a new verification token
	verificationToken, err := GenerateVerificationToken()
	if err != nil {
		http.Error(w, "Failed to generate reset token", http.StatusInternalServerError)
		return
	}

	// Update the user's verification token
	_, err = h.collection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$set": bson.M{
			"verification_token": verificationToken,
		},
	})
	if err != nil {
		http.Error(w, "Failed to update reset token", http.StatusInternalServerError)
		return
	}

	// Send password reset email
	resetURL := "http://localhost:8000/api/users/reset-password?token=" + verificationToken
	emailBody := `
    <h1>Password Reset</h1>
    <p>Hi ` + user.DisplayName + `,</p>
    <p>You requested to reset your password. Click the link below to reset it:</p>
    <a href="` + resetURL + `">Reset Password</a>
    <p>If you did not request this, you can safely ignore this email.</p>`
	go func() {
		if err := utils.SendEmail(user.Email, "Password Reset", emailBody); err != nil {
			http.Error(w, "Failed to send reset email", http.StatusInternalServerError)
		}
	}()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password reset email sent"))
}

// ResetPassword handles resetting the user's password
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Reset token is required", http.StatusBadRequest)
		return
	}

	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the new password
	if len(request.NewPassword) < 6 {
		http.Error(w, "Password must be at least 6 characters long", http.StatusBadRequest)
		return
	}

	// Find the user with the given token
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user models.User
	err := h.collection.FindOne(ctx, bson.M{"verification_token": token}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Invalid or expired reset token", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to process request", http.StatusInternalServerError)
		}
		return
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Update the user's password and clear the verification token
	_, err = h.collection.UpdateOne(ctx, bson.M{"_id": user.ID}, bson.M{
		"$set": bson.M{
			"password":           string(hashedPassword),
			"verification_token": "",
		},
	})
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Password reset successfully"))
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

// CurrentUser returns the currently authenticated user's details
func (h *UserHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}

	var user models.User
	err = h.collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Return the user details (you can omit password field if needed)
	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Logout handles user logout
func (h *UserHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Unix(0, 0), // Expire immediately
		MaxAge:   -1,
	})
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Logged out successfully"))
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

// MarkAttendance handles marking attendance for a student based on the course schedule
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

	// Check if the student is enrolled in the course
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var enrollment models.Enrollment
	err = h.enrollments.FindOne(ctx, bson.M{"student_id": studentObjID, "course_id": courseObjID}).Decode(&enrollment)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Student is not enrolled in this course", http.StatusForbidden)
		} else {
			http.Error(w, "Failed to check enrollment status", http.StatusInternalServerError)
		}
		return
	}

	// Fetch the course details
	var course models.Course
	err = h.collection.Database().Collection("courses").FindOne(ctx, bson.M{"_id": courseObjID}).Decode(&course)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Course not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to fetch course details", http.StatusInternalServerError)
		}
		return
	}

	// Validate the current time against the course schedule
	currentTime := time.Now()
	currentDay := currentTime.Weekday().String()[:3] // Get the current day (e.g., "Mon", "Tue")
	currentHour := currentTime.Format("3:04 PM")     // Get the current time in "HH:MM AM/PM" format

	// Check if the current day is in the course schedule
	isDayValid := false
	for _, day := range course.Schedule.Days {
		if strings.EqualFold(day, currentDay) {
			isDayValid = true
			break
		}
	}
	if !isDayValid {
		http.Error(w, "Attendance cannot be marked outside the scheduled days", http.StatusForbidden)
		return
	}

	// Check if the current time falls within the scheduled time range
	if currentHour < course.Schedule.StartTime || currentHour > course.Schedule.EndTime {
		http.Error(w, "Attendance cannot be marked outside the scheduled time", http.StatusForbidden)
		return
	}

	// Check if attendance is already marked for the student on the current day
	var existingAttendance models.Attendance
	err = h.collection.Database().Collection("attendances").FindOne(ctx, bson.M{
		"course_id":  courseObjID,
		"student_id": studentObjID,
		"marked_at": bson.M{
			"$gte": time.Date(currentTime.Year(), currentTime.Month(), currentTime.Day(), 0, 0, 0, 0, currentTime.Location()),
			"$lt":  time.Date(currentTime.Year(), currentTime.Month(), currentTime.Day()+1, 0, 0, 0, 0, currentTime.Location()),
		},
	}).Decode(&existingAttendance)
	if err == nil {
		http.Error(w, "Attendance already marked for today", http.StatusConflict)
		return
	} else if err != mongo.ErrNoDocuments {
		http.Error(w, "Failed to check attendance status", http.StatusInternalServerError)
		return
	}

	// Mark attendance
	newAttendance := models.Attendance{
		ID:        primitive.NewObjectID(),
		SessionID: primitive.NilObjectID, // No session ID since it's based on schedule
		StudentID: studentObjID,
		Status:    models.StatusPresent,
		MarkedBy:  studentObjID, // Assuming self-marking for simplicity
		MarkedAt:  currentTime,
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
func (h *UserHandler) GetNoticesForEnrolledCourses(w http.ResponseWriter, r *http.Request) {
	// Get the student ID from the context (set by middleware)
	studentID, ok := r.Context().Value("userID").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Convert studentID to ObjectID
	studentObjID, err := primitive.ObjectIDFromHex(studentID)
	if err != nil {
		http.Error(w, "Invalid student ID", http.StatusBadRequest)
		return
	}

	// Fetch enrollments for the student
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	enrollmentsCursor, err := h.enrollments.Find(ctx, bson.M{"student_id": studentObjID})
	if err != nil {
		http.Error(w, "Failed to fetch enrollments", http.StatusInternalServerError)
		return
	}
	defer enrollmentsCursor.Close(ctx)

	var enrollments []models.Enrollment
	if err = enrollmentsCursor.All(ctx, &enrollments); err != nil {
		http.Error(w, "Error decoding enrollments", http.StatusInternalServerError)
		return
	}

	// Extract course IDs from enrollments
	courseIDs := make([]primitive.ObjectID, len(enrollments))
	for i, enrollment := range enrollments {
		courseIDs[i] = enrollment.CourseID
	}

	// Fetch notices for the enrolled courses
	noticesCursor, err := h.collection.Database().Collection("notices").Find(ctx, bson.M{"course_id": bson.M{"$in": courseIDs}})
	if err != nil {
		http.Error(w, "Failed to fetch notices", http.StatusInternalServerError)
		return
	}
	defer noticesCursor.Close(ctx)

	var notices []models.Notice
	if err = noticesCursor.All(ctx, &notices); err != nil {
		http.Error(w, "Error decoding notices", http.StatusInternalServerError)
		return
	}

	// Fetch course details for the enrolled courses
	coursesCursor, err := h.collection.Database().Collection("courses").Find(ctx, bson.M{"_id": bson.M{"$in": courseIDs}})
	if err != nil {
		http.Error(w, "Failed to fetch courses", http.StatusInternalServerError)
		return
	}
	defer coursesCursor.Close(ctx)

	courseMap := make(map[primitive.ObjectID]string)
	var courses []models.Course
	if err = coursesCursor.All(ctx, &courses); err != nil {
		http.Error(w, "Error decoding courses", http.StatusInternalServerError)
		return
	}

	// Map course IDs to course names
	for _, course := range courses {
		courseMap[course.ID] = course.Name
	}

	// Combine notices with course names
	type NoticeWithCourseName struct {
		ID         primitive.ObjectID `json:"id"`
		CourseID   primitive.ObjectID `json:"course_id"`
		CourseName string             `json:"course_name"`
		Content    string             `json:"content"`
		Link       string             `json:"link,omitempty"`
		CreatedAt  time.Time          `json:"created_at"`
	}

	var response []NoticeWithCourseName
	for _, notice := range notices {
		response = append(response, NoticeWithCourseName{
			ID:         notice.ID,
			CourseID:   notice.CourseID,
			CourseName: courseMap[notice.CourseID],
			Content:    notice.Content,
			Link:       notice.Link,
			CreatedAt:  notice.CreatedAt,
		})
	}

	// Return the response as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
