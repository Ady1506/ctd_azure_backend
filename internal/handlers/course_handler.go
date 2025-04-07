package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jas-4484/ctd-backend/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

type CourseHandler struct {
	collection *mongo.Collection
}

func NewCourseHandler(client *mongo.Client, dbName string) *CourseHandler {
	return &CourseHandler{
		collection: client.Database(dbName).Collection("courses"),
	}
}

// CreateCourse handles creating a new course
func (h *CourseHandler) CreateCourse(w http.ResponseWriter, r *http.Request) {
	var newCourse models.Course
	if err := json.NewDecoder(r.Body).Decode(&newCourse); err != nil {
		log.Print(err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newCourse.Name == "" || newCourse.Subject == "" || newCourse.CreatedBy == primitive.NilObjectID {
		http.Error(w, "Course name, subject, and created_by are required", http.StatusBadRequest)
		return
	}

	// Set default values
	newCourse.ID = primitive.NewObjectID()
	newCourse.CreatedAt = time.Now()
	newCourse.Archived = false

	// Insert into database
	_, err := h.collection.InsertOne(context.TODO(), newCourse)
	if err != nil {
		http.Error(w, "Failed to create course", http.StatusInternalServerError)
		return
	}

	// Return the created course
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newCourse)
}

// GetCourses retrieves all courses
func (h *CourseHandler) GetCourses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := h.collection.Find(ctx, bson.M{"archived": false})
	if err != nil {
		http.Error(w, "Failed to fetch courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var courses []models.Course
	if err = cursor.All(ctx, &courses); err != nil {
		http.Error(w, "Error decoding courses", http.StatusInternalServerError)
		return
	}

	// Return courses as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(courses)
}

// UpdateCourse updates course details
func (h *CourseHandler) UpdateCourse(w http.ResponseWriter, r *http.Request) {
	courseID := r.URL.Query().Get("id")
	if courseID == "" {
		http.Error(w, "Course ID is required", http.StatusBadRequest)
		return
	}

	var updatedCourse models.Course
	if err := json.NewDecoder(r.Body).Decode(&updatedCourse); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Convert courseID to ObjectID
	objID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Update fields
	update := bson.M{
		"$set": bson.M{
			"name":           updatedCourse.Name,
			"subject":        updatedCourse.Subject,
			"schedule":       updatedCourse.Schedule,
			"duration_weeks": updatedCourse.DurationWeeks,
			"meeting_link":   updatedCourse.MeetingLink,
			"updated_at":     time.Now(),
		},
	}

	_, err = h.collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, update)
	if err != nil {
		http.Error(w, "Failed to update course", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Course updated successfully"))
}

// DeleteCourse deletes a course
func (h *CourseHandler) DeleteCourse(w http.ResponseWriter, r *http.Request) {
	courseID := r.URL.Query().Get("id")
	if courseID == "" {
		http.Error(w, "Course ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	_, err = h.collection.DeleteOne(context.TODO(), bson.M{"_id": objID})
	if err != nil {
		http.Error(w, "Failed to delete course", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Course deleted successfully"))
}

// ArchiveCourse marks a course as archived
func (h *CourseHandler) ArchiveCourse(w http.ResponseWriter, r *http.Request) {
	courseID := r.URL.Query().Get("id")
	if courseID == "" {
		http.Error(w, "Course ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	_, err = h.collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, bson.M{"$set": bson.M{"archived": true}})
	if err != nil {
		http.Error(w, "Failed to archive course", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Course archived successfully"))
}

// CreateSession handles creating a new session for a course
func (h *CourseHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	var newSession models.Session
	if err := json.NewDecoder(r.Body).Decode(&newSession); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newSession.CourseID == primitive.NilObjectID || newSession.StartTime.IsZero() || newSession.EndTime.IsZero() {
		http.Error(w, "CourseID, StartTime, and EndTime are required", http.StatusBadRequest)
		return
	}

	// Set default values
	newSession.ID = primitive.NewObjectID()

	// Insert into database
	_, err := h.collection.Database().Collection("sessions").InsertOne(context.TODO(), newSession)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Return the created session
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newSession)
}

// AssignTutor handles assigning a tutor to a course
func (h *CourseHandler) AssignTutor(w http.ResponseWriter, r *http.Request) {
	var assignment struct {
		TutorID  string `json:"tutor_id"`
		CourseID string `json:"course_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Convert TutorID and CourseID to ObjectID
	tutorObjID, err := primitive.ObjectIDFromHex(assignment.TutorID)
	if err != nil {
		http.Error(w, "Invalid tutor ID", http.StatusBadRequest)
		return
	}
	courseObjID, err := primitive.ObjectIDFromHex(assignment.CourseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Get the admin ID from the context
	adminID, ok := r.Context().Value("userID").(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	adminObjID, err := primitive.ObjectIDFromHex(adminID)
	if err != nil {
		http.Error(w, "Invalid admin ID", http.StatusBadRequest)
		return
	}

	// Check if the course exists
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var course models.Course
	err = h.collection.FindOne(ctx, bson.M{"_id": courseObjID}).Decode(&course)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Course not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to check course existence", http.StatusInternalServerError)
		}
		return
	}

	// Check if the tutor exists
	var tutor models.User
	err = h.collection.Database().Collection("users").FindOne(ctx, bson.M{"_id": tutorObjID, "role": models.RoleTutor}).Decode(&tutor)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Tutor not found", http.StatusNotFound)
		} else {
			http.Error(w, "Failed to check tutor existence", http.StatusInternalServerError)
		}
		return
	}

	// Create the tutor assignment
	newAssignment := models.TutorAssignment{
		TutorID:    tutorObjID,
		CourseID:   courseObjID,
		AssignedBy: adminObjID,
		AssignedAt: time.Now(),
	}

	// Insert the assignment into the database
	_, err = h.collection.Database().Collection("tutor_assignments").InsertOne(ctx, newAssignment)
	if err != nil {
		http.Error(w, "Failed to assign tutor", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newAssignment)
}

// GetTutorsWithCourses retrieves all tutors with their assigned courses
func (h *CourseHandler) GetTutorsWithCourses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Aggregate tutors with their assigned courses
	pipeline := mongo.Pipeline{
		{
			{
				Key: "$lookup",
				Value: bson.D{
					{Key: "from", Value: "tutor_assignments"},
					{Key: "localField", Value: "_id"},
					{Key: "foreignField", Value: "tutor_id"},
					{Key: "as", Value: "assigned_courses"},
				},
			},
		},
		{
			{
				Key: "$match",
				Value: bson.D{
					{Key: "role", Value: models.RoleTutor},
				},
			},
		},
	}

	cursor, err := h.collection.Database().Collection("users").Aggregate(ctx, pipeline)
	if err != nil {
		http.Error(w, "Failed to fetch tutors with courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var tutors []bson.M
	if err = cursor.All(ctx, &tutors); err != nil {
		http.Error(w, "Error decoding tutors with courses", http.StatusInternalServerError)
		return
	}

	// Return tutors with their assigned courses as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tutors)
}

// GetCoursesWithSessions retrieves all courses with their sessions
func (h *CourseHandler) GetCoursesWithSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Aggregate courses with their sessions
	pipeline := mongo.Pipeline{
		{
			{
				Key: "$lookup",
				Value: bson.D{
					{Key: "from", Value: "sessions"},
					{Key: "localField", Value: "_id"},
					{Key: "foreignField", Value: "course_id"},
					{Key: "as", Value: "sessions"},
				},
			},
		},
		{
			{
				Key: "$match",
				Value: bson.D{
					{Key: "archived", Value: false},
				},
			},
		},
	}

	cursor, err := h.collection.Aggregate(ctx, pipeline)
	if err != nil {
		http.Error(w, "Failed to fetch courses with sessions", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var courses []bson.M
	if err = cursor.All(ctx, &courses); err != nil {
		http.Error(w, "Error decoding courses with sessions", http.StatusInternalServerError)
		return
	}

	// Return courses with their sessions as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(courses)
}

// get course by id
func (h *CourseHandler) GetCourseByID(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	idParam := params["id"]

	objID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	var course models.Course
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = h.collection.FindOne(ctx, bson.M{"_id": objID}).Decode(&course)
	if err != nil {
		http.Error(w, "Course not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(course)
}
