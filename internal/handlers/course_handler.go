package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

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
			"name":         updatedCourse.Name,
			"subject":      updatedCourse.Subject,
			"schedule":     updatedCourse.Schedule,
			"duration_weeks": updatedCourse.DurationWeeks,
			"meeting_link": updatedCourse.MeetingLink,
			"updated_at":   time.Now(),
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
