package handlers

import (
	"context"
	"encoding/json"
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
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newCourse.Name == "" || newCourse.Subject == "" || newCourse.CreatedBy == primitive.NilObjectID {
		http.Error(w, "Course name, subject, and created_by are required", http.StatusBadRequest)
		return
	}

	// Validate StartDate and EndDate
	if newCourse.StartDate.IsZero() || newCourse.EndDate.IsZero() {
		http.Error(w, "StartDate and EndDate are required", http.StatusBadRequest)
		return
	}
	if newCourse.StartDate.After(newCourse.EndDate) {
		http.Error(w, "StartDate cannot be after EndDate", http.StatusBadRequest)
		return
	}

	// Validate Schedule
	if len(newCourse.Schedule.Days) == 0 || newCourse.Schedule.StartTime == "" || newCourse.Schedule.EndTime == "" {
		http.Error(w, "Schedule must include days, start time, and end time", http.StatusBadRequest)
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

// ViewEnrolledCourses retrieves all courses a user is enrolled in
func (h *UserHandler) ViewEnrolledCourses(w http.ResponseWriter, r *http.Request) {
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

	// Fetch enrolled courses for the student
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

	// Fetch course details for the enrolled courses
	coursesCursor, err := h.collection.Database().Collection("courses").Find(ctx, bson.M{"_id": bson.M{"$in": courseIDs}})
	if err != nil {
		http.Error(w, "Failed to fetch courses", http.StatusInternalServerError)
		return
	}
	defer coursesCursor.Close(ctx)

	var courses []models.Course
	if err = coursesCursor.All(ctx, &courses); err != nil {
		http.Error(w, "Error decoding courses", http.StatusInternalServerError)
		return
	}

	// Return courses as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(courses)
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

	// Validate Schedule
	if len(updatedCourse.Schedule.Days) == 0 || updatedCourse.Schedule.StartTime == "" || updatedCourse.Schedule.EndTime == "" {
		http.Error(w, "Schedule must include days, start time, and end time", http.StatusBadRequest)
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
			"description":    updatedCourse.Description,
			"start_date":     updatedCourse.StartDate,
			"end_date":       updatedCourse.EndDate,
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

func (h *CourseHandler) CreateNotice(w http.ResponseWriter, r *http.Request) {
	var newNotice models.Notice
	if err := json.NewDecoder(r.Body).Decode(&newNotice); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if newNotice.CourseID == primitive.NilObjectID || newNotice.Content == "" {
		http.Error(w, "CourseID and Content are required", http.StatusBadRequest)
		return
	}

	// Set default values
	newNotice.ID = primitive.NewObjectID()
	newNotice.CreatedAt = time.Now()

	// Insert into database
	_, err := h.collection.Database().Collection("notices").InsertOne(context.TODO(), newNotice)
	if err != nil {
		http.Error(w, "Failed to create notice", http.StatusInternalServerError)
		return
	}

	// Return the created notice
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newNotice)
}

// GetNotices retrieves all notices for a specific course
func (h *CourseHandler) GetNotices(w http.ResponseWriter, r *http.Request) {
	courseID := r.URL.Query().Get("course_id")
	if courseID == "" {
		http.Error(w, "Course ID is required", http.StatusBadRequest)
		return
	}

	// Convert courseID to ObjectID
	courseObjID, err := primitive.ObjectIDFromHex(courseID)
	if err != nil {
		http.Error(w, "Invalid course ID", http.StatusBadRequest)
		return
	}

	// Find notices for the course
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cursor, err := h.collection.Database().Collection("notices").Find(ctx, bson.M{"course_id": courseObjID})
	if err != nil {
		http.Error(w, "Failed to fetch notices", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var notices []models.Notice
	if err = cursor.All(ctx, &notices); err != nil {
		http.Error(w, "Error decoding notices", http.StatusInternalServerError)
		return
	}

	// Return notices as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(notices)
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
func (h *CourseHandler) GetArchivedCourses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query for archived courses
	cursor, err := h.collection.Find(ctx, bson.M{"archived": true})
	if err != nil {
		http.Error(w, "Failed to fetch archived courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var archivedCourses []models.Course
	if err = cursor.All(ctx, &archivedCourses); err != nil {
		http.Error(w, "Error decoding archived courses", http.StatusInternalServerError)
		return
	}

	// Return archived courses as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(archivedCourses)
}

// GetUnarchivedCourses retrieves all unarchived courses
func (h *CourseHandler) GetUnarchivedCourses(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query for unarchived courses
	cursor, err := h.collection.Find(ctx, bson.M{"archived": false})
	if err != nil {
		http.Error(w, "Failed to fetch unarchived courses", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)

	var unarchivedCourses []models.Course
	if err = cursor.All(ctx, &unarchivedCourses); err != nil {
		http.Error(w, "Error decoding unarchived courses", http.StatusInternalServerError)
		return
	}

	// Return unarchived courses as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(unarchivedCourses)
}
