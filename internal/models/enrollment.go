package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type EnrollmentStatus string

const (
	StatusActive    EnrollmentStatus = "active"
	StatusCompleted EnrollmentStatus = "completed"
	StatusDropped   EnrollmentStatus = "dropped"
)

type Enrollment struct {
	StudentID  primitive.ObjectID `json:"student_id" bson:"student_id"`
	CourseID   primitive.ObjectID `json:"course_id" bson:"course_id"`
	EnrolledAt time.Time          `json:"enrolled_at" bson:"enrolled_at"`
	Status     EnrollmentStatus   `json:"status" bson:"status"`
}
