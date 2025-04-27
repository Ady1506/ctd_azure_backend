package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type AttendanceStatus string

const (
	StatusPresent AttendanceStatus = "present"
	StatusAbsent  AttendanceStatus = "absent"
	StatusExcused AttendanceStatus = "excused"
)

type Attendance struct {
	ID         primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	SessionID  primitive.ObjectID `json:"session_id" bson:"session_id"`
	StudentID  primitive.ObjectID `json:"student_id" bson:"student_id"`
	CourseID   primitive.ObjectID `json:"course_id" bson:"course_id"`
	CourseName string             `json:"course_name" bson:"course_name"` // New field
	Status     AttendanceStatus   `json:"status" bson:"status"`
	MarkedBy   primitive.ObjectID `json:"marked_by" bson:"marked_by"`
	MarkedAt   time.Time          `json:"marked_at" bson:"marked_at"`
}
