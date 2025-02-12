package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Session struct {
	ID             primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	CourseID       primitive.ObjectID `json:"course_id" bson:"course_id"`
	SequenceNumber int                `json:"sequence_number" bson:"sequence_number"`
	StartTime      time.Time          `json:"start_time" bson:"start_time"`
	EndTime        time.Time          `json:"end_time" bson:"end_time"`
	Topic          string             `json:"topic" bson:"topic"`
	MaterialsURL   string             `json:"materials_url" bson:"materials_url"`
}
