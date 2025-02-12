package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Course struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name         string             `json:"name" bson:"name"`
	Subject      string             `json:"subject" bson:"subject"`
	CoverPicURL  string             `json:"cover_pic_url" bson:"cover_pic_url"`
	Schedule     string             `json:"schedule" bson:"schedule"`
	DurationWeeks int               `json:"duration_weeks" bson:"duration_weeks"`
	MeetingLink  string             `json:"meeting_link" bson:"meeting_link"`
	CreatedBy    primitive.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt    time.Time          `json:"created_at" bson:"created_at"`
	Archived     bool               `json:"archived" bson:"archived"`
}
