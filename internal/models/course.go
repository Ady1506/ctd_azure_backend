package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Schedule struct {
	Days      []string `json:"days" bson:"days"`             // Days of the week (e.g., ["Mon", "Tue", "Wed"])
	StartTime string   `json:"start_time" bson:"start_time"` // Start time (e.g., "5:00 PM")
	EndTime   string   `json:"end_time" bson:"end_time"`     // End time (e.g., "7:00 PM")
}

type Course struct {
	ID            primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name          string             `json:"name" bson:"name"`
	Subject       string             `json:"subject" bson:"subject"`
	Schedule      Schedule           `json:"schedule" bson:"schedule"`
	DurationWeeks int                `json:"duration_weeks" bson:"duration_weeks"`
	MeetingLink   string             `json:"meeting_link" bson:"meeting_link"`
	Link          string             `json:"link,omitempty" bson:"link,omitempty"` // Optional field
	Description   string             `json:"description" bson:"description"`       // New field
	StartDate     time.Time          `json:"start_date" bson:"start_date"`         // New field
	EndDate       time.Time          `json:"end_date" bson:"end_date"`             // New field
	CreatedBy     primitive.ObjectID `json:"created_by" bson:"created_by"`
	CreatedAt     time.Time          `json:"created_at" bson:"created_at"`
	Archived      bool               `json:"archived" bson:"archived"`
}
