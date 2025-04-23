package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Notice struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	CourseID  primitive.ObjectID `json:"course_id" bson:"course_id"`
	Content   string             `json:"content" bson:"content"`
	Link      string             `json:"link,omitempty" bson:"link,omitempty"` // Optional field for a link
	CreatedAt time.Time          `json:"created_at" bson:"created_at"`
}
