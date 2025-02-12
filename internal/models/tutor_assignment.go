package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type TutorAssignment struct {
	TutorID    primitive.ObjectID `json:"tutor_id" bson:"tutor_id"`
	CourseID   primitive.ObjectID `json:"course_id" bson:"course_id"`
	AssignedBy primitive.ObjectID `json:"assigned_by" bson:"assigned_by"`
	AssignedAt time.Time          `json:"assigned_at" bson:"assigned_at"`
}

