package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"github.com/jas-4484/ctd-backend/internal/handlers"
)

func SetupRouter(client *mongo.Client, dbName string) *mux.Router {
	router := mux.NewRouter()

	// Health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Server is healthy"))
	}).Methods("GET")

	// Initialize handlers
	userHandler := handlers.NewUserHandler(client, dbName)
	courseHandler := handlers.NewCourseHandler(client, dbName)

	// User routes
	router.HandleFunc("/api/users/signup", userHandler.Signup).Methods("POST")
	router.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET")

	// Course routes
	router.HandleFunc("/api/courses", courseHandler.GetCourses).Methods("GET")
	router.HandleFunc("/api/courses", courseHandler.CreateCourse).Methods("POST")
	router.HandleFunc("/api/courses", courseHandler.UpdateCourse).Methods("PUT")
	router.HandleFunc("/api/courses", courseHandler.DeleteCourse).Methods("DELETE")
	router.HandleFunc("/api/courses/archive", courseHandler.ArchiveCourse).Methods("PUT")

	return router
}
