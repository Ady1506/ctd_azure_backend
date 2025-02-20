package routes

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jas-4484/ctd-backend/internal/handlers"
	"github.com/jas-4484/ctd-backend/internal/middleware"
	"go.mongodb.org/mongo-driver/mongo"
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

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte("<h1>working just fine</h1>"))
	}).Methods("GET")

	// User routes
	router.HandleFunc("/api/users/signup", userHandler.Signup).Methods("POST")
	router.HandleFunc("/api/users/signin", userHandler.Signin).Methods("POST")
	router.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET")

	// Course routes
	router.HandleFunc("/api/courses", courseHandler.GetCourses).Methods("GET")
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.CreateCourse))).Methods("POST") // Protected
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.UpdateCourse))).Methods("PUT")
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.DeleteCourse))).Methods("DELETE")
	router.Handle("/api/courses/archive", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.ArchiveCourse))).Methods("PUT")

	// Session routes
	router.Handle("/api/sessions", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.CreateSession))).Methods("POST") // Protected

	// Enrollment routes
	router.Handle("/api/enrollments", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.EnrollCourse))).Methods("POST") // Protected

	// Attendance routes
	router.Handle("/api/attendance", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.MarkAttendance))).Methods("POST") // Protected

	return router
}
