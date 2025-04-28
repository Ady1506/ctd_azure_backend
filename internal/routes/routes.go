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
	router.HandleFunc("/api/users/logout", userHandler.Logout).Methods("POST")
	router.Handle("/api/users/current", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.CurrentUser))).Methods("GET")

	// Email verification route
	router.HandleFunc("/api/users/verify", userHandler.VerifyEmail).Methods("GET")

	// Password reset routes
	router.HandleFunc("/api/users/forgot-password", userHandler.ForgotPassword).Methods("POST")
	router.HandleFunc("/api/users/reset-password", userHandler.ResetPassword).Methods("POST")

	// Course routes
	router.HandleFunc("/api/courses", courseHandler.GetCourses).Methods("GET")
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.CreateCourse))).Methods("POST") // Protected
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.UpdateCourse))).Methods("PUT")
	router.Handle("/api/courses", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.DeleteCourse))).Methods("DELETE")
	router.Handle("/api/courses/archive", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.ArchiveCourse))).Methods("PUT")

	// Enrollment views routes
	router.Handle("/api/enrollments/courses", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.ViewEnrolledCourses))).Methods("GET") // Protected

	//get course by id
	router.HandleFunc("/api/courses/{id}", courseHandler.GetCourseByID).Methods("GET")

	// Enrollment routes
	router.Handle("/api/enrollments", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.EnrollCourse))).Methods("POST") // Protected

	// Attendance routes
	router.Handle("/api/attendance", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.MarkAttendance))).Methods("POST") // Protected
	router.Handle("/api/attendances/recent", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.GetRecentAttendances))).Methods("GET")
	router.Handle("/api/attendance/summary", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.GetAttendanceSummary))).Methods("GET")

	// Notice routes
	router.Handle("/api/notices", middleware.AdminAuthMiddleware(http.HandlerFunc(courseHandler.CreateNotice))).Methods("POST") // Protected
	router.HandleFunc("/api/notices", courseHandler.GetNotices).Methods("GET")
	router.Handle("/api/notices/enrolled", middleware.StudentAuthMiddleware(http.HandlerFunc(userHandler.GetNoticesForEnrolledCourses))).Methods("GET") // Protected
	return router
}
