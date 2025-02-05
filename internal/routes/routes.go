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
	userHandler := handlers.NewUserHandler(client, dbName)
	
	router.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET")
	router.HandleFunc("/api/users", userHandler.CreateUser).Methods("POST")
	router.HandleFunc("/api/users", userHandler.GetUsers).Methods("GET")
	router.HandleFunc("/api/users", userHandler.CreateUser).Methods("POST")

	return router
}
