package main

import (
	"context"
	"log"
	"net/http"

	"github.com/rs/cors"

	"github.com/jas-4484/ctd-backend/internal/config"
	"github.com/jas-4484/ctd-backend/internal/database"
	"github.com/jas-4484/ctd-backend/internal/routes"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Connect to MongoDB
	client, err := database.ConnectMongoDB(cfg.MongoURI)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer func() {
		if err := client.Disconnect(context.Background()); err != nil {
			log.Fatal("Failed to disconnect from MongoDB:", err)
		}
	}()

	// Initialize router
	router := routes.SetupRouter(client, cfg.DatabaseName)

	// Setup CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{cfg.Origin},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	// Wrap router with CORS
	handler := c.Handler(router)

	// Start server
	log.Printf("🚀 Server running on port %s", cfg.Port)
	if err := http.ListenAndServe(":"+cfg.Port, handler); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
