package config

import (
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port         string
	MongoURI     string
	DatabaseName string
	Timeout      time.Duration
}

func LoadConfig() Config {
	_ = godotenv.Load()

	return Config{
		Port:         getEnv("PORT", "8000"),
		MongoURI:     getEnv("MONGODB_URI", "mongodb://localhost:27017"),
		DatabaseName: getEnv("DATABASE_NAME", "go_backend"),
		Timeout:      10 * time.Second,
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}