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
	err := godotenv.Load()
	if err != nil {
		if os.IsNotExist(err) {
			// .env file not found, proceed with default values
		} else {
			panic("Error loading .env file")
		}
	}
	return Config{
		Port:         getEnv("PORT", "8000"),
		MongoURI:     getEnv("MONGODB_URI", "mongodb+srv://jas:jas@abc.xqqgc.mongodb.net/?retryWrites=true&w=majority&appName=ABC"),
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
