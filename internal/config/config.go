package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port         string
	Origin       string
	MongoURI     string
	DatabaseName string
	Timeout      time.Duration
}

func LoadConfig() Config {
	err := godotenv.Load(".env")
	if err != nil {
		if os.IsNotExist(err) {
			log.Println(".env file not found, using default/environment values")
		} else {
			panic("Error loading .env file: " + err.Error())
		}
	}
	return Config{
		Port:         getEnv("PORT"),
		Origin:       getEnv("ORIGIN"),
		MongoURI:     getEnv("MONGODB_URI"),
		DatabaseName: getEnv("DATABASE_NAME"),
		Timeout:      10 * time.Second,
	}
}

func getEnv(key string) string {
	value := os.Getenv(key)
	return value
}
