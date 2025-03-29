package utils

import (
	"log"

	"gopkg.in/gomail.v2"
)

// SendEmail sends an email using the provided SMTP configuration
func SendEmail(to string, subject string, body string) error {
	// Load SMTP configuration from environment variables
	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	smtpUsername := "jasingh203@gmail.com"
	smtpPassword := "jmrd sieq mqtm izuh"

	// Create a new email message
	mailer := gomail.NewMessage()
	mailer.SetHeader("From", smtpUsername)
	mailer.SetHeader("To", to)
	mailer.SetHeader("Subject", subject)
	mailer.SetBody("text/html", body)

	// Create a new SMTP dialer
	dialer := gomail.NewDialer(smtpHost, smtpPort, smtpUsername, smtpPassword)

	// Send the email
	if err := dialer.DialAndSend(mailer); err != nil {
		log.Printf("Failed to send email: %v", err)
		return err
	}

	log.Printf("Email sent successfully to %s", to)
	return nil
}
