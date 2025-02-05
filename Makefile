run:
	go run cmd/api/main.go

setup:
	go mod tidy

test:
	go test -v ./...

mongo:
	docker run -d -p 27017:27017 --name go-mongo mongo:latest

.PHONY: run setup test mongo