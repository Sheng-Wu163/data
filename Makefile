.PHONY: build test run-server run-client up down tidy vet

build:
	go build -o bin/server ./cmd/server
	go build -o bin/client ./cmd/client

test:
	go test ./...

vet:
	go vet ./...

run-server:
	go run ./cmd/server

run-client:
	go run ./cmd/client -server http://localhost:8080 -input testdata/input.json

up:
	docker compose up --build

down:
	docker compose down -v

tidy:
	go mod tidy
