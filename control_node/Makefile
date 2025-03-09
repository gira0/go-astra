# Variables
BINARY_NAME=control_node
DB_FILE=./control_node.db

# Targets
.PHONY: all build swag clean run

all: clean swag build run

build:
	@echo "Building the project..."
	go build -o $(BINARY_NAME)

swag:
	@echo "Generating Swagger documentation..."
	swag init -g ./*.go

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f $(DB_FILE)
	rm -rf docs

run: build swag
	@echo "Running the project..."
	chmod +x $(BINARY_NAME)
	./$(BINARY_NAME)

# Default target
.DEFAULT_GOAL := all
