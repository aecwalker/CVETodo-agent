# CVETodo Agent Makefile

# Build variables
BINARY_NAME=cvetodo-agent
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD)
DATE?=$(shell powershell -Command "Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ'")

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Output directories
BUILD_DIR=build
DIST_DIR=dist

# Default target
.DEFAULT_GOAL := build

# Build the agent for current platform
build:
	@echo "Building $(BINARY_NAME) for current platform..."
ifeq ($(OS),Windows_NT)
	@if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).exe ./cmd/agent
else
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/agent
endif

# Build for all platforms
build-all: build-linux build-windows build-darwin

# Build for Linux (64-bit)
build-linux:
	@echo "Building $(BINARY_NAME) for Linux..."
ifeq ($(OS),Windows_NT)
	@if not exist $(DIST_DIR)\linux-amd64 mkdir $(DIST_DIR)\linux-amd64
else
	@mkdir -p $(DIST_DIR)/linux-amd64
endif
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/linux-amd64/$(BINARY_NAME) ./cmd/agent

# Build for Windows (64-bit)
build-windows:
	@echo "Building $(BINARY_NAME) for Windows..."
ifeq ($(OS),Windows_NT)
	@if not exist $(DIST_DIR)\windows-amd64 mkdir $(DIST_DIR)\windows-amd64
else
	@mkdir -p $(DIST_DIR)/windows-amd64
endif
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/windows-amd64/$(BINARY_NAME).exe ./cmd/agent

# Build for macOS (64-bit)
build-darwin:
	@echo "Building $(BINARY_NAME) for macOS..."
ifeq ($(OS),Windows_NT)
	@if not exist $(DIST_DIR)\darwin-amd64 mkdir $(DIST_DIR)\darwin-amd64
else
	@mkdir -p $(DIST_DIR)/darwin-amd64
endif
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/darwin-amd64/$(BINARY_NAME) ./cmd/agent

# Run tests
test:
	@echo "Running tests..."
ifeq ($(OS),Windows_NT)
	$(GOTEST) -v -race ./...
else
	$(GOTEST) -v -race -tags=!windows ./...
endif

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
ifeq ($(OS),Windows_NT)
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
else
	$(GOTEST) -v -race -coverprofile=coverage.out -tags=!windows ./...
endif
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run linting
lint:
	@echo "Running linting..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Tidy dependencies
tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
ifeq ($(OS),Windows_NT)
	@if exist $(BUILD_DIR) rmdir /s /q $(BUILD_DIR)
	@if exist $(DIST_DIR) rmdir /s /q $(DIST_DIR)
	@if exist coverage.out del coverage.out
	@if exist coverage.html del coverage.html
else
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html
endif

# Create release packages
package: build-all
	@echo "Creating release packages..."
ifeq ($(OS),Windows_NT)
	@if not exist $(DIST_DIR)\packages mkdir $(DIST_DIR)\packages
else
	@mkdir -p $(DIST_DIR)/packages
endif
	
	# Linux package
	@tar -czf $(DIST_DIR)/packages/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C $(DIST_DIR)/linux-amd64 $(BINARY_NAME)
	
	# Windows package
	@cd $(DIST_DIR)/windows-amd64 && zip -q ../packages/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME).exe
	
	# macOS package
	@tar -czf $(DIST_DIR)/packages/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C $(DIST_DIR)/darwin-amd64 $(BINARY_NAME)
	
	@echo "Packages created in $(DIST_DIR)/packages/"

# Install the agent locally
install: build
	@echo "Installing $(BINARY_NAME)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "$(BINARY_NAME) installed to /usr/local/bin/"

# Uninstall the agent
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "$(BINARY_NAME) uninstalled"

# Run the agent in development mode
run: build
	@echo "Running $(BINARY_NAME)..."
ifeq ($(OS),Windows_NT)
	./$(BUILD_DIR)/$(BINARY_NAME).exe scan --log-level debug
else
	./$(BUILD_DIR)/$(BINARY_NAME) scan --log-level debug
endif

# Run with config init
init-config: build
	@echo "Initializing configuration..."
ifeq ($(OS),Windows_NT)
	./$(BUILD_DIR)/$(BINARY_NAME).exe config init
else
	./$(BUILD_DIR)/$(BINARY_NAME) config init
endif

# Create development environment
dev-setup: deps tidy fmt
	@echo "Development environment setup complete"

# Show help
help:
	@echo "CVETodo Agent Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  build          Build for current platform"
	@echo "  build-all      Build for all platforms (Linux, Windows, macOS)"
	@echo "  build-linux    Build for Linux"
	@echo "  build-windows  Build for Windows"
	@echo "  build-darwin   Build for macOS"
	@echo "  test           Run tests"
	@echo "  test-coverage  Run tests with coverage"
	@echo "  lint           Run linting"
	@echo "  fmt            Format code"
	@echo "  tidy           Tidy dependencies"
	@echo "  deps           Download dependencies"
	@echo "  clean          Clean build artifacts"
	@echo "  package        Create release packages"
	@echo "  install        Install agent locally"
	@echo "  uninstall      Uninstall agent"
	@echo "  run            Run agent in development mode"
	@echo "  init-config    Initialize configuration"
	@echo "  dev-setup      Setup development environment"
	@echo "  help           Show this help"

.PHONY: build build-all build-linux build-windows build-darwin test test-coverage lint fmt tidy deps clean package install uninstall run init-config dev-setup help 