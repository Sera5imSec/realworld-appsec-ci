#!/usr/bin/env bash
set -e

# Clean up database
rm -f ./data/gorm.db

# Use the collection pinned in this repository. The old remote URL is gone.
COLLECTION=./api/Conduit.postman_collection.json
test -s "$COLLECTION"

# Build the application
echo "Building application..."
go build -o app hello.go

# Start the server
echo "Starting server..."
PORT=8080 ./app &
SERVER_PID=$!

# Cleanup function to kill server on exit
cleanup() {
    echo "Stopping server..."
    kill $SERVER_PID
    rm -f app
}
trap cleanup EXIT

# Wait for server to be ready
echo "Waiting for server to be ready..."
for i in {1..30}; do
    if curl -fsS http://localhost:8080/api/ping/ > /dev/null; then
        echo "Server is up!"
        break
    fi
    sleep 1
done

# Run Newman
echo "Running API tests..."
# Check if newman is available
if ! command -v newman &> /dev/null; then
    echo "newman not found, trying npx..."
    npx newman run "$COLLECTION" \
      --global-var "APIURL=http://localhost:8080/api" \
      --global-var "EMAIL=test@example.com" \
      --global-var "PASSWORD=password" \
      --global-var "USERNAME=testuser" \
      --delay-request 50
else
    newman run "$COLLECTION" \
      --global-var "APIURL=http://localhost:8080/api" \
      --global-var "EMAIL=test@example.com" \
      --global-var "PASSWORD=password" \
      --global-var "USERNAME=testuser" \
      --delay-request 50
fi
