FROM golang:1.18-alpine AS build

# Move to working directory (/build).
WORKDIR /app

# Copy and download dependency using go mod.
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /appserver

# FROM scratch
# COPY --from=build /appserver /appserver

# RUN adduser -D -g '' nonroot