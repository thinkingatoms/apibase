FROM golang:1.18-alpine AS build

RUN apk add ca-certificates && update-ca-certificates

# Move to working directory (/build).
WORKDIR /app

# Copy and download dependency using go mod.
COPY go.mod go.sum ./
RUN go mod download

# Copy the code into the container.
COPY cmd cmd
COPY ez ez
COPY models models
COPY servers servers
COPY main.go main.go
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /appserver
COPY config config

FROM scratch
COPY --from=build /appserver /appserver
COPY --from=build /app/config /app/config

# RUN adduser -D -g '' nonroot