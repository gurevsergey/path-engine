FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /path-engine .

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=build /path-engine /path-engine
EXPOSE 49105
CMD ["/path-engine"]
