FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app main.go

FROM scratch

COPY --from=builder /out/app /app
EXPOSE 9001
ENTRYPOINT ["/app"]
