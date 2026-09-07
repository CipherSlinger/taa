FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/app main.go

FROM scratch

WORKDIR /
COPY --from=builder /out/app /app
COPY configs/taa-production.json /taa-config.json
EXPOSE 6001
ENTRYPOINT ["/app"]
