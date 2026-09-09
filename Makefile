.PHONY: taa docker docker-base test run platform-mock platform-mock-build attestation-ioctl attestation-vmmcall clean help

BIN_DIR ?= bin
TAA_BINARY ?= $(BIN_DIR)/taa
MOCK_BINARY ?= $(BIN_DIR)/platform-mock
BASE_IMAGE ?= taa-env-slim:latest

taa:
	@mkdir -p $(dir $(TAA_BINARY))
	@echo "[build] building taa daemon from ./cmd/taa..."
	@go build -o $(TAA_BINARY) ./cmd/taa

test:
	@go test ./...

run: taa attestation-ioctl
	@if [ ! -f taa-config.json ]; then cp configs/taa-local.json taa-config.json; fi
	@$(TAA_BINARY)

platform-mock:
	@go run ./cmd/platform-mock -addr 0.0.0.0:8080

platform-mock-build:
	@mkdir -p $(dir $(MOCK_BINARY))
	@echo "[build] building platform-mock from ./cmd/platform-mock..."
	@go build -o $(MOCK_BINARY) ./cmd/platform-mock

attestation-ioctl:
	@$(MAKE) -C attestation/csv_c BIN_DIR=$(abspath $(BIN_DIR)) ioctl-get-attestation

attestation-vmmcall:
	@$(MAKE) -C attestation/csv_c BIN_DIR=$(abspath $(BIN_DIR)) vmmcall-get-attestation

docker: deploy/manifest/docker/Dockerfile
	@if [ -f deploy/.dockerignore ]; then cp deploy/.dockerignore .dockerignore; trap 'rm -f .dockerignore' EXIT INT TERM; fi; \
	docker build -t taa:latest -f deploy/manifest/docker/Dockerfile .

docker-base: deploy/manifest/docker/Dockerfile.base
	docker build -t $(BASE_IMAGE) -f deploy/manifest/docker/Dockerfile.base deploy/manifest/docker

clean:
	@rm -f $(TAA_BINARY) $(MOCK_BINARY)
	@$(MAKE) -C attestation/csv_c BIN_DIR=$(abspath $(BIN_DIR)) clean
	@rmdir $(BIN_DIR) 2>/dev/null || true

help:
	@echo "make taa                编译本地二进制到 bin/taa"
	@echo "make test               运行 Go 测试"
	@echo "make run                编译并启动 TAA 服务"
	@echo "make platform-mock      启动本地平台模拟器"
	@echo "make platform-mock-build 构建平台模拟器单文件二进制到 bin/"
	@echo "make attestation-ioctl  构建 ioctl-attestation helper 到 bin/"
	@echo "make attestation-vmmcall 构建 vmmcall-attestation helper 到 bin/"
	@echo "make docker             构建 Docker 镜像"
	@echo "make docker-base        构建标准基础环境镜像 (taa-env-slim:latest)"
	@echo "make clean              清理构建产物"
