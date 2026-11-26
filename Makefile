.DEFAULT_GOAL := help

SHELL := sh
COMPOSE_FILE := deployments/docker-compose.yml
FRONTEND_DIR := frontend
BACKEND_DIR := backend
PROTO_DIR := $(BACKEND_DIR)/proto

.PHONY: help codegen build test verify bench up down clean

help: ## Show available make targets
	@echo "urGuard Makefile targets:"
	@echo "  make codegen  - Generate TypeScript/Go bindings from backend/proto"
	@echo "  make build    - Build frontend (and backend when available)"
	@echo "  make test     - Run frontend checks/tests (and backend race tests when available)"
	@echo "  make verify   - Run clean-machine and end-to-end verification scripts"
	@echo "  make bench    - Run latency, throughput, and detection benchmarks"
	@echo "  make up       - Start multi-node Docker Compose stack"
	@echo "  make down     - Stop multi-node Docker Compose stack"
	@echo "  make clean    - Remove build artifacts and coverage outputs"

codegen: ## Generate ConnectRPC/Protobuf bindings
	@if [ -d "$(PROTO_DIR)" ] && [ -n "$$(find $(PROTO_DIR) -name '*.proto' 2>/dev/null)" ]; then \
		if [ -d "$(FRONTEND_DIR)/node_modules" ]; then \
			npm --prefix $(FRONTEND_DIR) run codegen; \
		else \
			echo "frontend/node_modules missing; run 'npm --prefix frontend install' first"; \
			exit 1; \
		fi; \
	else \
		echo "frontend codegen: backend/proto/*.proto not implemented yet"; \
	fi
	@if [ -f "$(BACKEND_DIR)/buf.gen.yaml" ]; then \
		(cd $(BACKEND_DIR) && buf generate); \
	else \
		echo "backend codegen: not implemented yet"; \
	fi

build: ## Build frontend and backend
	@if [ -d "$(FRONTEND_DIR)/node_modules" ]; then \
		npm --prefix $(FRONTEND_DIR) run build; \
	else \
		echo "frontend/node_modules missing; run 'npm --prefix frontend install' first"; \
		exit 1; \
	fi
	@if [ -f "$(BACKEND_DIR)/go.mod" ]; then \
		mkdir -p bin && (cd $(BACKEND_DIR) && go build -o ../bin/ ./...); \
	else \
		echo "backend build: not implemented yet"; \
	fi

test: ## Run typecheck, lint, unit tests
	@if [ -d "$(FRONTEND_DIR)/node_modules" ]; then \
		npm --prefix $(FRONTEND_DIR) run typecheck && \
		npm --prefix $(FRONTEND_DIR) run lint && \
		npm --prefix $(FRONTEND_DIR) test; \
	else \
		echo "frontend/node_modules missing; run 'npm --prefix frontend install' first"; \
		exit 1; \
	fi
	@if [ -f "$(BACKEND_DIR)/go.mod" ]; then \
		(cd $(BACKEND_DIR) && go test -race ./...); \
	else \
		echo "backend tests: not implemented yet"; \
	fi

verify: ## Run verification and clean-machine check scripts
	@if [ -f "scripts/clean-machine-check.sh" ]; then \
		bash scripts/clean-machine-check.sh; \
	else \
		echo "scripts/clean-machine-check.sh: not implemented yet"; \
	fi
	@if [ -f "scripts/verify.sh" ]; then \
		bash scripts/verify.sh; \
	else \
		echo "scripts/verify.sh: not implemented yet"; \
	fi

bench: ## Run performance and detection evaluation benchmarks
	@if [ -f "scripts/bench.sh" ]; then \
		bash scripts/bench.sh; \
	else \
		echo "scripts/bench.sh: not implemented yet"; \
	fi

up: ## Start Docker Compose stack
	@if [ -f "$(COMPOSE_FILE)" ]; then \
		docker compose -f $(COMPOSE_FILE) up --build -d; \
	else \
		echo "$(COMPOSE_FILE): not implemented yet"; \
	fi

down: ## Stop Docker Compose stack
	@if [ -f "$(COMPOSE_FILE)" ]; then \
		docker compose -f $(COMPOSE_FILE) down; \
	else \
		echo "$(COMPOSE_FILE): not implemented yet"; \
	fi

clean: ## Clean build artifacts and temporary outputs
	@rm -rf $(FRONTEND_DIR)/dist $(FRONTEND_DIR)/coverage bin coverage
	@echo "Cleaned frontend/dist, frontend/coverage, bin, coverage"
