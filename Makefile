# Makefile

# go install github.com/rubenv/sql-migrate/...@latest
MIGRATE_CMD=sql-migrate
MIGRATIONS_DIR=migrations
ENV_FILE=.env

CONFIG_TEMPLATE=dbconfig.yml.in
CONFIG_FILE=dbconfig.yml

SERVICE := authservice

REGISTRY := ghcr.io/swayrider
IMAGE := $(REGISTRY)/$(SERVICE)
VERSION := $(shell cat .version)
BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
DATE_TAG := $(shell date +%Y%m%d-%H%M)

BASE_TAG := 
LATEST_TAG :=

ifeq ($(BRANCH), main)
	BASE_TAG := v$(VERSION)
	LATEST_TAG := latest
else ifeq ($(BRANCH), dev)
	BASE_TAG := v$(VERSION)-$(DATE_TAG)-dev
	LATEST_TAG := dev-latest
else ifeq ($(BRANCH), test)
	BASE_TAG := v$(VERSION)-$(DATE_TAG)-test
	LATEST_TAG := test-latest
else
	BASE_TAG := v$(VERSION)-$(DATE_TAG)-$(BRANCH)
endif

TAGS := -t $(IMAGE):$(BASE_TAG)
ifneq ($(LATEST_TAG),)
	TAGS := $(TAGS) -t $(IMAGE):$(LATEST_TAG)
endif

include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE))

.PHONY: migrate-up migrate-down migrate-status create-migration container-build ensure-db

all: container-build

container-build:
	@echo "Building version: $(BASE_TAG)"
	docker buildx build \
		-f Dockerfile \
		--platform linux/amd64,linux/arm64 \
		$(TAGS) \
		--push ../../
	@echo "Image pushed with tags: $(BASE_TAG) $(LATEST_TAG)"

$(CONFIG_FILE): $(CONFIG_TEMPLATE)
	envsubst < $(CONFIG_TEMPLATE) > $(CONFIG_FILE)

ensure-db:
	@PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d postgres -tc \
		"SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}'" | grep -q 1 || \
		PGPASSWORD=${DB_PASSWORD} psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_USER} -d postgres -c \
		"CREATE DATABASE ${DB_NAME};"


create-migration:
	@read -p "Migration name: " name ; \
	mkdir -p $(MIGRATIONS_DIR) ; \
	touch "$(MIGRATIONS_DIR)$${name}.sql" ; \
	echo "Created: $${name}.sql in $(MIGRATIONS_DIR)/"

migrate-up: $(CONFIG_FILE) ensure-db
	@echo "Running migrations up ..."
	@$(MIGRATE_CMD) up -env="development" -config="$(CONFIG_FILE)"

migrate-down: $(CONFIG_FILE) ensure-db
	@echo "Rolling back on migration ..." -env="development" -config="$(CONFIG_FILE)"
	@$(MIGRATE_CMD) down

migrate-status: $(CONFIG_FILE) ensure-db
	@$(MIGRATE_CMD) status -env="development" -config="$(CONFIG_FILE)"


