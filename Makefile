# Makefile

# go install github.com/rubenv/sql-migrate/...@latest
MIGRATE_CMD=sql-migrate
MIGRATIONS_DIR=migrations
ENV_FILE=.env

CONFIG_TEMPLATE=dbconfig.yml.in
CONFIG_FILE=dbconfig.yml

SERVICE := authservice

REGISTRY := ghcr.io/swayrider
IMAGE    := $(REGISTRY)/$(SERVICE)

VERSION_TAG    := $(shell git tag --points-at HEAD 2>/dev/null | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | sort -V | tail -1)
LAST_VERSION   := $(shell git describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --abbrev=0 2>/dev/null || echo v0.0.0)
CURRENT_BRANCH := $(shell git symbolic-ref --short HEAD 2>/dev/null)
DATE_TAG       := $(shell date +%Y%m%d)
SHORT_SHA      := $(shell git rev-parse --short HEAD 2>/dev/null)
SAFE_BRANCH    := $(shell echo "$(CURRENT_BRANCH)" | sed 's|/|-|g; s|[^a-zA-Z0-9-]|-|g')

FORCE_DEV_LATEST ?=

ifneq ($(VERSION_TAG),)
  BASE_TAG     := $(VERSION_TAG)
  FLOATING_TAG := latest
  ifeq ($(FORCE_DEV_LATEST),1)
    EXTRA_TAG := dev-latest
  else
    EXTRA_TAG :=
  endif
else ifeq ($(CURRENT_BRANCH),main)
  BASE_TAG     := $(LAST_VERSION)-$(DATE_TAG)-dev
  FLOATING_TAG := dev-latest
  EXTRA_TAG    :=
else ifneq ($(CURRENT_BRANCH),)
  BASE_TAG     := $(LAST_VERSION)-$(SAFE_BRANCH)
  FLOATING_TAG :=
  EXTRA_TAG    :=
else
  BASE_TAG     := $(LAST_VERSION)-$(SHORT_SHA)
  FLOATING_TAG :=
  EXTRA_TAG    :=
endif

TAGS := -t $(IMAGE):$(BASE_TAG)
ifneq ($(FLOATING_TAG),)
  TAGS := $(TAGS) -t $(IMAGE):$(FLOATING_TAG)
endif
ifneq ($(EXTRA_TAG),)
  TAGS := $(TAGS) -t $(IMAGE):$(EXTRA_TAG)
endif

-include $(ENV_FILE)
export $(shell sed 's/=.*//' $(ENV_FILE) 2>/dev/null)

.PHONY: container-build migrate-up migrate-down migrate-status create-migration ensure-db

all: container-build

container-build:
	@echo "Building $(IMAGE):$(BASE_TAG)$(if $(FLOATING_TAG), [+$(FLOATING_TAG)])$(if $(EXTRA_TAG), [+$(EXTRA_TAG)])"
	docker buildx build \
		-f Dockerfile \
		--network=host \
		--platform linux/amd64,linux/arm64 \
		$(TAGS) \
		--push .
	@echo "Done."

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
	@echo "Rolling back on migration ..."
	@$(MIGRATE_CMD) down -env="development" -config="$(CONFIG_FILE)"

migrate-status: $(CONFIG_FILE) ensure-db
	@$(MIGRATE_CMD) status -env="development" -config="$(CONFIG_FILE)"
