CURDIR := $(strip $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))
ifneq (,$(wildcard $(CURDIR)/.env))
	include $(CURDIR)/.env
	export
endif

VERSION := $(shell grep -sw version package.json | grep -oE '[0-9\.]+')
FILENAME := $(patsubst %,admin-console-%.js,$(VERSION))
OUTFILE := $(patsubst %,dist/assets/%,$(FILENAME))
SOURCE_FILES := $(shell find . -type f \( -iname \*.js -o -iname \*.svelte -o -iname \*.ts \) -and -not -path './node_modules/*' -not -path './dist/*' -not -path '*/\.*')

.DEFAULT: all

.PHONY: all
all: $(OUTFILE)

$(OUTFILE): $(SOURCE_FILES)
	@$(MAKE) install
	@pnpm run build
	@touch embed.go

.PHONY: check-pnpm
check-pnpm:
	@command -v node >/dev/null 2>&1 || { \
		echo >&2 "$$(tput bold)Node.js$$(tput sgr0) is not installed"; \
		echo >&2 "Please install Node.js from https://nodejs.org/"; \
		exit 1; \
	}
	@node_version=$$(node -v); \
	node_major_version=$$(echo $$node_version | sed 's/v\([0-9]*\).*/\1/'); \
	if [ "$$node_major_version" -lt 20 ]; then \
		echo >&2 "Node.js version is $$node_version"; \
		echo >&2 "Please install Node.js v20 or above from https://nodejs.org/"; \
		exit 1; \
	fi
	@command -v npm >/dev/null 2>&1 || { \
		echo >&2 "$$(tput bold)npm$$(tput sgr0) is not installed."; \
		echo >&2 "Please install Node.js, which includes npm, from https://nodejs.org/"; \
		exit 1; \
	}
	@command -v corepack >/dev/null 2>&1 || { \
		echo >&2 "$$(tput bold)corepack$$(tput sgr0) is not installed."; \
		echo >&2 "Please install it by running '$$(tput bold)$$(tput setaf 5)npm install -g corepack$$(tput sgr0)'"; \
		echo >&2 "Once corepack is installed, enable pnpm by running '$$(tput bold)$$(tput setaf 5)corepack enable pnpm$$(tput sgr0)'"; \
		exit 1; \
	}
	@command -v pnpm >/dev/null 2>&1 || { \
		echo >&2 "$$(tput bold)pnpm$$(tput sgr0) is not installed."; \
		echo >&2 "Enable pnpm by running '$$(tput bold)$$(tput setaf 5)corepack enable pnpm$$(tput sgr0)'"; \
		echo >&2 "Alternatively, you can install pnpm globally by running '$$(tput bold)$$(tput setaf 5)npm install -g pnpm$$(tput sgr0)'"; \
		exit 1; \
	}


.PHONY: install
install: check-pnpm
	@pnpm install

.PHONY: fmt
fmt: check-pnpm
	@pnpm run format

.PHONY: lint
lint: check-pnpm
	@pnpm run lint

.PHONY: clean
clean:
	@rm -rf $(filter-out dist/vite.svg,$(wildcard dist/*))
	@touch embed.go
