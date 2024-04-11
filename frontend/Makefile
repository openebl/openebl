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
	@pnpm run build
	@touch embed.go

.PHONY: fmt
fmt:
	@pnpm run format

.PHONY: lint
lint:
	@pnpm run lint

.PHONY: clean
clean:
	@rm -rf $(filter-out dist/vite.svg,$(wildcard dist/*))
	@touch embed.go
