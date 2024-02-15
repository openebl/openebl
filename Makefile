MOCK_DIR := test/mock
MOCK_SOURCES := \
	pkg/bu_server/storage/interface.go \
	pkg/bu_server/auth/api_key.go \
	pkg/bu_server/auth/application.go \
	pkg/bu_server/auth/user.go \
	pkg/bu_server/business_unit/bu_storage.go \
	pkg/bu_server/business_unit/bu_controller.go \
	pkg/bu_server/business_unit/bu_jws_signer.go \
	pkg/bu_server/cert_authority/cert_authority.go
MOCK_FILES := $(patsubst pkg/%,$(MOCK_DIR)/%,$(MOCK_SOURCES))

.PHONY: mock
mock: $(MOCK_FILES)


$(MOCK_FILES): test/mock/% : pkg/%
	@mkdir -p $(@D)
	@printf "Generating $(bold)$@$(sgr0) ... "
	@mockgen -source $< -destination $@
	@printf "$(green)done$(sgr0)\n"
