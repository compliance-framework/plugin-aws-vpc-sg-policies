# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI catalog characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

# Check if OPA CLI is installed
OPA := $(shell command -v opa 2> /dev/null)
ifeq ($(OPA),)
$(error "opa CLI not found. Please install it: https://www.openpolicyagent.org/docs/latest/cli/")
endif

##@ Help
help: ## Display this concise help, ie only the porcelain target
	@awk 'BEGIN {FS = ":.*##"; printf "\033[1mUsage\033[0m\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-30s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

help-all: ## Display all help items, ie including plumbing targets
	@awk 'BEGIN {FS = ":.*#"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?#/ { printf "  \033[36m%-25s\033[0m %s\n", $$1, $$2 } /^#@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Policies
test: ## Test policy files
	@$(OPA) test policies

validate: ## Validate policy files
	@opa check policies

clean: # Cleanup build artifacts
	@rm -f dist/*

# Bundle the policies into a tarball for OCI registry
build: clean ## Build the policy bundle
	@mkdir -p dist/
	@opa build -b policies -o dist/bundle.tar.gz

