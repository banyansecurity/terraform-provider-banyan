SHELL := bash 
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

#Constants
ARTIFACT_NAME = terraform-provider-banyan
GO_VERSION = go1.16.6

HOSTNAME=github.com
NAMESPACE=banyansecurity
NAME=banyan
OS_ARCH=darwin_amd64
VERSION=0.1

# ifeq ($(origin .RECIPEPREFIX), undefined)
#   $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
# endif
# .RECIPEPREFIX = >

default: install

install-go: 
	gvm install $(GO_VERSION)
.PHONY: install-go

# issue using "$gvm use" detailed https://github.com/moovweb/gvm/issues/188 
# so using the source gvm to get around the issue
set-go-version: install-go
	source ~/.gvm/scripts/gvm && gvm use $(GO_VERSION)
.PHONY: set-go-version

build: set-go-version clean-examples
	go build -o $(ARTIFACT_NAME)
	cp $(ARTIFACT_NAME) examples/
.PHONY: build

clean-examples:
	echo "Cleaning"
	rm -rf examples/.terraform
	rm -f examples/.terraform.lock.hcl
	rm -f examples/terraform-provider-banyan examples/terraform.tfstate examples/terraform.tfstate.backup
.PHONY: clean-examples

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv $(ARTIFACT_NAME) ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
.PHONY: install
