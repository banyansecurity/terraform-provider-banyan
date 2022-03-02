SHELL := bash 
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

#Constants
ARTIFACT_NAME = terraform-provider-banyan

HOSTNAME=github.com
NAMESPACE=banyansecurity
NAME=banyan
OS_ARCH=darwin_amd64
VERSION=0.4.1

# ifeq ($(origin .RECIPEPREFIX), undefined)
#   $(error This Make does not support .RECIPEPREFIX. Please use GNU Make 4.0 or later)
# endif
# .RECIPEPREFIX = >

default: install

build:
	go build -o $(ARTIFACT_NAME)
	cp $(ARTIFACT_NAME) examples/
.PHONY: build

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	mv $(ARTIFACT_NAME) ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
.PHONY: install
