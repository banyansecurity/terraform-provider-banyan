//go:build tools
// +build tools

package tools

import (
	// document generation
	// Command line Usage:
	// tfplugindocs generate --provider-name terraform-provider-banyan --examples-dir ./examples/
	_ "github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs"
)
