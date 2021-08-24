package banyan

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_validateCIDR_tooLargeSuffixBitSize(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/3666", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_validateCIDR_0SuffixBitSize(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/0", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_validateCIDR_validCIDR(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("10.1.2.1/32", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_validateCIDR_invalidIPValues(t *testing.T) {
	t.Parallel()
	warns, errs := validateCIDR()("300.1.2.1/32", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_portValidation_zeroPort(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(0, "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_portValidation_maxPortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(65535, "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_portValidation_negativePortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(-1, "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_portValidation_tooLargePortValue(t *testing.T) {
	t.Parallel()
	warns, errs := validatePort()(65536, "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}

func Test_templateValidation_validNonEmpty(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("WEB_USER", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_templateValidation_validEmpty(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("", "key")
	assert.Empty(t, warns)
	assert.Empty(t, errs)
}

func Test_templateValidation_invalidValue_returnsError(t *testing.T) {
	t.Parallel()
	warns, errs := validateTemplate()("invalid", "key")
	assert.Empty(t, warns)
	assert.NotEmpty(t, errs)
}
