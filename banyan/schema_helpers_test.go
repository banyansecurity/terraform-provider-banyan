package banyan

import (
	"github.com/stretchr/testify/assert"
	"testing"
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

func Test_typeSwitchPort(t *testing.T) {
	t.Parallel()
	var val interface{}
	_, err := typeSwitchPort(val)
	if err == nil {
		t.Errorf("expected error here, got none")
	}
	val = 1234
	v, _ := typeSwitchPort(val)
	if v != val {
		t.Errorf("got %T expected %T", v, val)
	}
	sVal := "1234"
	v, _ = typeSwitchPort(sVal)
	if v != val {
		t.Errorf("got %T expected %T", v, val)
	}
}

func Test_contains(t *testing.T) {
	t.Parallel()
	valid := []string{"a", "b", "c", "d", "e"}
	v := "a"
	if !contains(valid, v) {
		t.Errorf("expected error, got none")
	}
}
