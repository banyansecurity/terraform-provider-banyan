package banyan

import (
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"math"
	"net"
	"reflect"
	"strconv"
)

func convertInterfaceMapToStringMap(original map[string]interface{}) (newMap map[string]string) {
	newMap = make(map[string]string)
	for key, value := range original {
		stringifiedValue := value.(string)
		newMap[key] = stringifiedValue
	}
	return
}

func convertEmptyInterfaceToStringMap(original interface{}) (stringMap map[string]string) {
	semiStringMap := original.(map[string]interface{})
	stringMap = convertInterfaceMapToStringMap(semiStringMap)
	return
}

func convertSliceInterfaceToSliceStringMap(original []interface{}) (sliceStringMap []map[string]string) {
	for _, v := range original {
		stringMap := convertEmptyInterfaceToStringMap(v.(interface{}))
		sliceStringMap = append(sliceStringMap, stringMap)
	}
	return
}

func convertSchemaSetToStringSlice(original *schema.Set) (stringSlice []string) {
	for _, v := range original.List() {
		stringSlice = append(stringSlice, v.(string))
	}
	return
}

func convertSchemaSetToIntSlice(original *schema.Set) (stringSlice []int) {
	for _, v := range original.List() {
		stringSlice = append(stringSlice, v.(int))
	}
	return
}

func handleNotFoundError(d *schema.ResourceData, id string, err error) (diagnostics diag.Diagnostics) {
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return
}

func validateL7Protocol() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		valid := []string{"http", "https"}
		if !contains(valid, v) {
			errs = append(errs, fmt.Errorf("%q must be one of %q", v, valid))
		}
		return
	}
}

func validateTrustLevel() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		valid := []string{"High", "Medium", "Low", ""}
		if !contains(valid, v) {
			errs = append(errs, fmt.Errorf("%q must be one of %q", v, valid))
		}
		return
	}
}

func validatePolicyTemplate() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		valid := []string{"USER"}
		if !contains(valid, v) {
			errs = append(errs, fmt.Errorf("%q must be one of %q", v, valid))
		}
		return
	}
}

func validateContains() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		valid := []string{"WEB_USER", "TCP_USER", "CUSTOM"}
		if !contains(valid, v) {
			errs = append(errs, fmt.Errorf("%q must be one of %q", v, valid))
		}
		return
	}
}

func contains(valid []string, v string) bool {
	for _, v := range valid {
		if v == v {
			return true
		}
	}
	return false
}

func validatePort() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v, err := typeSwitchPort(val)
		if err != nil {
			errs = append(errs, err)
			return
		}
		if v < 0 || v > math.MaxUint16 {
			errs = append(errs, fmt.Errorf("%q must be in range 0-%d, got: %d ", key, math.MaxUint16, v))
		}
		return
	}
}

func typeSwitchPort(val interface{}) (v int, err error) {
	switch val.(type) {
	case int:
		v = val.(int)
	case string:
		v, err = strconv.Atoi(val.(string))
		if err != nil {
			err = fmt.Errorf("port %q could not be converted to an int", val)
		}
	default:
		err = fmt.Errorf("could not validate port %q unsupported type", val)
	}
	return
}

// typeSwitchPort type switches a string pointer to an int pointer if possible
func typeSwitchPortPtr(val interface{}) (ptrv *int, err error) {
	var v int
	switch val.(type) {
	case *int:
		v = val.(int)
	case *string:
		if val.(*string) == nil {
			ptrv = nil
			return
		}
		vstring := val.(*string)
		vstringval := *vstring
		v, err = strconv.Atoi(vstringval)
		if err != nil {
			err = fmt.Errorf("%q could not be converted to an int", val)
		}
	default:
		err = fmt.Errorf("could not validate port %q unsupported type", val)
	}
	ptrv = &v
	return
}

func validateCIDR() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v == "" {
			return
		}
		_, _, err := net.ParseCIDR(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q must be a CIDR, got: %q", key, v))
		}
		return
	}
}

func validateHttpMethods() func(val interface{}, key string) (warns []string, errs []error) {
	validMethods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	return validation.StringInSlice(validMethods, false)
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func removeFromSlice(slice []string, s string) (result []string) {
	for _, element := range slice {
		if element != s {
			result = append(result, element)
		}
	}
	return
}

func isNil(i interface{}) bool {
	if i == nil {
		return true
	}
	switch reflect.TypeOf(i).Kind() {
	case reflect.Ptr, reflect.Map, reflect.Array, reflect.Chan, reflect.Slice:
		return reflect.ValueOf(i).IsNil()
	}
	return false
}

// TODO: revisit after cluster consolidation
func setCluster(c *client.Holder, d *schema.ResourceData) (diagnostics diag.Diagnostics) {
	globalEdge, ok := d.GetOk("global_edge")
	if !ok {
		cluster, err := c.Shield.GetAll()
		if err != nil {
			return diag.FromErr(err)
		}
		d.Set("cluster", cluster[0])
		if err != nil {
			return diag.FromErr(err)
		}
		return
	}
	if globalEdge.(bool) {
		d.Set("global_edge", true)
	}
	return
}
