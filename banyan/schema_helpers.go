package banyan

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func convertInterfaceMapToStringMap(original map[string]interface{}) (newMap map[string]string, err error) {
	newMap = make(map[string]string)
	for key, value := range original {
		stringifiedValue, ok := value.(string)
		if !ok {
			err = errors.New("couldn't type assert value to be string")
			return
		}
		newMap[key] = stringifiedValue
	}
	return
}

func convertEmptyInterfaceToStringMap(original interface{}) (stringMap map[string]string, err error) {
	stringMap, ok := original.(map[string]string)
	if ok {
		return
	}
	semiStringMap, ok := original.(map[string]interface{})
	if !ok {
		err = errors.New("couldn't type assert value to be a map of string to empty interface")
		return
	}
	stringMap, err = convertInterfaceMapToStringMap(semiStringMap)
	return
}

func createTypeAssertDiagnostic(itemName string, original interface{}) diag.Diagnostics {
	return diag.Errorf("Couldn't type assert %s in addressMap: %v", itemName, reflect.TypeOf(original))
}

func getStringSliceFromSet(set interface{}, setName string) (slice []string, diagnostics []diag.Diagnostic) {
	assertedSet, ok := set.(*schema.Set)
	if !ok {
		diagnostics = createTypeAssertDiagnostic(setName, set)
		return
	}
	for idx, setItem := range assertedSet.List() {
		assertedSetItem, ok := setItem.(string)
		if !ok {
			diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("%q", idx), setItem)
		}
		slice = append(slice, assertedSetItem)
	}
	return
}

func convertSliceInterfaceToSliceMap(original []interface{}) (sliceOfStringMap []map[string]string, err error) {
	for _, elem := range original {
		stringMap, err := convertEmptyInterfaceToStringMap(elem)
		if err != nil {
			err = errors.New("couldn't convert empty interface to string map")
		}
		sliceOfStringMap = append(sliceOfStringMap, stringMap)
	}
	return
}
