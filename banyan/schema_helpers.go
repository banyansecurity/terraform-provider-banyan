package banyan

import (
	"errors"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
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

func convertEmptyInterfaceToStringMapTwo(original interface{}) (stringMap map[string]string) {
	stringMap, _ = original.(map[string]string)
	semiStringMap := original.(map[string]interface{})
	stringMap, _ = convertInterfaceMapToStringMap(semiStringMap)
	return
}

func convertEmptyInterfaceSliceToStringSlice(original []interface{}) (stringSlice []string) {
	for _, v := range original {
		stringSlice = append(stringSlice, v.(string))
	}
	return
}

func convertSchemaSetToStringSlice(original *schema.Set) (stringSlice []string) {
	for _, v := range original.List() {
		stringSlice = append(stringSlice, v.(string))
	}
	return
}

func handleNotFoundError(d *schema.ResourceData, resource string) (diagnostics diag.Diagnostics) {
	log.Printf("[WARN] Removing %s because it's gone", resource)
	// The resource doesn't exist anymore
	d.SetId("")
	return nil
}
