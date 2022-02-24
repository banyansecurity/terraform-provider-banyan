package banyan

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"log"
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

func handleNotFoundError(d *schema.ResourceData, resource string) (diagnostics diag.Diagnostics) {
	log.Printf("[WARN] Removing %s because it's gone", resource)
	// The resource doesn't exist anymore
	d.SetId("")
	return nil
}
