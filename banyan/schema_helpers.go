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
	"sort"
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

func validateTrustLevel() func(val interface{}, key string) (warns []string, errs []error) {
	return validation.StringInSlice([]string{"LOW", "MEDIUM", "HIGH"}, false)
}

func contains(valid []string, v string) bool {
	for _, s := range valid {
		if s == v {
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
// sets the cluster to global-edge if global-edge is enabled.
// errors if global-edge and cluster are both set
// sets cluster to cluster value if cluster is set
// sets default cluster by asking API if cluster and
func setCluster(c *client.Holder, d *schema.ResourceData) (diagnostics diag.Diagnostics) {
	globalEdge, GLok := d.GetOk("global_edge")
	if GLok {
		if globalEdge.(bool) {
			err := d.Set("cluster", "global-edge")
			if err != nil {
				return diag.FromErr(err)
			}
		}
	}
	_, CLok := d.GetOk("cluster")
	if CLok && GLok {
		return diag.Errorf("cluster and global-edge cannot both be set")
	}
	if CLok {
		return
	}
	err := getCluster(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func getCluster(c *client.Holder, d *schema.ResourceData) (err error) {
	clusters, err := c.Shield.GetAll()
	if err != nil {
		return
	}
	sort.Strings(clusters)
	err = d.Set("cluster", clusters[0])
	return
}
