package banyan

import (
	"errors"
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

// Adds a warning to the diagnostics if the resource is not found and sets the id to "" which deletes it from the schema
func handleNotFoundError(d *schema.ResourceData, err error) (diagnostics diag.Diagnostics) {
	if err != nil {
		diagnostics = append(diagnostics, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  fmt.Sprintf("%s not found", d.Id()),
		})
		d.SetId("")
	}
	return
}

func validateTrustLevel() func(val interface{}, key string) (warns []string, errs []error) {
	return validation.StringInSlice([]string{"Low", "Medium", "High"}, false)
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

// creates the hostTagSelector key
func buildHostTagSelector(d *schema.ResourceData) (hostTagSelector []map[string]string, err error) {
	conn, connOk := d.GetOk("connector")
	at, atOk := d.GetOk("access_tier")

	// error if both are set
	if connOk && atOk {
		err = errors.New("cannot have both access_tier and connector set")
		return
	}

	// if connector is set, ensure access_tier is *
	if conn.(string) != "" {
		at = "*"
	}
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": at.(string)}
	hostTagSelector = append(hostTagSelector, siteNameSelector)
	return
}

// TODO: revisit after cluster consolidation
// sets the cluster to global-edge if connector is set.
// errors if connector and access_tier are both set
// sets cluster to same as access_tier value if access_tier is set
// sets to first cluster if the access_tier does not exist
func setCluster(d *schema.ResourceData, m interface{}) (err error) {
	c := m.(*client.Holder)
	clusterName, err := determineCluster(c, d)
	if err != nil {
		return
	}
	err = d.Set("cluster", clusterName)
	return
}

func determineCluster(c *client.Holder, d *schema.ResourceData) (clusterName string, err error) {
	_, connOk := d.GetOk("connector")
	at, atOk := d.GetOk("access_tier")

	// error if both are set
	if connOk && atOk {
		err = errors.New("cannot have both access_tier and connector set")
	}

	// set to global-edge if connector is set
	if connOk {
		clusterName = "global-edge"
		return
	}

	// otherwise determine which cluster to set based off of the access tier
	atDetails, err := c.AccessTier.GetName(at.(string))
	if err != nil {
		err = fmt.Errorf("accesstier %s not found", at.(string))
		clusterName, err = getFirstCluster(c)
		return
	}
	clusterName = atDetails.ClusterName
	return
}

func getFirstCluster(c *client.Holder) (clusterName string, err error) {
	clusters, err := c.Shield.GetAll()
	if err != nil {
		return
	}
	sort.Strings(clusters)
	return clusters[0], nil
}
