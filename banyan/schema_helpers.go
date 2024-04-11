package banyan

import (
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstiergroup"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func convertSchemaSetToStringSlice(original *schema.Set) (stringSlice []string) {
	for _, v := range original.List() {
		stringSlice = append(stringSlice, v.(string))
	}
	return
}
func getStringListWithinSetForKey(keys *schema.Set, key string) (values []string, err error) {
	for _, keyRaw := range keys.List() {
		lp := keyRaw.(map[string]interface{})[key]
		for _, v := range lp.([]interface{}) {
			values = append(values, v.(string))
		}
	}
	return
}

// Adds a warning to the diagnostics if the resource is not found and sets the id to "" which deletes it from the schema
func handleNotFoundError(d *schema.ResourceData, err error) (diagnostics diag.Diagnostics) {
	if strings.Contains(err.Error(), "not found") {
		diagnostics = append(diagnostics, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  fmt.Sprintf("%s not found", d.Id()),
		})
		d.SetId("")
	}
	return
}

func validateTrustLevel() func(val interface{}, key string) (warns []string, errs []error) {
	return validation.StringInSlice([]string{"", "Low", "Medium", "High"}, false)
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
	switch typeval := val.(type) {
	case int:
		v = val.(int)
	case string:
		v, err = strconv.Atoi(val.(string))
		if err != nil {
			err = fmt.Errorf("port %q could not be converted to an int", val)
		}
	default:
		err = fmt.Errorf("could not validate port %q unsupported type %q", val, typeval)
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
	var list []string
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

func GetStringPtr(d *schema.ResourceData, key string) (result *string) {
	r, ok := d.GetOk(key)
	if !ok {
		return nil
	}
	x := r.(string)
	return &x
}

func GetBoolPtr(d *schema.ResourceData, key string) (result *bool) {
	r, ok := d.GetOk(key)
	if !ok {
		return nil
	}
	x := r.(bool)
	return &x
}

func GetIntPtr(d *schema.ResourceData, key string) (result *int) {
	r, ok := d.GetOk(key)
	if !ok {
		return nil
	}
	x := r.(int)
	return &x
}

// creates the hostTagSelector key
func buildHostTagSelector(d *schema.ResourceData) (hostTagSelector []map[string]string, err error) {
	conn, connOk := d.GetOk("connector")
	at, atOk := d.GetOk("access_tier")
	atg, atgOk := d.GetOk("access_tier_group")

	// error if both are set
	if connOk && atOk {
		err = errors.New("cannot have both access_tier and connector set")
		return
	}

	if (atgOk && atOk) || (connOk && atgOk) {
		err = errors.New("cannot have both access_tier or connector and access tier group set")
		return
	}

	// if connector is set, ensure access_tier is *
	if conn.(string) != "" {
		at = "*"
	}
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": at.(string)}

	if atg != nil {
		siteNameSelector["com.banyanops.hosttag.access_tier_group"] = atg.(string)
	}

	hostTagSelector = append(hostTagSelector, siteNameSelector)
	return
}

// TODO: revisit after cluster consolidation
// sets the cluster to global-edge if connector is set.
// errors if connector and access_tier are both set
// sets cluster to same as access_tier value if access_tier is set
// sets to first cluster if the access_tier does not exist
func setCluster(d *schema.ResourceData, m interface{}) (err error) {
	_, clusterOk := d.GetOk("cluster")
	if clusterOk {
		return
	}

	c := m.(*client.Holder)
	clusterName, err := determineCluster(c, d)
	if err != nil {
		return
	}
	err = d.Set("cluster", clusterName)
	return
}

func determineCluster(c *client.Holder, d *schema.ResourceData) (clusterName string, err error) {
	// registered services
	_, connOk := d.GetOk("connector")
	at, atOk := d.GetOk("access_tier")
	// service tunnels
	_, connsOk := d.GetOk("connectors")
	ats, atsOk := d.GetOk("access_tiers")

	atg, atgOk := d.GetOk("access_tier_group")

	// error if singular and plural are used
	if (connOk && connsOk) || (atOk && atsOk) {
		err = errors.New("cannot have both access_tier and access_tiers set or both connector and connectors set")
		return
	}

	// error if both are set
	if (connOk && atOk) || (connsOk && atsOk) {
		err = errors.New("cannot have both access_tier and connector set")
		return
	}

	if (atgOk && atOk) || (atgOk && atsOk) {
		err = errors.New("cannot have both access_tier and access tier group set")
		return
	}

	// set to global-edge if connector is set
	if connOk || connsOk {
		clusterName = "global-edge"
		return
	}

	// if multiple ats use the 1st one
	if ats != nil {
		atsSlice := convertSchemaSetToStringSlice(ats.(*schema.Set))
		if atsOk {
			at = atsSlice[0]
		}
	}

	if atg != nil {
		var atDetails accesstiergroup.AccessTierGroupResponse
		atDetails, err = c.AccessTierGroup.GetName(atg.(string))
		if err != nil {
			_ = fmt.Errorf("accesstier group %s not found", atg.(string))
			clusterName, err = getFirstCluster(c)
			return
		}
		clusterName = atDetails.ClusterName
		return
	}

	// otherwise determine which cluster to set based off of the access tier
	atDetails, err := c.AccessTier.GetName(at.(string))
	if err != nil {
		_ = fmt.Errorf("accesstier %s not found", at.(string))
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
