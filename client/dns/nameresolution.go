package dns

type NameResolutionInfo struct {
	NameServers      []string `json:"name_servers,omitempty"`
	DnsSearchDomains []string `json:"dns_search_domains,omitempty"`
}
