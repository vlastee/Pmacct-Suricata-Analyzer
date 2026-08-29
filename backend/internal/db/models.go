package db

import "time"

// Window is a time range filter for accounting queries.
type Window struct {
	Since time.Time
	Until time.Time
}

// Totals summarises traffic in a window.
type Totals struct {
	Bytes       int64 `json:"bytes"`
	Packets     int64 `json:"packets"`
	Flows       int64 `json:"flows"`
	LocalHosts  int64 `json:"local_hosts"`
	ExternalIPs int64 `json:"external_ips"`
	BytesIn     int64 `json:"bytes_in"`  // external -> local
	BytesOut    int64 `json:"bytes_out"` // local -> external
	BytesLocal  int64 `json:"bytes_local"`
}

// Bucket is one point in a time series.
type Bucket struct {
	Time     time.Time `json:"time"`
	Bytes    int64     `json:"bytes"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
	Packets  int64     `json:"packets"`
	Flows    int64     `json:"flows"`
}

// ProtoStat aggregates by IP protocol.
type ProtoStat struct {
	Proto   int    `json:"proto"`
	Name    string `json:"name"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Flows   int64  `json:"flows"`
}

// PortStat aggregates by destination port + protocol.
type PortStat struct {
	Port    int    `json:"port"`
	Proto   int    `json:"proto"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Bytes   int64  `json:"bytes"`
	Packets int64  `json:"packets"`
	Flows   int64  `json:"flows"`
}

// HostStat is a per-IP traffic summary.
type HostStat struct {
	IP        string    `json:"ip"`
	Nickname  *string   `json:"nickname"`
	Local     bool      `json:"local"`
	BytesIn   int64     `json:"bytes_in"`
	BytesOut  int64     `json:"bytes_out"`
	Bytes     int64     `json:"bytes"`
	Packets   int64     `json:"packets"`
	Flows     int64     `json:"flows"`
	Peers     int64     `json:"peers"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Names     []string  `json:"names"`
	Risk      *HostRisk `json:"risk,omitempty"`
	Info      *IPInfo   `json:"info,omitempty"`
}

// Flow is a raw accounting row.
type Flow struct {
	IPSrc         string     `json:"ip_src"`
	IPDst         string     `json:"ip_dst"`
	SrcNickname   *string    `json:"src_nickname"`
	DstNickname   *string    `json:"dst_nickname"`
	PortSrc       int        `json:"port_src"`
	PortDst       int        `json:"port_dst"`
	Proto         int        `json:"proto"`
	ProtoName     string     `json:"proto_name"`
	Packets       int64      `json:"packets"`
	Bytes         int64      `json:"bytes"`
	StampInserted time.Time  `json:"stamp_inserted"`
	StampUpdated  *time.Time `json:"stamp_updated"`
}

// IPInfo is enrichment data about an external IP.
type IPInfo struct {
	IP          string     `json:"ip"`
	Hostname    *string    `json:"hostname"`
	Country     *string    `json:"country"`
	CountryCode *string    `json:"country_code"`
	Region      *string    `json:"region"`
	City        *string    `json:"city"`
	Lat         *float64   `json:"lat"`
	Lon         *float64   `json:"lon"`
	Timezone    *string    `json:"timezone"`
	ASN         *string    `json:"asn"`
	ASOrg       *string    `json:"as_org"`
	ISP         *string    `json:"isp"`
	Org         *string    `json:"org"`
	IsHosting   *bool      `json:"is_hosting"`
	IsProxy     *bool      `json:"is_proxy"`
	IsMobile    *bool      `json:"is_mobile"`
	Source      *string    `json:"source"`
	Status      string     `json:"status"`
	Error       *string    `json:"error"`
	Attempts    int        `json:"attempts"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastLookup  *time.Time `json:"last_lookup"`
	UpdatedAt   time.Time  `json:"updated_at"`
	VT          *VTResult  `json:"vt,omitempty"`
	// Populated for single-IP views only.
	Names      []IPName     `json:"names,omitempty"`
	Reputation []Reputation `json:"reputation,omitempty"`
	Lists      []string     `json:"lists,omitempty"`
}

// VTResult is the VirusTotal reputation summary for an IP.
type VTResult struct {
	Malicious    *int       `json:"malicious"`
	Suspicious   *int       `json:"suspicious"`
	Harmless     *int       `json:"harmless"`
	Undetected   *int       `json:"undetected"`
	Reputation   *int       `json:"reputation"`
	Tags         []string   `json:"tags"`
	Network      *string    `json:"network"`
	LastAnalysis *time.Time `json:"last_analysis"`
	Status       string     `json:"status"`
	Error        *string    `json:"error"`
	Attempts     int        `json:"attempts"`
	LookupAt     *time.Time `json:"lookup_at"`
	// Geo fields VirusTotal also returns; merged into the main record when missing.
	ASN         *string `json:"-"`
	ASOrg       *string `json:"-"`
	CountryCode *string `json:"-"`
}

// Threat is an external IP flagged by VirusTotal that appeared in the window.
type Threat struct {
	IP         string    `json:"ip"`
	Nickname   *string   `json:"nickname"`
	Malicious  int       `json:"malicious"`
	Suspicious int       `json:"suspicious"`
	Tags       []string  `json:"tags"`
	Bytes      int64     `json:"bytes"`
	Flows      int64     `json:"flows"`
	LocalHosts []string  `json:"local_hosts"`
	LastSeen   time.Time `json:"last_seen"`
	Info       *IPInfo   `json:"info,omitempty"`
}

// GroupStat aggregates external traffic by an enrichment dimension (country, ASN...).
type GroupStat struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	IPs      int64  `json:"ips"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
	Bytes    int64  `json:"bytes"`
	Flows    int64  `json:"flows"`
}

// EnrichmentStatus summarises the ip_info table.
type EnrichmentStatus struct {
	Total   int64 `json:"total"`
	OK      int64 `json:"ok"`
	Pending int64 `json:"pending"`
	Failed  int64 `json:"failed"`
	Stale   int64 `json:"stale"`
	// VirusTotal lane
	VTDone      int64 `json:"vt_done"`
	VTFailed    int64 `json:"vt_failed"`
	VTNever     int64 `json:"vt_never"` // known ip_info rows never sent to VT
	VTStale     int64 `json:"vt_stale"`
	VTUsedToday int64 `json:"vt_used_today"`
	VTUsedMonth int64 `json:"vt_used_month"`
	VTFlagged   int64 `json:"vt_flagged"`
}

// Nickname is a user-assigned label for an IP.
type Nickname struct {
	IP        string    `json:"ip"`
	Nickname  string    `json:"nickname"`
	Note      *string   `json:"note"`
	Kind      string    `json:"kind"`
	UpdatedAt time.Time `json:"updated_at"`
}

// DeviceKinds are the accepted nickname kinds.
var DeviceKinds = []string{"pc", "phone", "server", "iot", "network", "other"}
