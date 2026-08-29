package db

// wellKnownPorts maps common ports to service names for display purposes.
var wellKnownPorts = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
	69: "tftp", 80: "http", 110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios",
	143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpd", 548: "afp", 587: "submission", 631: "ipp",
	636: "ldaps", 853: "dns-over-tls", 873: "rsync", 989: "ftps", 990: "ftps", 993: "imaps", 995: "pop3s",
	1194: "openvpn", 1433: "mssql", 1521: "oracle", 1701: "l2tp", 1723: "pptp", 1883: "mqtt", 1900: "ssdp",
	2049: "nfs", 2375: "docker", 3000: "grafana", 3306: "mysql", 3389: "rdp", 3478: "stun", 4500: "ipsec-nat",
	5000: "upnp", 5060: "sip", 5061: "sips", 5222: "xmpp", 5353: "mdns", 5432: "postgres", 5900: "vnc",
	6379: "redis", 6881: "bittorrent", 8080: "http-alt", 8443: "https-alt", 8883: "mqtts", 9000: "php-fpm",
	9090: "prometheus", 9100: "node-exporter", 27017: "mongodb", 32400: "plex", 51820: "wireguard",
}

// ServiceName returns a friendly name for a port, or "".
func ServiceName(port int) string { return wellKnownPorts[port] }

var protoNames = map[int]string{
	0: "ip", 1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah",
	58: "icmpv6", 89: "ospf", 112: "vrrp", 132: "sctp",
}

// ProtoName returns the textual protocol name for a protocol number.
func ProtoName(n int) string {
	if s, ok := protoNames[n]; ok {
		return s
	}
	return "proto-" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
