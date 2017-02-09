package connstr

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
)

type HostPortPair struct {
	Host string
	Port int
}

type ConnSpec struct {
	Scheme  string
	Hosts   []HostPortPair
	Bucket  string
	Options url.Values
}

func (spec ConnSpec) SrvRecordName() (recordName string) {
	// Only `couchbase`-type schemes allow SRV records
	if spec.Scheme != "couchbase" && spec.Scheme != "couchbases" {
		return ""
	}

	// Must have only a single host, with no port specified
	if len(spec.Hosts) != 1 || spec.Hosts[0].Port != 0 {
		return ""
	}

	return fmt.Sprintf("_%s._tcp.%s", spec.Scheme, spec.Hosts[0].Host)
}

func (spec ConnSpec) String() string {
	str := ""

	if spec.Scheme != "" {
		str += spec.Scheme + "://"
	}

	for i, host := range spec.Hosts {
		if i != 0 {
			str += ","
		}

		if host.Port == 0 {
			str += host.Host
		} else {
			str += fmt.Sprintf("%s:%d", host.Host, host.Port)
		}
	}

	if spec.Bucket != "" {
		str += "/" + spec.Bucket
	}

	if len(spec.Options) > 0 {
		str += "?" + spec.Options.Encode()
	}

	return str
}

type ResolvedConnSpec struct {
	UseSsl    bool
	CccpHosts []HostPortPair
	HttpHosts []HostPortPair
	Bucket    string
	Options   url.Values
}

func Parse(connStr string) (out ConnSpec, err error) {
	partMatcher := regexp.MustCompile(`((.*):\/\/)?(([^\/?:]*)(:([^\/?:@]*))?@)?([^\/?]*)(\/([^\?]*))?(\?(.*))?`)
	hostMatcher := regexp.MustCompile(`([^;\,\:]+)(:([0-9]*))?(;\,)?`)
	parts := partMatcher.FindStringSubmatch(connStr)

	if parts[2] != "" {
		out.Scheme = parts[2]

		if out.Scheme != "couchbase" && out.Scheme != "couchbases" && out.Scheme != "http" {
			err = errors.New("unknown scheme")
			return
		}
	}

	if parts[7] != "" {
		hosts := hostMatcher.FindAllStringSubmatch(parts[7], -1)
		for _, hostInfo := range hosts {
			var newHostPort HostPortPair

			newHostPort.Host = hostInfo[1]

			if hostInfo[3] != "" {
				newHostPort.Port, _ = strconv.Atoi(hostInfo[3])
			}

			out.Hosts = append(out.Hosts, newHostPort)
		}
	}

	if parts[9] != "" {
		out.Bucket, err = url.QueryUnescape(parts[9])
		if err != nil {
			return
		}
	}

	if parts[11] != "" {
		out.Options, err = url.ParseQuery(parts[11])
		if err != nil {
			return
		}
	}

	return
}

func ResolveAsDnsSrv(spec ConnSpec) (out ResolvedConnSpec, err error) {
	switch spec.Scheme {
	case "couchbase":
	case "couchbases":
	default:
		err = errors.New("unsupported scheme")
		return
	}

	srvRecordName := spec.SrvRecordName()
	if srvRecordName == "" {
		err = errors.New("not a srv connection string")
		return
	}

	_, addrs, _ := net.LookupSRV("", "", srvRecordName)

	if len(addrs) == 0 {
		err = errors.New("no srv records found")
		return
	}

	if spec.Scheme == "couchbases" {
		out.UseSsl = true
	} else {
		out.UseSsl = false
	}

	out.Bucket = spec.Bucket
	out.Options = spec.Options

	for _, addr := range addrs {
		out.CccpHosts = append(out.CccpHosts, HostPortPair{addr.Target, int(addr.Port)})
	}

	return
}

func ResolveAsHostList(spec ConnSpec) (out ResolvedConnSpec, err error) {
	switch spec.Scheme {
	case "couchbase":
	case "couchbases":
	case "http":
	default:
		err = errors.New("unsupported scheme")
		return
	}

	allHostsUseDefaultPorts := true
	for _, host := range spec.Hosts {
		if host.Port != 0 {
			allHostsUseDefaultPorts = false
			break
		}
	}

	isSslScheme := (spec.Scheme == "couchbases")

	genCccpList := false
	genHttpList := false

	if spec.Scheme == "couchbase" || spec.Scheme == "couchbases" {
		genCccpList = true

		if allHostsUseDefaultPorts {
			genHttpList = true
		}
	} else if spec.Scheme == "http" {
		genHttpList = true

		if allHostsUseDefaultPorts {
			genCccpList = true
		}
	} else {
		panic(0)
	}

	out.UseSsl = isSslScheme

	if spec.Bucket != "" {
		out.Bucket = spec.Bucket
	} else {
		out.Bucket = "default"
	}

	out.Options = spec.Options

	if genCccpList {
		for _, host := range spec.Hosts {
			cccpPort := host.Port

			if cccpPort == 0 {
				if !isSslScheme {
					cccpPort = 11210
				} else {
					cccpPort = 11207
				}
			}

			out.CccpHosts = append(out.CccpHosts, HostPortPair{host.Host, cccpPort})
		}
	}

	if genHttpList {
		for _, host := range spec.Hosts {
			httpPort := host.Port

			if httpPort == 0 {
				if !isSslScheme {
					httpPort = 8091
				} else {
					httpPort = 18091
				}
			}

			out.HttpHosts = append(out.HttpHosts, HostPortPair{host.Host, httpPort})
		}
	}

	return
}

func Resolve(spec ConnSpec) (out ResolvedConnSpec, err error) {
	out, resolveErr := ResolveAsDnsSrv(spec)
	if resolveErr == nil {
		return
	}

	out, err = ResolveAsHostList(spec)
	return
}
