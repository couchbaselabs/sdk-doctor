package cmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/couchbaselabs/gocbconnstr"
	"github.com/couchbaselabs/sdk-doctor/helpers"
	"github.com/spf13/cobra"
)

func stripIPv6Address(address string) string {
	if strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]") {
		return address[1 : len(address)-1]
	}
	return address
}

// diagnoseCmd represents the diagnose command
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose [connection_string]",
	Short: "Diagnose checks for problems with your configuration",
	Long: `Diagnose runs various tests against your network and cluster
to identify any flaws in your configuration that would cause failures
in development or production environments.`,
	RunE: runDiagnose,
}

var (
	tlsCaArg          string
	usernameArg       string
	passwordArg       string
	bucketPasswordArg string
)

func init() {
	RootCmd.AddCommand(diagnoseCmd)

	diagnoseCmd.PersistentFlags().StringVarP(&tlsCaArg, "tls-ca", "a", "", "certificate authority")
	diagnoseCmd.PersistentFlags().StringVarP(&usernameArg, "username", "u", "", "username")
	diagnoseCmd.PersistentFlags().StringVarP(&passwordArg, "password", "p", "", "password")
	diagnoseCmd.PersistentFlags().StringVarP(&bucketPasswordArg, "bucket-password", "z", "", "bucket password (deprecated, use password instead)")
}

var gLog helpers.Logger

func runDiagnose(cmd *cobra.Command, args []string) error {
	fmt.Printf(
		"Note: Diagnostics can only provide accurate results when your cluster\n" +
			" is in a stable state.  Active rebalancing and other cluster configuration\n" +
			" changes can cause the output of the doctor to be inconsistent or in the\n" +
			" worst cases, completely incorrect.\n")
	fmt.Printf("\n")

	var connStr string
	if len(args) < 1 {
		connStr = "couchbase://localhost"
		gLog.Warn("No connection string specified, defaulting to `%s`", connStr)
	} else {
		connStr = args[0]
	}

	var tlsConfig *tls.Config
	if tlsCaArg != "" {
		caCertData, err := ioutil.ReadFile(tlsCaArg)
		if err != nil {
			gLog.Error("Failed to read specified TLS certificate authority: %s", err)
			return nil
		}

		rootCAs := x509.NewCertPool()
		rootCAs.AppendCertsFromPEM(caCertData)

		tlsConfig = &tls.Config{}
		tlsConfig.RootCAs = rootCAs
	}

	if passwordArg == "" && bucketPasswordArg != "" {
		passwordArg = bucketPasswordArg
	}
	diagnose(connStr, usernameArg, passwordArg, tlsConfig)

	gLog.Log("Diagnostics completed")
	gLog.NewLine()

	gLog.PrintSummary()

	return nil
}

type clusterConfigNode struct {
	OptNode           string         `json:"optNode"`
	ThisNode          bool           `json:"thisNode"`
	CouchAPIBase      string         `json:"couchApiBase"`
	CouchAPIBaseHTTPS string         `json:"couchApiBaseHTTPS"`
	Status            string         `json:"status"`
	Hostname          string         `json:"hostname"`
	Version           string         `json:"version"`
	Os                string         `json:"os"`
	Ports             map[string]int `json:"Ports"`
	Services          []string       `json:"services"`
}

type clusterConfig struct {
	Nodes   []clusterConfigNode `json:"nodes"`
	Buckets struct {
		URI string `json:"uri"`
	} `json:"buckets"`
}

type bucketConfigAlternateNames struct {
	Hostname string         `json:"hostname"`
	Ports    map[string]int `json:"ports"`
}

type bucketConfigNodeExt struct {
	ThisNode       bool                                  `json:"thisNode"`
	Hostname       string                                `json:"hostname"`
	Services       map[string]int                        `json:"services"`
	AlternateNames map[string]bucketConfigAlternateNames `json:"alternateAddresses"`
}

type terseBucketConfig struct {
	SourceHost string
	UUID       string                `json:"uuid"`
	Rev        uint                  `json:"rev"`
	NodesExt   []bucketConfigNodeExt `json:"nodesExt"`
}

func (config *terseBucketConfig) GetSourceNodeExt() *bucketConfigNodeExt {
	for _, node := range config.NodesExt {
		if node.ThisNode {
			return &node
		}
	}

	return nil
}

type clusterNode struct {
	Hostname string
	Services map[string]int
}

func clusterNodesFromTerseBucketConfig(config terseBucketConfig, networkType string) []clusterNode {
	var out []clusterNode

	for _, node := range config.NodesExt {
		var newNode clusterNode

		if node.Hostname == "" {
			newNode.Hostname = config.SourceHost
		} else {
			newNode.Hostname = node.Hostname
		}

		newNode.Services = node.Services

		if networkType != "default" {
			netInfo, found := node.AlternateNames[networkType]
			if !found {
				return nil
			}

			if netInfo.Hostname != "" {
				newNode.Hostname = netInfo.Hostname
			}
			if netInfo.Ports != nil {
				newNode.Services = netInfo.Ports
			}
		}

		out = append(out, newNode)
	}

	return out
}

func networkFromTerseBucketConfig(config terseBucketConfig) string {
	// Check if we connected using any of the ports associated with the default
	// configurations that are available.
	for _, node := range config.NodesExt {
		for _, svcPort := range node.Services {
			if fmt.Sprintf("%s:%d", node.Hostname, svcPort) == config.SourceHost {
				return "default"
			}
		}
	}

	for _, node := range config.NodesExt {
		if _, found := node.AlternateNames["external"]; found {
			return "external"
		}
	}

	return "default"
}

func fetchHTTPTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, error) {
	if user == "" {
		user = bucket
	}

	httpTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	httpClient := &http.Client{
		Transport: httpTransport,
		Timeout:   2000 * time.Millisecond,
	}

	uri := fmt.Sprintf("http://%s:%d/pools/default/b/%s", host, port, bucket)
	req, _ := http.NewRequest("GET", uri, nil)
	req.SetBasicAuth(user, pass)

	resp, err := httpClient.Do(req)
	if err != nil {
		return terseBucketConfig{}, err
	}

	if resp.StatusCode != 200 {
		if resp.StatusCode == 401 {
			return terseBucketConfig{}, errors.New("incorrect bucket/password")
		}

		return terseBucketConfig{}, fmt.Errorf("http error (status code: %d)", resp.StatusCode)
	}

	configBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, err
	}

	config.SourceHost = host

	return config, nil
}

func fetchCccpTerseBucketConfig(host string, port int, bucket, user, pass string, tlsConfig *tls.Config) (terseBucketConfig, error) {
	if user == "" {
		user = bucket
	}

	client, err := helpers.Dial(host, port, bucket, user, pass, tlsConfig)
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes, err := client.GetConfig()
	if err != nil {
		return terseBucketConfig{}, err
	}

	configBytes = bytes.Replace(configBytes, []byte("$HOST"), []byte(host), -1)

	var config terseBucketConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return terseBucketConfig{}, err
	}

	config.SourceHost = host

	return config, nil
}

func diagnose(connStr, username, password string, tlsConfig *tls.Config) {
	//======================================================================
	//  CONNECTION STRING
	//======================================================================
	gLog.Log("Parsing connection string `%s`", connStr)

	connSpec, err := gocbconnstr.Parse(connStr)
	if err != nil {
		gLog.Error("Failed to parse connection string of `%s` (error: %s)",
			connStr, err.Error())
	}

	connSpecSrv := connSpec.SrvRecordName()
	if connSpecSrv != "" {
		gLog.Log("Connection string was parsed as a potential DNS SRV record")
	}

	if connSpec.Scheme == "http" {
		gLog.Warn(
			"Connection string is using the deprecated `http://` scheme.  Use" +
				" the `couchbase://` scheme instead!")
	}

	resConnSpec, err := gocbconnstr.Resolve(connSpec)
	if err != nil {
		gLog.Error("Failed to properly resolve connection string `%s` (error: %s)",
			connStr, err.Error())
	}

	if resConnSpec.UseSsl {
		gLog.Log("Connection string specifies to use secured connections")

		if tlsConfig == nil {
			gLog.Warn("No certificate authority file specified (--tls-ca), skipping" +
				" server certificate verification for this run.")

			tlsConfig = &tls.Config{
				InsecureSkipVerify: true,
			}
		}
	} else {
		tlsConfig = nil
	}

	gLog.Log("Connection string identifies the following CCCP endpoints:")
	for i, host := range resConnSpec.MemdHosts {
		gLog.Log("  %d. %s:%d", i+1, host.Host, host.Port)
	}

	gLog.Log("Connection string identifies the following HTTP endpoints:")
	for i, host := range resConnSpec.HttpHosts {
		gLog.Log("  %d. %s:%d", i+1, host.Host, host.Port)
	}

	gLog.Log("Connection string specifies bucket `%s`", resConnSpec.Bucket)

	//======================================================================
	//  DNS
	//======================================================================
	warnSingleHost := false
	if len(connSpec.Addresses) == 1 {
		warnSingleHost = true
	}

	dnsHosts := connSpec.Addresses
	if connSpecSrv != "" {
		_, srvAddrs, _ := net.LookupSRV("", "", connSpecSrv)
		aAddrs, _ := net.LookupHost(connSpec.Addresses[0].Host)

		if len(srvAddrs) > 0 {
			// Don't warn for single-hosts if using DNS SRV
			warnSingleHost = false

			// Replace the hosts for DNS testing with the values from the DNS SRV record
			dnsHosts = []gocbconnstr.Address{}
			for _, addr := range srvAddrs {
				addrTarget := addr.Target
				addrPort := int(addr.Port)

				if !strings.HasSuffix(addrTarget, ".") {
					gLog.Warn(
						"The hostname specified in one of the SRV records was missing the trailing" +
							" dot which is expected to make a valid SRV record entry.")
				}

				addrTarget = strings.TrimSuffix(addrTarget, ".")

				dnsHosts = append(dnsHosts, gocbconnstr.Address{
					Host: addrTarget,
					Port: addrPort,
				})
			}
		}

		if len(srvAddrs) > 0 && len(aAddrs) > 0 {
			gLog.Warn(
				"The hostname specified in your connection string resolves both for SRV" +
					" records, as well as A records.  This is not suggested as later DNS" +
					" configuration changes could cause the wrong servers to be contacted")
		}
	}

	if warnSingleHost {
		gLog.Warn(
			"Your connection string specifies only a single host.  You should" +
				" consider adding additional static nodes from your cluster to this" +
				" list to improve your applications fault-tolerance")
	}

	for _, target := range dnsHosts {
		strippedHost := stripIPv6Address(target.Host)

		gLog.Log("Performing DNS lookup for host `%s`", strippedHost)

		addrs, err := net.LookupHost(strippedHost)

		if err != nil {
			if dnsErr, ok := err.(*net.DNSError); ok {
				if dnsErr.Err == "no such host" {
					err = nil
					addrs = nil
				}
			} else {
				gLog.Error(
					"Failed to perform DNS lookup for bootstrap entry `%s` (error: %s)",
					err)
				continue
			}
		}

		if err != nil || len(addrs) == 0 {
			gLog.Error(
				"Bootstrap host `%s` does not have a valid DNS entry.",
				strippedHost)
			continue
		} else if len(addrs) > 1 {
			gLog.Warn(
				"Bootstrap host `%s` has more than one single DNS entry associated.  While this"+
					" is not neccessarily an error, it has been known to cause difficult-to-diagnose"+
					" problems in the future when routing is changed or the cluster layout is updated.",
				strippedHost)
		} else if addrs[0] != strippedHost {
			gLog.Log(
				"Bootstrap host `%s` refers to a server with the address `%s`",
				strippedHost, addrs[0])
		}

		// Check for any IPv6 addresses
		ips, _ := net.LookupIP(strippedHost)

		hasIPv6 := false
		for _, ip := range ips {
			if ip.To4() == nil {
				hasIPv6 = true
			}
		}
		if hasIPv6 {
			gLog.Log(
				"Bootstrap host `%s` has IPv6 addresses associated. This is only supported"+
					" in Couchbase Server 5.5 or later, and must be specifically enabled on"+
					" the cluster.",
				strippedHost)
		}
	}

	//======================================================================
	//  BOOTSTRAP
	//======================================================================
	var nodesList []clusterNode
	var selectedNetwork string
	var configSource string

	// Scans a list of hosts and configurations and logs any appropriate warnings then returns
	//  the first good configuration that it actually encounters (or nil if none are found).
	scanTerseConfigList := func(hosts []gocbconnstr.Address, configs []*terseBucketConfig) *terseBucketConfig {
		if len(hosts) != len(configs) {
			panic(0)
		}

		var masterConfig *terseBucketConfig

		for i, target := range hosts {
			config := configs[i]

			if config == nil {
				continue
			}

			if masterConfig == nil {
				masterConfig = config
			} else {
				if config.UUID != masterConfig.UUID {
					gLog.Error(
						"Boostrap host `%s` appears to be pointing to a different cluster.  Tests"+
							" will be running against the first successfully connected node in your"+
							" bootstrap list, as a client would behave.",
						target.Host)
				}
			}

			thisNodeExt := config.GetSourceNodeExt()
			if thisNodeExt.Hostname != "" && target.Host != thisNodeExt.Hostname {
				gLog.Warn(
					"Bootstrap host `%s` is not using the canonical node hostname of `%s`.  This"+
						" is not neccessarily an error, but has been known to result in strange and"+
						" challenging to diagnose errors when DNS entries are reconfigured.",
					target.Host, thisNodeExt.Hostname)
			}
		}

		return masterConfig
	}

	// Attempt to bootstrap via CCCP
	if nodesList == nil {
		if len(resConnSpec.MemdHosts) == 0 {
			gLog.Log("Not attempting CCCP, as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via CCCP")

			configs := make([]*terseBucketConfig, len(resConnSpec.MemdHosts))

			for i, target := range resConnSpec.MemdHosts {
				gLog.Log("Attempting to fetch config via cccp from `%s:%d`", target.Host, target.Port)

				// Query the host
				config, err := fetchCccpTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
				if err != nil {
					gLog.Error(
						"Failed to fetch configuration via cccp from `%s:%d` (error: %s)",
						target.Host, target.Port, err.Error())

					continue
				}

				configs[i] = &config
			}

			masterConfig := scanTerseConfigList(resConnSpec.MemdHosts, configs)
			if masterConfig != nil {
				if selectedNetwork == "" {
					selectedNetwork = networkFromTerseBucketConfig(*masterConfig)
				}
				nodesList = clusterNodesFromTerseBucketConfig(*masterConfig, selectedNetwork)
				configSource = "cccp"
			}
		}
	}

	// Attempt to bootstrap via Terse HTTP endpoints
	if nodesList == nil {
		if len(resConnSpec.HttpHosts) == 0 {
			gLog.Log("Not attempting HTTP (Terse), as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via HTTP (Terse)")

			configs := make([]*terseBucketConfig, len(resConnSpec.HttpHosts))

			for i, target := range resConnSpec.HttpHosts {
				gLog.Log("Attempting to fetch terse config via http from `%s:%d`", target.Host, target.Port)

				// Query the host
				config, err := fetchHTTPTerseBucketConfig(target.Host, target.Port, resConnSpec.Bucket, username, password, tlsConfig)
				if err != nil {
					gLog.Error(
						"Failed to fetch terse configuration via http from `%s:%d` (error: %s)",
						target.Host, target.Port, err.Error())

					continue
				}

				configs[i] = &config
			}

			masterConfig := scanTerseConfigList(resConnSpec.HttpHosts, configs)
			if masterConfig != nil {
				if selectedNetwork == "" {
					selectedNetwork = networkFromTerseBucketConfig(*masterConfig)
				}
				nodesList = clusterNodesFromTerseBucketConfig(*masterConfig, selectedNetwork)
				configSource = "http-terse"
			}
		}
	}

	// Attempt to bootstrap via full HTTP endpoints
	if nodesList == nil {
		if len(resConnSpec.HttpHosts) == 0 {
			gLog.Log("Not attempting HTTP (Full), as the connection string does not support it")
		} else {
			gLog.Log("Attempting to connect to cluster via HTTP (Full)")

			// TODO: Add support for full HTTP configuration fetching

			gLog.Log("Failed to connect via HTTP (Full), as it is not yet supported by the doctor")
		}
	}

	// Print out information about which network type was selected
	gLog.Log("Selected the following network type: %s", selectedNetwork)

	// Failed to bootstrap
	if nodesList == nil {
		gLog.Error(
			"All endpoints specified by your connection string were unreachable, further" +
				" cluster diagnostics are not possible")
		return
	}

	gLog.Log("Identified the following nodes:")
	for i, target := range nodesList {
		gLog.Log("  [%d] %s", i, target.Hostname)

		serviceStr := ""
		serviceNum := 0
		for service, port := range target.Services {
			if serviceStr != "" {
				serviceStr += ", "
			}

			serviceStr += fmt.Sprintf("%20s:% 6d", service, port)

			if serviceNum%3 == 2 {
				gLog.Log("    %s", serviceStr)
				serviceStr = ""
			}

			serviceNum++
		}

		if serviceStr != "" {
			gLog.Log("    %s", serviceStr)
		}
	}

	if configSource != "cccp" {
		gLog.Warn(
			"Your configuration was fetched via a non-optimal path, you should update your" +
				" connection string and/or cluster configuration to allow CCCP config fetch")
	}

	//======================================================================
	//  CLUSTER INFORMATION
	//======================================================================
	{
		var infoSourceTarget *clusterNode

		infoSourceSvcKey := "mgmt"
		infoSourceScheme := "http"
		if tlsConfig != nil {
			infoSourceSvcKey = "mgmtSSL"
			infoSourceScheme = "https"
		}

		for _, target := range nodesList {
			if target.Services[infoSourceSvcKey] != 0 {
				infoSourceTarget = &target
				break
			}
		}

		if infoSourceTarget == nil {
			gLog.Log("Failed to retrieve cluster information as we couldn't find a node with management services")
		} else {
			infoSourceHost := infoSourceTarget.Hostname
			infoSourcePort := infoSourceTarget.Services[infoSourceSvcKey]

			gLog.Log("Fetching config from `%s://%s:%d`",
				infoSourceScheme,
				infoSourceHost,
				infoSourcePort)

			httpTransport := &http.Transport{
				TLSClientConfig: tlsConfig,
			}
			httpClient := &http.Client{
				Transport: httpTransport,
				Timeout:   2000 * time.Millisecond,
			}

			uri := fmt.Sprintf("%s://%s:%d/pools/default", infoSourceScheme, infoSourceHost, infoSourcePort)
			req, _ := http.NewRequest("GET", uri, nil)
			req.SetBasicAuth(username, password)

			resp, err := httpClient.Do(req)
			if err != nil {
				gLog.Log("Failed to retreive cluster information (error: %s)", err.Error())
			} else if resp.StatusCode != 200 {
				gLog.Log("Failed to retreive cluster information (status code: %d)", resp.StatusCode)
			} else {
				var clusterConfig map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&clusterConfig)

				fmtdConfigNodes, _ := json.MarshalIndent(clusterConfig["nodes"], "", "  ")
				gLog.Log("Received cluster configuration, nodes list:\n%s", fmtdConfigNodes)
			}
		}
	}

	//======================================================================
	//  SERVICES
	//======================================================================

	testHTTPTransport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	testHTTPClient := &http.Client{
		Transport: testHTTPTransport,
		Timeout:   2000 * time.Millisecond,
	}

	testMemdService := func(node clusterNode, svcName, svcKeyPlain, svcKeySSL string) {
		svcKey := svcKeyPlain
		if tlsConfig != nil {
			svcKey = svcKeySSL
		}

		svcPort := node.Services[svcKey]
		if svcPort != 0 {
			client, err := helpers.Dial(node.Hostname, svcPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
					svcName, node.Hostname, node.Services[svcKey], err.Error())
			} else {
				gLog.Log("Successfully connected to %s service at `%s:%d`",
					svcName, node.Hostname, node.Services[svcKey])

				client.Close()
			}
		} else {
			gLog.Warn("Could not test %s service on `%s` as it was not in the config", svcName, node.Hostname)
		}
	}

	testHTTPService := func(node clusterNode, svcName, svcKeyPlain, svcKeySSL string) {
		svcScheme := "http"
		svcKey := svcKeyPlain
		if tlsConfig != nil {
			svcScheme = "https"
			svcKey = svcKeySSL
		}

		svcPort := node.Services[svcKey]
		if svcPort != 0 {
			uri := fmt.Sprintf("%s://%s:%d/", svcScheme, node.Hostname, svcPort)
			req, _ := http.NewRequest("GET", uri, nil)
			// No credentials are set here since we only care that the service responds,
			//  not that it responds with anything in particular.

			_, err := testHTTPClient.Do(req)
			if err != nil {
				gLog.Error("Failed to connect to %s service at `%s:%d` (error: %s)",
					svcName, node.Hostname, node.Services[svcKey], err.Error())
			} else {
				gLog.Log("Successfully connected to %s service at `%s:%d`",
					svcName, node.Hostname, node.Services[svcKey])
			}
		} else {
			gLog.Warn("Could not test %s service on `%s` as it was not in the config", svcName, node.Hostname)
		}
	}

	for _, node := range nodesList {
		testMemdService(node, "Key Value", "kv", "kvSSL")
		testHTTPService(node, "Management", "mgmt", "mgmtSSL")
		testHTTPService(node, "Views", "capi", "capiSSL")
		testHTTPService(node, "Query", "n1ql", "n1qlSSL")
		testHTTPService(node, "Search", "fts", "ftsSSL")
		testHTTPService(node, "Analytics", "cbas", "cbasSSL")
	}

	//======================================================================
	//  CONNECTION PERFORMANCE
	//======================================================================
	for _, node := range nodesList {
		kvPort := node.Services["kv"]
		if tlsConfig != nil {
			kvPort = node.Services["kvSSL"]
		}

		if kvPort != 0 {
			client, err := helpers.Dial(node.Hostname, kvPort,
				resConnSpec.Bucket, username, password, tlsConfig)
			if err != nil {
				gLog.Warn(
					"Failed to perform KV connection performance analysis on `%s:%d` (error: %d)",
					node.Hostname, kvPort, err.Error())
				continue
			}

			var stats helpers.PingHelper

			for i := 0; i < 10; i++ {
				pingState := stats.StartOne()
				err = client.Ping()
				stats.StopOne(pingState, err)
			}

			gLog.Log("Memd Nop Pinged `%s:%d` %d times, %d errors, %dms min, %dms max, %dms mean",
				node.Hostname, kvPort,
				stats.Count(), stats.Errors(),
				stats.Min()/time.Millisecond,
				stats.Max()/time.Millisecond,
				stats.Mean()/time.Millisecond)

			allowedMeanMs := 10
			if stats.Mean() >= time.Duration(allowedMeanMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` on average took longer than %dms (was: %dms) to"+
						" reply.  This is usually due to network-related issues, and could significantly"+
						" affect application performance.",
					node.Hostname, kvPort,
					allowedMeanMs, stats.Mean()/time.Millisecond)
			}

			allowedMaxMs := 20
			if stats.Max() >= time.Duration(allowedMaxMs)*time.Millisecond {
				gLog.Warn(
					"Memcached service on `%s:%d` maximally took longer than %dms (was: %dms) to reply."+
						" This is usually due to network-related issues, and could significantly"+
						" affect application performance.",
					node.Hostname, kvPort,
					allowedMaxMs, stats.Max()/time.Millisecond)
			}
		}
	}
}
