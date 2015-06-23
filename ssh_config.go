package ssh_config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"
)

type (
	Config struct {
		Source  []byte
		Globals []*Param
		Hosts   []*Host
	}
	Host struct {
		Comments  []string
		Hostnames []string
		Params    []*Param
	}
	Param struct {
		Comments []string
		Keyword  string
		Args     []string
	}
)

const (
	HostKeyword                             = "Host"
	MatchKeyword                            = "Match"
	AddressFamilyKeyword                    = "AddressFamily"
	BatchModeKeyword                        = "BatchMode"
	BindAddressKeyword                      = "BindAddress"
	CanonicalDomainsKeyword                 = "CanonicalDomains"
	CanonicalizeFallbackLocalKeyword        = "CanonicalizeFallbackLocal"
	CanonicalizeHostnameKeyword             = "CanonicalizeHostname"
	CanonicalizeMaxDotsKeyword              = "CanonicalizeMaxDots"
	CanonicalizePermittedCNAMEsKeyword      = "CanonicalizePermittedCNAMEs"
	ChallengeResponseAuthenticationKeyword  = "ChallengeResponseAuthentication"
	CheckHostIPKeyword                      = "CheckHostIP"
	CipherKeyword                           = "Cipher"
	CiphersKeyword                          = "Ciphers"
	ClearAllForwardingsKeyword              = "ClearAllForwardings"
	CompressionKeyword                      = "Compression"
	CompressionLevelKeyword                 = "CompressionLevel"
	ConnectionAttemptsKeyword               = "ConnectionAttempts"
	ConnectTimeoutKeyword                   = "ConnectTimeout"
	ControlMasterKeyword                    = "ControlMaster"
	ControlPathKeyword                      = "ControlPath"
	ControlPersistKeyword                   = "ControlPersist"
	DynamicForwardKeyword                   = "DynamicForward"
	EnableSSHKeysignKeyword                 = "EnableSSHKeysign"
	EscapeCharKeyword                       = "EscapeChar"
	ExitOnForwardFailureKeyword             = "ExitOnForwardFailure"
	FingerprintHashKeyword                  = "FingerprintHash"
	ForwardAgentKeyword                     = "ForwardAgent"
	ForwardX11Keyword                       = "ForwardX11"
	ForwardX11TimeoutKeyword                = "ForwardX11Timeout"
	ForwardX11TrustedKeyword                = "ForwardX11Trusted"
	GatewayPortsKeyword                     = "GatewayPorts"
	GlobalKnownHostsFileKeyword             = "GlobalKnownHostsFile"
	GSSAPIAuthenticationKeyword             = "GSSAPIAuthentication"
	GSSAPIDelegateCredentialsKeyword        = "GSSAPIDelegateCredentials"
	HashKnownHostsKeyword                   = "HashKnownHosts"
	HostbasedAuthenticationKeyword          = "HostbasedAuthentication"
	HostbasedKeyTypesKeyword                = "HostbasedKeyTypes"
	HostKeyAlgorithmsKeyword                = "HostKeyAlgorithms"
	HostKeyAliasKeyword                     = "HostKeyAlias"
	HostNameKeyword                         = "HostName"
	IdentitiesOnlyKeyword                   = "IdentitiesOnly"
	IdentityFileKeyword                     = "IdentityFile"
	IgnoreUnknownKeyword                    = "IgnoreUnknown"
	IPQoSKeyword                            = "IPQoS"
	KbdInteractiveAuthenticationKeyword     = "KbdInteractiveAuthentication"
	KbdInteractiveDevicesKeyword            = "KbdInteractiveDevices"
	KexAlgorithmsKeyword                    = "KexAlgorithms"
	LocalCommandKeyword                     = "LocalCommand"
	LocalForwardKeyword                     = "LocalForward"
	LogLevelKeyword                         = "LogLevel"
	MACsKeyword                             = "MACs"
	NoHostAuthenticationForLocalhostKeyword = "NoHostAuthenticationForLocalhost"
	NumberOfPasswordPromptsKeyword          = "NumberOfPasswordPrompts"
	PasswordAuthenticationKeyword           = "PasswordAuthentication"
	PermitLocalCommandKeyword               = "PermitLocalCommand"
	PKCS11ProviderKeyword                   = "PKCS11Provider"
	PortKeyword                             = "Port"
	PreferredAuthenticationsKeyword         = "PreferredAuthentications"
	ProtocolKeyword                         = "Protocol"
	ProxyCommandKeyword                     = "ProxyCommand"
	ProxyUseFdpassKeyword                   = "ProxyUseFdpass"
	PubkeyAuthenticationKeyword             = "PubkeyAuthentication"
	RekeyLimitKeyword                       = "RekeyLimit"
	RemoteForwardKeyword                    = "RemoteForward"
	RequestTTYKeyword                       = "RequestTTY"
	RevokedHostKeysKeyword                  = "RevokedHostKeys"
	RhostsRSAAuthenticationKeyword          = "RhostsRSAAuthentication"
	RSAAuthenticationKeyword                = "RSAAuthentication"
	SendEnvKeyword                          = "SendEnv"
	ServerAliveCountMaxKeyword              = "ServerAliveCountMax"
	ServerAliveIntervalKeyword              = "ServerAliveInterval"
	StreamLocalBindMaskKeyword              = "StreamLocalBindMask"
	StreamLocalBindUnlinkKeyword            = "StreamLocalBindUnlink"
	StrictHostKeyCheckingKeyword            = "StrictHostKeyChecking"
	TCPKeepAliveKeyword                     = "TCPKeepAlive"
	TunnelKeyword                           = "Tunnel"
	TunnelDeviceKeyword                     = "TunnelDevice"
	UpdateHostKeysKeyword                   = "UpdateHostKeys"
	UsePrivilegedPortKeyword                = "UsePrivilegedPort"
	UserKeyword                             = "User"
	UserKnownHostsFileKeyword               = "UserKnownHostsFile"
	VerifyHostKeyDNSKeyword                 = "VerifyHostKeyDNS"
	VisualHostKeyKeyword                    = "VisualHostKey"
	XAuthLocationKeyword                    = "XAuthLocation"

	FileHeader                = "# ssh config generated by some go code (github.com/jasonmoo/ssh_config)"
	GlobalConfigurationHeader = "# global configuration"
	HostConfigurationHeader   = "# host-based configuration"
)

func NewHost(hostnames []string, comments []string) *Host {
	return &Host{
		Comments:  comments,
		Hostnames: hostnames,
	}
}

func (host *Host) String() string {

	buf := &bytes.Buffer{}

	fmt.Fprintln(buf)
	if len(host.Comments) > 0 {
		for _, comment := range host.Comments {
			if !strings.HasPrefix(comment, "#") {
				comment = "# " + comment
			}
			fmt.Fprintln(buf, comment)
		}
	}

	fmt.Fprintf(buf, "%s %s\n", HostKeyword, strings.Join(host.Hostnames, " "))
	for _, param := range host.Params {
		fmt.Fprint(buf, "  ", param.String())
	}

	return buf.String()

}

func NewParam(keyword string, args []string, comments []string) *Param {
	return &Param{
		Comments: comments,
		Keyword:  keyword,
		Args:     args,
	}
}

func (param *Param) String() string {

	buf := &bytes.Buffer{}

	if len(param.Comments) > 0 {
		fmt.Fprintln(buf)
		for _, comment := range param.Comments {
			if !strings.HasPrefix(comment, "#") {
				comment = "# " + comment
			}
			fmt.Fprintln(buf, comment)
		}
	}

	fmt.Fprintf(buf, "%s %s\n", param.Keyword, strings.Join(param.Args, " "))

	return buf.String()

}

func (param *Param) Value() string {
	if len(param.Args) > 0 {
		return param.Args[0]
	}
	return ""
}

func Parse(r io.Reader) (*Config, error) {

	// dat state
	var (
		global = true

		param = &Param{}
		host  *Host
	)

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	config := &Config{
		Source: data,
	}

	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {

		line := strings.TrimSpace(sc.Text())
		if len(line) == 0 {
			continue
		}

		switch line {
		case FileHeader,
			GlobalConfigurationHeader,
			HostConfigurationHeader:
			continue
		}

		if line[0] == '#' {
			param.Comments = append(param.Comments, line)
			continue
		}

		psc := bufio.NewScanner(strings.NewReader(line))
		psc.Split(bufio.ScanWords)
		if !psc.Scan() {
			continue
		}

		param.Keyword = psc.Text()

		for psc.Scan() {
			param.Args = append(param.Args, psc.Text())
		}

		if param.Keyword == HostKeyword {
			global = false
			if host != nil {
				config.Hosts = append(config.Hosts, host)
			}
			host = &Host{
				Comments:  param.Comments,
				Hostnames: param.Args,
			}
			param = &Param{}
			continue
		} else if global {
			config.Globals = append(config.Globals, param)
			param = &Param{}
			continue
		}

		host.Params = append(host.Params, param)
		param = &Param{}

	}

	if global {
		config.Globals = append(config.Globals, param)
	} else if host != nil {
		config.Hosts = append(config.Hosts, host)
	}

	return config, nil

}

func (config *Config) WriteTo(w io.Writer) error {

	fmt.Fprintln(w, FileHeader)
	fmt.Fprintln(w)
	fmt.Fprintln(w, GlobalConfigurationHeader)

	for _, param := range config.Globals {
		fmt.Fprint(w, param.String())
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, HostConfigurationHeader)

	for _, host := range config.Hosts {
		fmt.Fprint(w, host.String())
	}

	return nil
}

func (config *Config) WriteToFilepath(file_path string) error {

	// create a tmp file in the same path with the same mode
	tmp_file_path := file_path + "." + strconv.FormatInt(time.Now().UnixNano(), 10)

	stat, err := os.Stat(file_path)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(tmp_file_path, os.O_CREATE|os.O_WRONLY|os.O_EXCL|os.O_SYNC, stat.Mode())
	if err != nil {
		return err
	}

	if err := config.WriteTo(file); err != nil {
		file.Close()
		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmp_file_path, file_path); err != nil {
		return err
	}

	return nil

}

func (config *Config) GetParam(keyword string) *Param {
	for _, param := range config.Globals {
		if param.Keyword == keyword {
			return param
		}
	}
	return nil
}

func (config *Config) GetHost(hostname string) *Host {
	for _, host := range config.Hosts {
		for _, hn := range host.Hostnames {
			if hn == hostname {
				return host
			}
		}
	}
	return nil
}

func (host *Host) GetParam(keyword string) *Param {
	for _, param := range host.Params {
		if param.Keyword == keyword {
			return param
		}
	}
	return nil
}

func (config *Config) FindByHostname(hostname string) *Host {
	for _, host := range config.Hosts {
		for _, hn := range host.Hostnames {
			if hn == hostname {
				return host
			}
		}
		if hns := host.GetParam(HostNameKeyword); hn != nil {
			for _, hn := range hns {
				if hn == hostname {
					return host
				}
			}
		}
	}
	return nil
}
