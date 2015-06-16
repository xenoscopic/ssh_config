package ssh_config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

type (
	Config struct {
		Source  []byte
		Globals []*Param
		Hosts   []*Host
	}
	Host struct {
		Comments []string
		Hostname string
		Params   []*Param
	}
	Param struct {
		Comments []string
		Keyword  string
		Args     string
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

func NewHost(hostname string, comments []string) *Host {
	return &Host{
		Comments: comments,
		Hostname: hostname,
	}
}

func NewParam(keyword string, args string, comments []string) *Param {
	return &Param{
		Comments: comments,
		Keyword:  keyword,
		Args:     args,
	}
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
		psc.Split(scanParts)
		if !psc.Scan() {
			continue
		}

		param.Keyword = psc.Text()

		if psc.Scan() {
			param.Args = psc.Text()
		}

		if param.Keyword == HostKeyword {
			global = false
			if host != nil {
				config.Hosts = append(config.Hosts, host)
			}
			host = &Host{
				Comments: param.Comments,
				Hostname: param.Args,
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

func scanParts(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces and double quotes.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !unicode.IsSpace(r) || r == '"' {
			break
		}
	}
	// Scan until space or double quote, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if unicode.IsSpace(r) || r == '"' {
			return i + width, data[start:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data[start:], nil
	}
	// Request more data.
	return start, nil, nil
}

func (config *Config) WriteTo(w io.Writer) error {

	fmt.Fprintln(w, FileHeader)
	fmt.Fprintln(w)
	fmt.Fprintln(w, GlobalConfigurationHeader)

	for _, param := range config.Globals {
		if len(param.Comments) > 0 {
			fmt.Fprintln(w)
		}
		for _, comment := range param.Comments {
			if !strings.HasPrefix(comment, "#") {
				comment = "# " + comment
			}
			fmt.Fprintln(w, comment)
		}
		fmt.Fprintf(w, "%s %s\n", param.Keyword, param.Args)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, HostConfigurationHeader)

	for _, host := range config.Hosts {
		if len(host.Comments) > 0 {
			fmt.Fprintln(w)
			for _, comment := range host.Comments {
				if !strings.HasPrefix(comment, "#") {
					comment = "# " + comment
				}
				fmt.Fprintln(w, comment)
			}
		} else {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s %s\n", HostKeyword, host.Hostname)
		for _, param := range host.Params {
			for _, comment := range param.Comments {
				if !strings.HasPrefix(comment, "#") {
					comment = "# " + comment
				}
				fmt.Fprintln(w, comment)
			}
			fmt.Fprintf(w, "  %s %s\n", param.Keyword, param.Args)
		}
	}

	return nil
}

func (config *Config) WriteToFile(file *os.File) error {

	if err := file.Truncate(0); err != nil {
		// for some reason the error is generic here and sniffing the trace
		// has shown likely causes, including in error for possible quick fixing.
		if strings.Contains(err.Error(), "invalid argument") {
			return fmt.Errorf("%s, possible cause (file permissions or opened as read-only)", err)
		}
		return err
	}

	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	if err := config.WriteTo(file); err != nil {
		err = fmt.Errorf("WriteTo err: %s (rolling back...)", err)
		if _, rollbackErr := file.Write(config.Source); rollbackErr != nil {
			err = fmt.Errorf("%s, Rollback err: %s\nOriginal Source:\n\n%s", err, rollbackErr, config.Source)
		}
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
		if host.Hostname == hostname {
			return host
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
