package config

import (
	"github.com/containous/flaeg/parse"
	"github.com/containous/traefik/ip"
)

type Router struct {
	EntryPoints []string `json:"entryPoints"`
	Middlewares []string `json:"middlewares,omitempty"`
	Service     string   `json:"service"`
	Rule        string   `json:"rule,omitempty"`
}

type LoadBalancerService struct {
	Stickiness     *Stickiness  `json:"stickiness,omitempty"`
	Servers        []Server     `json:"servers,omitempty"`
	Method         string       `json:"method,omitempty"`
	HealthCheck    *HealthCheck `json:"healthCheck,omitempty"`
	PassHostHeader bool         `json:"passHostHeader"`
}

type Stickiness struct {
	CookieName string `json:"cookieName,omitempty"`
}

type Server struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// HealthCheck holds HealthCheck configuration
type HealthCheck struct {
	Scheme   string            `json:"scheme,omitempty"`
	Path     string            `json:"path,omitempty"`
	Port     int               `json:"port,omitempty"`
	Interval string            `json:"interval,omitempty"`
	Hostname string            `json:"hostname,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
}

type Middleware struct {
	WhiteList *WhiteList            `json:"whiteList,omitempty"`
	Headers   *Headers              `json:"headers,omitempty"`
	Errors    map[string]*ErrorPage `json:"errors,omitempty"`
	RateLimit *RateLimit            `json:"ratelimit,omitempty"`
	Redirect  *Redirect             `json:"redirect,omitempty"`
	Auth      *Auth                 `json:"auth,omitempty"`
	Chain     *Chain                `json:"chain,omitempty"`
}

type Chain struct {
	Middlewares []string `json:"middlewares"`
}

// WhiteList contains white list configuration.
type WhiteList struct {
	SourceRange []string    `json:"sourceRange,omitempty"`
	IPStrategy  *IPStrategy `json:"ipStrategy,omitempty"`
}

// Headers holds the custom header configuration
type Headers struct {
	CustomRequestHeaders  map[string]string `json:"customRequestHeaders,omitempty"`
	CustomResponseHeaders map[string]string `json:"customResponseHeaders,omitempty"`

	AllowedHosts            []string          `json:"allowedHosts,omitempty"`
	HostsProxyHeaders       []string          `json:"hostsProxyHeaders,omitempty"`
	SSLRedirect             bool              `json:"sslRedirect,omitempty"`
	SSLTemporaryRedirect    bool              `json:"sslTemporaryRedirect,omitempty"`
	SSLHost                 string            `json:"sslHost,omitempty"`
	SSLProxyHeaders         map[string]string `json:"sslProxyHeaders,omitempty"`
	SSLForceHost            bool              `json:"sslForceHost,omitempty"`
	STSSeconds              int64             `json:"stsSeconds,omitempty"`
	STSIncludeSubdomains    bool              `json:"stsIncludeSubdomains,omitempty"`
	STSPreload              bool              `json:"stsPreload,omitempty"`
	ForceSTSHeader          bool              `json:"forceSTSHeader,omitempty"`
	FrameDeny               bool              `json:"frameDeny,omitempty"`
	CustomFrameOptionsValue string            `json:"customFrameOptionsValue,omitempty"`
	ContentTypeNosniff      bool              `json:"contentTypeNosniff,omitempty"`
	BrowserXSSFilter        bool              `json:"browserXssFilter,omitempty"`
	CustomBrowserXSSValue   string            `json:"customBrowserXSSValue,omitempty"`
	ContentSecurityPolicy   string            `json:"contentSecurityPolicy,omitempty"`
	PublicKey               string            `json:"publicKey,omitempty"`
	ReferrerPolicy          string            `json:"referrerPolicy,omitempty"`
	IsDevelopment           bool              `json:"isDevelopment,omitempty"`
}

func (h *Headers) HasCustomHeadersDefined() bool {
	return h != nil && (len(h.CustomResponseHeaders) != 0 ||
		len(h.CustomRequestHeaders) != 0)
}

// HasSecureHeadersDefined checks to see if any of the secure header elements have been set
func (h *Headers) HasSecureHeadersDefined() bool {
	return h != nil && (len(h.AllowedHosts) != 0 ||
		len(h.HostsProxyHeaders) != 0 ||
		h.SSLRedirect ||
		h.SSLTemporaryRedirect ||
		h.SSLForceHost ||
		h.SSLHost != "" ||
		len(h.SSLProxyHeaders) != 0 ||
		h.STSSeconds != 0 ||
		h.STSIncludeSubdomains ||
		h.STSPreload ||
		h.ForceSTSHeader ||
		h.FrameDeny ||
		h.CustomFrameOptionsValue != "" ||
		h.ContentTypeNosniff ||
		h.BrowserXSSFilter ||
		h.CustomBrowserXSSValue != "" ||
		h.ContentSecurityPolicy != "" ||
		h.PublicKey != "" ||
		h.ReferrerPolicy != "" ||
		h.IsDevelopment)
}

// ErrorPage holds custom error page configuration
type ErrorPage struct {
	Status  []string `json:"status,omitempty"`
	Backend string   `json:"backend,omitempty"`
	Query   string   `json:"query,omitempty"`
}

// RateLimit holds a rate limiting configuration for a given frontend
type RateLimit struct {
	RateSet       map[string]*Rate `json:"rateset,omitempty"`
	ExtractorFunc string           `json:"extractorFunc,omitempty"`
}

// Rate holds a rate limiting configuration for a specific time period
type Rate struct {
	Period  parse.Duration `json:"period,omitempty"`
	Average int64          `json:"average,omitempty"`
	Burst   int64          `json:"burst,omitempty"`
}

// Redirect configures a redirection of an entry point to another, or to an URL
type Redirect struct {
	EntryPoint  string `json:"entryPoint,omitempty"`
	Regex       string `json:"regex,omitempty"`
	Replacement string `json:"replacement,omitempty"`
	Permanent   bool   `json:"permanent,omitempty"`
}

// Auth holds authentication configuration (BASIC, DIGEST, users)
type Auth struct {
	Basic       *Basic   `json:"basic,omitempty" export:"true"`
	Digest      *Digest  `json:"digest,omitempty" export:"true"`
	Forward     *Forward `json:"forward,omitempty" export:"true"`
	HeaderField string   `json:"headerField,omitempty" export:"true"`
}

// Users authentication users
type Users []string

// Basic HTTP basic authentication
type Basic struct {
	Users        `json:"users,omitempty" mapstructure:","`
	UsersFile    string `json:"usersFile,omitempty"`
	RemoveHeader bool   `json:"removeHeader,omitempty"`
}

// Digest HTTP authentication
type Digest struct {
	Users        `json:"users,omitempty" mapstructure:","`
	UsersFile    string `json:"usersFile,omitempty"`
	RemoveHeader bool   `json:"removeHeader,omitempty"`
}

// Forward authentication
type Forward struct {
	Address             string     `description:"Authentication server address" json:"address,omitempty"`
	TLS                 *ClientTLS `description:"Enable TLS support" json:"tls,omitempty" export:"true"`
	TrustForwardHeader  bool       `description:"Trust X-Forwarded-* headers" json:"trustForwardHeader,omitempty" export:"true"`
	AuthResponseHeaders []string   `description:"Headers to be forwarded from auth response" json:"authResponseHeaders,omitempty"`
}

// ClientTLS holds TLS specific configurations as client
// CA, Cert and Key can be either path or file contents
type ClientTLS struct {
	CA                 string `description:"TLS CA" json:"ca,omitempty"`
	CAOptional         bool   `description:"TLS CA.Optional" json:"caOptional,omitempty"`
	Cert               string `description:"TLS cert" json:"cert,omitempty"`
	Key                string `description:"TLS key" json:"key,omitempty"`
	InsecureSkipVerify bool   `description:"TLS insecure skip verify" json:"insecureSkipVerify,omitempty"`
}

// IPStrategy Configuration to choose the IP selection strategy.
type IPStrategy struct {
	Depth       int      `json:"depth,omitempty" export:"true"`
	ExcludedIPs []string `json:"excludedIPs,omitempty"`
}

// Get an IP selection strategy
// if nil return the RemoteAddr strategy
// else return a strategy base on the configuration using the X-Forwarded-For Header.
// Depth override the ExcludedIPs
func (s *IPStrategy) Get() (ip.Strategy, error) {
	if s == nil {
		return &ip.RemoteAddrStrategy{}, nil
	}

	if s.Depth > 0 {
		return &ip.DepthStrategy{
			Depth: s.Depth,
		}, nil
	}

	if len(s.ExcludedIPs) > 0 {
		checker, err := ip.NewChecker(s.ExcludedIPs)
		if err != nil {
			return nil, err
		}
		return &ip.CheckerStrategy{
			Checker: checker,
		}, nil
	}

	return &ip.RemoteAddrStrategy{}, nil
}
