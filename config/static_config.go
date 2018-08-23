package config

import (
	"github.com/containous/flaeg/parse"
	"github.com/containous/traefik/tls"
)

type StaticConfiguration struct {
	Global      *Global
	EntryPoints *EntryPoints

	// TODO
	//Tracing     *tracing.Tracing   `description:"OpenTracing configuration" export:"true"`
	//Constraints types.Constraints  `description:"Filter services by constraint, matching with service tags" export:"true"`
	//ACME        *acme.ACME         `description:"Enable ACME (Let's Encrypt): automatic SSL" export:"true"`
	//Retry       *Retry             `description:"Enable retry sending request if network error" export:"true"`
	//HealthCheck *HealthCheckConfig `description:"Health check parameters" export:"true"`
	//
	//API          *api.Handler        `description:"Enable api/dashboard" export:"true"`
	//Metrics      *types.Metrics      `description:"Enable a metrics exporter" export:"true"`
	//Ping         *ping.Handler       `description:"Enable ping" export:"true"`
	//HostResolver *HostResolverConfig `description:"Enable CNAME Flattening" export:"true"`
}

type Global struct {
	Debug              bool `short:"d" description:"Enable debug mode" export:"true"`
	CheckNewVersion    bool `description:"Periodically check if a new version has been released" export:"true"`
	SendAnonymousUsage bool `description:"send periodically anonymous usage statistics" export:"true"`
	// TODO (LogLevel)
	LogLevel                  string              `short:"l" description:"Log level" export:"true"`
	InsecureSkipVerify        bool                `description:"Disable SSL certificate verification" export:"true"`
	RootCAs                   tls.RootCAs         `description:"Add cert file for self-signed certificate"`
	ProvidersThrottleDuration parse.Duration      `description:"Backends throttle duration: minimum duration between 2 events from providers before applying a new configuration. It avoids unnecessary reloads if multiples events are sent in a short amount of time." export:"true"`
	LifeCycle                 *LifeCycle          `description:"Timeouts influencing the server life cycle" export:"true"`
	RespondingTimeouts        *RespondingTimeouts `description:"Timeouts for incoming requests to the Traefik instance" export:"true"`
	ForwardingTimeouts        *ForwardingTimeouts `description:"Timeouts for requests forwarded to the backend servers" export:"true"`
	MaxIdleConnsPerHost       int                 `description:"If non-zero, controls the maximum idle (keep-alive) to keep per-host.  If zero, DefaultMaxIdleConnsPerHost is used" export:"true"`
}

// RespondingTimeouts contains timeout configurations for incoming requests to the Traefik instance.
type RespondingTimeouts struct {
	ReadTimeout  parse.Duration `description:"ReadTimeout is the maximum duration for reading the entire request, including the body. If zero, no timeout is set" export:"true"`
	WriteTimeout parse.Duration `description:"WriteTimeout is the maximum duration before timing out writes of the response. If zero, no timeout is set" export:"true"`
	IdleTimeout  parse.Duration `description:"IdleTimeout is the maximum amount duration an idle (keep-alive) connection will remain idle before closing itself. Defaults to 180 seconds. If zero, no timeout is set" export:"true"`
}

// ForwardingTimeouts contains timeout configurations for forwarding requests to the backend servers.
type ForwardingTimeouts struct {
	DialTimeout           parse.Duration `description:"The amount of time to wait until a connection to a backend server can be established. Defaults to 30 seconds. If zero, no timeout exists" export:"true"`
	ResponseHeaderTimeout parse.Duration `description:"The amount of time to wait for a server's response headers after fully writing the request (including its body, if any). If zero, no timeout exists" export:"true"`
}

// LifeCycle contains configurations relevant to the lifecycle (such as the
// shutdown phase) of Traefik.
type LifeCycle struct {
	RequestAcceptGraceTimeout parse.Duration `description:"Duration to keep accepting requests before Traefik initiates the graceful shutdown procedure"`
	GraceTimeOut              parse.Duration `description:"Duration to give active requests a chance to finish before Traefik stops"`
}

type EntryPoint struct {
	Address string
	HTTP    *EntryPointHTTP
	TCP     *EntryPointTCP
	UDP     *EntryPointUDP
}

type EntryPointHTTP struct {
}

type EntryPointTCP struct {
}

type EntryPointUDP struct {
}

type EntryPointList map[string]EntryPoint
type EntryPoints struct {
	EntryPointList
	Default []string
}
