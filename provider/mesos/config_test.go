package mesos

import (
	"testing"
	"time"

	"github.com/containous/flaeg/parse"
	"github.com/containous/traefik/provider/label"
	"github.com/containous/traefik/types"
	"github.com/mesosphere/mesos-dns/records/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildConfiguration(t *testing.T) {
	p := &Provider{
		Domain:           "mesos.localhost",
		ExposedByDefault: true,
		IPSources:        "host",
	}

	testCases := []struct {
		desc              string
		tasks             []state.Task
		expectedFrontends map[string]*types.Frontend
		expectedBackends  map[string]*types.Backend
	}{
		{
			desc:              "when no tasks",
			tasks:             []state.Task{},
			expectedFrontends: map[string]*types.Frontend{},
			expectedBackends:  map[string]*types.Backend{},
		},
		{
			desc: "2 applications with 2 tasks",
			tasks: []state.Task{
				// App 1
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				aTask("ID2",
					withIP("10.10.10.11"),
					withInfo("name1",
						withPorts(withPort("TCP", 81, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				// App 2
				aTask("ID3",
					withIP("20.10.10.10"),
					withInfo("name2",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				aTask("ID4",
					withIP("20.10.10.11"),
					withInfo("name2",
						withPorts(withPort("TCP", 81, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					Backend:        "backend-name1",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:name1.mesos.localhost",
						},
					},
				},
				"frontend-ID3": {
					Backend:        "backend-name2",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID3": {
							Rule: "Host:name2.mesos.localhost",
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-name1": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "http://10.10.10.10:80",
							Weight: label.DefaultWeight,
						},
						"server-ID2": {
							URL:    "http://10.10.10.11:81",
							Weight: label.DefaultWeight,
						},
					},
				},
				"backend-name2": {
					Servers: map[string]types.Server{
						"server-ID3": {
							URL:    "http://20.10.10.10:80",
							Weight: label.DefaultWeight,
						},
						"server-ID4": {
							URL:    "http://20.10.10.11:81",
							Weight: label.DefaultWeight,
						},
					},
				},
			},
		},
		{
			desc: "With basic auth",
			tasks: []state.Task{
				// App 1
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
					withLabel(label.TraefikFrontendAuthBasicUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
					withLabel(label.TraefikFrontendAuthBasicUsersFile, ".htpasswd"),
					withLabel(label.TraefikFrontendAuthBasicRemoveHeader, "true"),
					withLabel(label.TraefikFrontendAuthHeaderField, "X-WebAuth-User"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					Backend:        "backend-name1",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:name1.mesos.localhost",
						},
					},
					Auth: &types.Auth{
						HeaderField: "X-WebAuth-User",
						Basic: &types.Basic{
							RemoveHeader: true,
							Users: []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
								"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"},
							UsersFile: ".htpasswd",
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-name1": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "http://10.10.10.10:80",
							Weight: label.DefaultWeight,
						},
					},
				},
			},
		},
		{
			desc: "With basic auth (backward compatibility)",
			tasks: []state.Task{
				// App 1
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
					withLabel(label.TraefikFrontendAuthBasic, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					Backend:        "backend-name1",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:name1.mesos.localhost",
						},
					},
					Auth: &types.Auth{
						Basic: &types.Basic{
							Users: []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
								"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"},
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-name1": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "http://10.10.10.10:80",
							Weight: label.DefaultWeight,
						},
					},
				},
			},
		},
		{
			desc: "With digest auth",
			tasks: []state.Task{
				// App 1
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
					withLabel(label.TraefikFrontendAuthDigestRemoveHeader, "true"),
					withLabel(label.TraefikFrontendAuthDigestUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
					withLabel(label.TraefikFrontendAuthDigestUsersFile, ".htpasswd"),
					withLabel(label.TraefikFrontendAuthHeaderField, "X-WebAuth-User"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					Backend:        "backend-name1",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:name1.mesos.localhost",
						},
					},
					Auth: &types.Auth{
						HeaderField: "X-WebAuth-User",
						Digest: &types.Digest{
							RemoveHeader: true,
							Users: []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
								"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"},
							UsersFile: ".htpasswd",
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-name1": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "http://10.10.10.10:80",
							Weight: label.DefaultWeight,
						},
					},
				},
			},
		},
		{
			desc: "With Forward auth",
			tasks: []state.Task{
				// App 1
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
					withLabel(label.TraefikFrontendAuthForwardAddress, "auth.server"),
					withLabel(label.TraefikFrontendAuthForwardTrustForwardHeader, "true"),
					withLabel(label.TraefikFrontendAuthForwardTLSCa, "ca.crt"),
					withLabel(label.TraefikFrontendAuthForwardTLSCaOptional, "true"),
					withLabel(label.TraefikFrontendAuthForwardTLSCert, "server.crt"),
					withLabel(label.TraefikFrontendAuthForwardTLSKey, "server.key"),
					withLabel(label.TraefikFrontendAuthForwardTLSInsecureSkipVerify, "true"),
					withLabel(label.TraefikFrontendAuthHeaderField, "X-WebAuth-User"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					Backend:        "backend-name1",
					EntryPoints:    []string{},
					PassHostHeader: true,
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:name1.mesos.localhost",
						},
					},
					Auth: &types.Auth{
						HeaderField: "X-WebAuth-User",
						Forward: &types.Forward{
							Address:            "auth.server",
							TrustForwardHeader: true,
							TLS: &types.ClientTLS{
								CA:                 "ca.crt",
								CAOptional:         true,
								InsecureSkipVerify: true,
								Cert:               "server.crt",
								Key:                "server.key",
							},
						},
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-name1": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "http://10.10.10.10:80",
							Weight: label.DefaultWeight,
						},
					},
				},
			},
		},
		{
			desc: "with all labels",
			tasks: []state.Task{
				aTask("ID1",
					withLabel(label.TraefikPort, "666"),
					withLabel(label.TraefikProtocol, "https"),
					withLabel(label.TraefikWeight, "12"),

					withLabel(label.TraefikBackend, "foobar"),

					withLabel(label.TraefikBackendCircuitBreakerExpression, "NetworkErrorRatio() > 0.5"),
					withLabel(label.TraefikBackendHealthCheckScheme, "http"),
					withLabel(label.TraefikBackendHealthCheckPath, "/health"),
					withLabel(label.TraefikBackendHealthCheckPort, "880"),
					withLabel(label.TraefikBackendHealthCheckInterval, "6"),
					withLabel(label.TraefikBackendHealthCheckHostname, "foo.com"),
					withLabel(label.TraefikBackendHealthCheckHeaders, "Foo:bar || Bar:foo"),

					withLabel(label.TraefikBackendLoadBalancerMethod, "drr"),
					withLabel(label.TraefikBackendLoadBalancerStickiness, "true"),
					withLabel(label.TraefikBackendLoadBalancerStickinessCookieName, "chocolate"),
					withLabel(label.TraefikBackendMaxConnAmount, "666"),
					withLabel(label.TraefikBackendMaxConnExtractorFunc, "client.ip"),
					withLabel(label.TraefikBackendBufferingMaxResponseBodyBytes, "10485760"),
					withLabel(label.TraefikBackendBufferingMemResponseBodyBytes, "2097152"),
					withLabel(label.TraefikBackendBufferingMaxRequestBodyBytes, "10485760"),
					withLabel(label.TraefikBackendBufferingMemRequestBodyBytes, "2097152"),
					withLabel(label.TraefikBackendBufferingRetryExpression, "IsNetworkError() && Attempts() <= 2"),

					withLabel(label.TraefikFrontendAuthBasic, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
					withLabel(label.TraefikFrontendAuthBasicRemoveHeader, "true"),
					withLabel(label.TraefikFrontendAuthBasicUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
					withLabel(label.TraefikFrontendAuthBasicUsersFile, ".htpasswd"),
					withLabel(label.TraefikFrontendAuthDigestRemoveHeader, "true"),
					withLabel(label.TraefikFrontendAuthDigestUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"),
					withLabel(label.TraefikFrontendAuthDigestUsersFile, ".htpasswd"),
					withLabel(label.TraefikFrontendAuthForwardAddress, "auth.server"),
					withLabel(label.TraefikFrontendAuthForwardTrustForwardHeader, "true"),
					withLabel(label.TraefikFrontendAuthForwardTLSCa, "ca.crt"),
					withLabel(label.TraefikFrontendAuthForwardTLSCaOptional, "true"),
					withLabel(label.TraefikFrontendAuthForwardTLSCert, "server.crt"),
					withLabel(label.TraefikFrontendAuthForwardTLSKey, "server.key"),
					withLabel(label.TraefikFrontendAuthForwardTLSInsecureSkipVerify, "true"),
					withLabel(label.TraefikFrontendAuthHeaderField, "X-WebAuth-User"),

					withLabel(label.TraefikFrontendEntryPoints, "http,https"),
					withLabel(label.TraefikFrontendPassHostHeader, "true"),
					withLabel(label.TraefikFrontendPassTLSCert, "true"),
					withLabel(label.TraefikFrontendPriority, "666"),
					withLabel(label.TraefikFrontendRedirectEntryPoint, "https"),
					withLabel(label.TraefikFrontendRedirectRegex, "nope"),
					withLabel(label.TraefikFrontendRedirectReplacement, "nope"),
					withLabel(label.TraefikFrontendRedirectPermanent, "true"),
					withLabel(label.TraefikFrontendRule, "Host:traefik.io"),
					withLabel(label.TraefikFrontendWhiteListSourceRange, "10.10.10.10"),
					withLabel(label.TraefikFrontendWhiteListUseXForwardedFor, "true"),

					withLabel(label.TraefikFrontendRequestHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type:application/json; charset=utf-8"),
					withLabel(label.TraefikFrontendResponseHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type:application/json; charset=utf-8"),
					withLabel(label.TraefikFrontendSSLProxyHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type:application/json; charset=utf-8"),
					withLabel(label.TraefikFrontendAllowedHosts, "foo,bar,bor"),
					withLabel(label.TraefikFrontendHostsProxyHeaders, "foo,bar,bor"),
					withLabel(label.TraefikFrontendSSLForceHost, "true"),
					withLabel(label.TraefikFrontendSSLHost, "foo"),
					withLabel(label.TraefikFrontendCustomFrameOptionsValue, "foo"),
					withLabel(label.TraefikFrontendContentSecurityPolicy, "foo"),
					withLabel(label.TraefikFrontendPublicKey, "foo"),
					withLabel(label.TraefikFrontendReferrerPolicy, "foo"),
					withLabel(label.TraefikFrontendCustomBrowserXSSValue, "foo"),
					withLabel(label.TraefikFrontendSTSSeconds, "666"),
					withLabel(label.TraefikFrontendSSLRedirect, "true"),
					withLabel(label.TraefikFrontendSSLTemporaryRedirect, "true"),
					withLabel(label.TraefikFrontendSTSIncludeSubdomains, "true"),
					withLabel(label.TraefikFrontendSTSPreload, "true"),
					withLabel(label.TraefikFrontendForceSTSHeader, "true"),
					withLabel(label.TraefikFrontendFrameDeny, "true"),
					withLabel(label.TraefikFrontendContentTypeNosniff, "true"),
					withLabel(label.TraefikFrontendBrowserXSSFilter, "true"),
					withLabel(label.TraefikFrontendIsDevelopment, "true"),

					withLabel(label.Prefix+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageStatus, "404"),
					withLabel(label.Prefix+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageBackend, "foobar"),
					withLabel(label.Prefix+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageQuery, "foo_query"),
					withLabel(label.Prefix+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageStatus, "500,600"),
					withLabel(label.Prefix+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageBackend, "foobar"),
					withLabel(label.Prefix+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageQuery, "bar_query"),

					withLabel(label.TraefikFrontendRateLimitExtractorFunc, "client.ip"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitPeriod, "6"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitAverage, "12"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitBurst, "18"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitPeriod, "3"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitAverage, "6"),
					withLabel(label.Prefix+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitBurst, "9"),
					withIP("10.10.10.10"),
					withInfo("name1", withPorts(
						withPortTCP(80, "n"),
						withPortTCP(666, "n"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-ID1": {
					EntryPoints: []string{
						"http",
						"https",
					},
					Backend: "backend-foobar",
					Routes: map[string]types.Route{
						"route-host-ID1": {
							Rule: "Host:traefik.io",
						},
					},
					PassHostHeader: true,
					PassTLSCert:    true,
					Priority:       666,
					Auth: &types.Auth{
						HeaderField: "X-WebAuth-User",
						Basic: &types.Basic{
							RemoveHeader: true,
							Users: []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
								"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"},
							UsersFile: ".htpasswd",
						},
					},
					WhiteList: &types.WhiteList{
						SourceRange:      []string{"10.10.10.10"},
						UseXForwardedFor: true,
					},
					Headers: &types.Headers{
						CustomRequestHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						CustomResponseHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						AllowedHosts: []string{
							"foo",
							"bar",
							"bor",
						},
						HostsProxyHeaders: []string{
							"foo",
							"bar",
							"bor",
						},
						SSLRedirect:          true,
						SSLTemporaryRedirect: true,
						SSLForceHost:         true,
						SSLHost:              "foo",
						SSLProxyHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						STSSeconds:              666,
						STSIncludeSubdomains:    true,
						STSPreload:              true,
						ForceSTSHeader:          true,
						FrameDeny:               true,
						CustomFrameOptionsValue: "foo",
						ContentTypeNosniff:      true,
						BrowserXSSFilter:        true,
						CustomBrowserXSSValue:   "foo",
						ContentSecurityPolicy:   "foo",
						PublicKey:               "foo",
						ReferrerPolicy:          "foo",
						IsDevelopment:           true,
					},
					Errors: map[string]*types.ErrorPage{
						"foo": {
							Status:  []string{"404"},
							Query:   "foo_query",
							Backend: "backend-foobar",
						},
						"bar": {
							Status:  []string{"500", "600"},
							Query:   "bar_query",
							Backend: "backend-foobar",
						},
					},
					RateLimit: &types.RateLimit{
						ExtractorFunc: "client.ip",
						RateSet: map[string]*types.Rate{
							"foo": {
								Period:  parse.Duration(6 * time.Second),
								Average: 12,
								Burst:   18,
							},
							"bar": {
								Period:  parse.Duration(3 * time.Second),
								Average: 6,
								Burst:   9,
							},
						},
					},
					Redirect: &types.Redirect{
						EntryPoint:  "https",
						Regex:       "",
						Replacement: "",
						Permanent:   true,
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-foobar": {
					Servers: map[string]types.Server{
						"server-ID1": {
							URL:    "https://10.10.10.10:666",
							Weight: 12,
						},
					},
					CircuitBreaker: &types.CircuitBreaker{
						Expression: "NetworkErrorRatio() > 0.5",
					},
					LoadBalancer: &types.LoadBalancer{
						Method: "drr",
						Stickiness: &types.Stickiness{
							CookieName: "chocolate",
						},
					},
					MaxConn: &types.MaxConn{
						Amount:        666,
						ExtractorFunc: "client.ip",
					},
					HealthCheck: &types.HealthCheck{
						Scheme:   "http",
						Path:     "/health",
						Port:     880,
						Interval: "6",
						Hostname: "foo.com",
						Headers: map[string]string{
							"Foo": "bar",
							"Bar": "foo",
						},
					},
					Buffering: &types.Buffering{
						MaxResponseBodyBytes: 10485760,
						MemResponseBodyBytes: 2097152,
						MaxRequestBodyBytes:  10485760,
						MemRequestBodyBytes:  2097152,
						RetryExpression:      "IsNetworkError() && Attempts() <= 2",
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actualConfig := p.buildConfiguration(test.tasks)

			require.NotNil(t, actualConfig)
			assert.Equal(t, test.expectedBackends, actualConfig.Backends)
			assert.Equal(t, test.expectedFrontends, actualConfig.Frontends)
		})
	}
}

func TestBuildConfigurationSegments(t *testing.T) {
	p := &Provider{
		Domain:           "mesos.localhost",
		ExposedByDefault: true,
		IPSources:        "host",
	}

	testCases := []struct {
		desc              string
		tasks             []state.Task
		expectedFrontends map[string]*types.Frontend
		expectedBackends  map[string]*types.Backend
	}{
		{
			desc: "multiple ports with segments",
			tasks: []state.Task{
				aTask("app-taskID",
					withIP("127.0.0.1"),
					withInfo("/app",
						withPorts(
							withPort("TCP", 80, "web"),
							withPort("TCP", 81, "admin"),
						),
					),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
					withLabel(label.TraefikBackendMaxConnAmount, "1000"),
					withLabel(label.TraefikBackendMaxConnExtractorFunc, "client.ip"),
					withSegmentLabel(label.TraefikPort, "80", "web"),
					withSegmentLabel(label.TraefikPort, "81", "admin"),
					withLabel("traefik..port", "82"), // This should be ignored, as it fails to match the segmentPropertiesRegexp regex.
					withSegmentLabel(label.TraefikFrontendRule, "Host:web.app.mesos.localhost", "web"),
					withSegmentLabel(label.TraefikFrontendRule, "Host:admin.app.mesos.localhost", "admin"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-app-taskID-service-web": {
					Backend: "backend-app-service-web",
					Routes: map[string]types.Route{
						`route-host-app-taskID-service-web`: {
							Rule: "Host:web.app.mesos.localhost",
						},
					},
					PassHostHeader: true,
					EntryPoints:    []string{},
				},
				"frontend-app-taskID-service-admin": {
					Backend: "backend-app-service-admin",
					Routes: map[string]types.Route{
						`route-host-app-taskID-service-admin`: {
							Rule: "Host:admin.app.mesos.localhost",
						},
					},
					PassHostHeader: true,
					EntryPoints:    []string{},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-app-service-web": {
					Servers: map[string]types.Server{
						"server-app-taskID-service-web": {
							URL:    "http://127.0.0.1:80",
							Weight: label.DefaultWeight,
						},
					},
					MaxConn: &types.MaxConn{
						Amount:        1000,
						ExtractorFunc: "client.ip",
					},
				},
				"backend-app-service-admin": {
					Servers: map[string]types.Server{
						"server-app-taskID-service-admin": {
							URL:    "http://127.0.0.1:81",
							Weight: label.DefaultWeight,
						},
					},
					MaxConn: &types.MaxConn{
						Amount:        1000,
						ExtractorFunc: "client.ip",
					},
				},
			},
		},
		{
			desc: "when all labels are set",
			tasks: []state.Task{
				aTask("app-taskID",
					withIP("127.0.0.1"),
					withInfo("/app",
						withPorts(
							withPort("TCP", 80, "web"),
							withPort("TCP", 81, "admin"),
						),
					),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),

					withLabel(label.TraefikBackendCircuitBreakerExpression, "NetworkErrorRatio() > 0.5"),
					withLabel(label.TraefikBackendHealthCheckScheme, "http"),
					withLabel(label.TraefikBackendHealthCheckPath, "/health"),
					withLabel(label.TraefikBackendHealthCheckPort, "880"),
					withLabel(label.TraefikBackendHealthCheckInterval, "6"),
					withLabel(label.TraefikBackendHealthCheckHostname, "foo.com"),
					withLabel(label.TraefikBackendHealthCheckHeaders, "Foo:bar || Bar:foo"),
					withLabel(label.TraefikBackendLoadBalancerMethod, "drr"),
					withLabel(label.TraefikBackendLoadBalancerStickiness, "true"),
					withLabel(label.TraefikBackendLoadBalancerStickinessCookieName, "chocolate"),
					withLabel(label.TraefikBackendMaxConnAmount, "666"),
					withLabel(label.TraefikBackendMaxConnExtractorFunc, "client.ip"),
					withLabel(label.TraefikBackendBufferingMaxResponseBodyBytes, "10485760"),
					withLabel(label.TraefikBackendBufferingMemResponseBodyBytes, "2097152"),
					withLabel(label.TraefikBackendBufferingMaxRequestBodyBytes, "10485760"),
					withLabel(label.TraefikBackendBufferingMemRequestBodyBytes, "2097152"),
					withLabel(label.TraefikBackendBufferingRetryExpression, "IsNetworkError() && Attempts() <= 2"),

					withSegmentLabel(label.TraefikPort, "80", "containous"),
					withSegmentLabel(label.TraefikPortName, "web", "containous"),
					withSegmentLabel(label.TraefikProtocol, "https", "containous"),
					withSegmentLabel(label.TraefikWeight, "12", "containous"),

					withSegmentLabel(label.TraefikFrontendAuthBasic, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthBasicRemoveHeader, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthBasicUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthBasicUsersFile, ".htpasswd", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthDigestRemoveHeader, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthDigestUsers, "test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/,test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthDigestUsersFile, ".htpasswd", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardAddress, "auth.server", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTrustForwardHeader, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTLSCa, "ca.crt", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTLSCaOptional, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTLSCert, "server.crt", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTLSKey, "server.key", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthForwardTLSInsecureSkipVerify, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendAuthHeaderField, "X-WebAuth-User", "containous"),

					withSegmentLabel(label.TraefikFrontendEntryPoints, "http,https", "containous"),
					withSegmentLabel(label.TraefikFrontendPassHostHeader, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendPassTLSCert, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendPriority, "666", "containous"),
					withSegmentLabel(label.TraefikFrontendRedirectEntryPoint, "https", "containous"),
					withSegmentLabel(label.TraefikFrontendRedirectRegex, "nope", "containous"),
					withSegmentLabel(label.TraefikFrontendRedirectReplacement, "nope", "containous"),
					withSegmentLabel(label.TraefikFrontendRedirectPermanent, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendRule, "Host:traefik.io", "containous"),
					withSegmentLabel(label.TraefikFrontendWhiteListSourceRange, "10.10.10.10", "containous"),
					withSegmentLabel(label.TraefikFrontendWhiteListUseXForwardedFor, "true", "containous"),

					withSegmentLabel(label.TraefikFrontendRequestHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8", "containous"),
					withSegmentLabel(label.TraefikFrontendResponseHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8", "containous"),
					withSegmentLabel(label.TraefikFrontendSSLProxyHeaders, "Access-Control-Allow-Methods:POST,GET,OPTIONS || Content-type: application/json; charset=utf-8", "containous"),
					withSegmentLabel(label.TraefikFrontendAllowedHosts, "foo,bar,bor", "containous"),
					withSegmentLabel(label.TraefikFrontendHostsProxyHeaders, "foo,bar,bor", "containous"),
					withSegmentLabel(label.TraefikFrontendSSLForceHost, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendSSLHost, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendCustomFrameOptionsValue, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendContentSecurityPolicy, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendPublicKey, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendReferrerPolicy, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendCustomBrowserXSSValue, "foo", "containous"),
					withSegmentLabel(label.TraefikFrontendSTSSeconds, "666", "containous"),
					withSegmentLabel(label.TraefikFrontendSSLRedirect, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendSSLTemporaryRedirect, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendSTSIncludeSubdomains, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendSTSPreload, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendForceSTSHeader, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendFrameDeny, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendContentTypeNosniff, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendBrowserXSSFilter, "true", "containous"),
					withSegmentLabel(label.TraefikFrontendIsDevelopment, "true", "containous"),

					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageStatus, "404"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageBackend, "foobar"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"foo."+label.SuffixErrorPageQuery, "foo_query"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageStatus, "500,600"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageBackend, "foobar"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendErrorPage+"bar."+label.SuffixErrorPageQuery, "bar_query"),

					withSegmentLabel(label.TraefikFrontendRateLimitExtractorFunc, "client.ip", "containous"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitPeriod, "6"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitAverage, "12"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"foo."+label.SuffixRateLimitBurst, "18"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitPeriod, "3"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitAverage, "6"),
					withLabel(label.Prefix+"containous."+label.BaseFrontendRateLimit+"bar."+label.SuffixRateLimitBurst, "9"),
				),
			},
			expectedFrontends: map[string]*types.Frontend{
				"frontend-app-taskID-service-containous": {
					EntryPoints: []string{
						"http",
						"https",
					},
					Backend: "backend-app-service-containous",
					Routes: map[string]types.Route{
						"route-host-app-taskID-service-containous": {
							Rule: "Host:traefik.io",
						},
					},
					PassHostHeader: true,
					PassTLSCert:    true,
					Priority:       666,
					Auth: &types.Auth{
						HeaderField: "X-WebAuth-User",
						Basic: &types.Basic{
							RemoveHeader: true,
							Users: []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/",
								"test2:$apr1$d9hr9HBB$4HxwgUir3HP4EsggP/QNo0"},
							UsersFile: ".htpasswd",
						},
					},

					WhiteList: &types.WhiteList{
						SourceRange:      []string{"10.10.10.10"},
						UseXForwardedFor: true,
					},
					Headers: &types.Headers{
						CustomRequestHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						CustomResponseHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						AllowedHosts: []string{
							"foo",
							"bar",
							"bor",
						},
						HostsProxyHeaders: []string{
							"foo",
							"bar",
							"bor",
						},
						SSLRedirect:          true,
						SSLTemporaryRedirect: true,
						SSLForceHost:         true,
						SSLHost:              "foo",
						SSLProxyHeaders: map[string]string{
							"Access-Control-Allow-Methods": "POST,GET,OPTIONS",
							"Content-Type":                 "application/json; charset=utf-8",
						},
						STSSeconds:              666,
						STSIncludeSubdomains:    true,
						STSPreload:              true,
						ForceSTSHeader:          true,
						FrameDeny:               true,
						CustomFrameOptionsValue: "foo",
						ContentTypeNosniff:      true,
						BrowserXSSFilter:        true,
						CustomBrowserXSSValue:   "foo",
						ContentSecurityPolicy:   "foo",
						PublicKey:               "foo",
						ReferrerPolicy:          "foo",
						IsDevelopment:           true,
					},
					Errors: map[string]*types.ErrorPage{
						"bar": {
							Status: []string{
								"500",
								"600",
							},
							Backend: "backend-foobar",
							Query:   "bar_query",
						},
						"foo": {
							Status: []string{
								"404",
							},
							Backend: "backend-foobar",
							Query:   "foo_query",
						},
					},
					RateLimit: &types.RateLimit{
						RateSet: map[string]*types.Rate{
							"bar": {
								Period:  parse.Duration(3 * time.Second),
								Average: 6,
								Burst:   9,
							},
							"foo": {
								Period:  parse.Duration(6 * time.Second),
								Average: 12,
								Burst:   18,
							},
						},
						ExtractorFunc: "client.ip",
					},
					Redirect: &types.Redirect{
						EntryPoint: "https",
						Permanent:  true,
					},
				},
			},
			expectedBackends: map[string]*types.Backend{
				"backend-app-service-containous": {
					Servers: map[string]types.Server{
						"server-app-taskID-service-containous": {
							URL:    "https://127.0.0.1:80",
							Weight: 12,
						},
					},
					CircuitBreaker: &types.CircuitBreaker{
						Expression: "NetworkErrorRatio() > 0.5",
					},
					LoadBalancer: &types.LoadBalancer{
						Method: "drr",
						Stickiness: &types.Stickiness{
							CookieName: "chocolate",
						},
					},
					MaxConn: &types.MaxConn{
						Amount:        666,
						ExtractorFunc: "client.ip",
					},
					HealthCheck: &types.HealthCheck{
						Scheme:   "http",
						Path:     "/health",
						Port:     880,
						Interval: "6",
						Hostname: "foo.com",
						Headers: map[string]string{
							"Bar": "foo",
							"Foo": "bar",
						},
					},
					Buffering: &types.Buffering{
						MaxResponseBodyBytes: 10485760,
						MemResponseBodyBytes: 2097152,
						MaxRequestBodyBytes:  10485760,
						MemRequestBodyBytes:  2097152,
						RetryExpression:      "IsNetworkError() && Attempts() <= 2",
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actualConfig := p.buildConfiguration(test.tasks)

			require.NotNil(t, actualConfig)
			assert.Equal(t, test.expectedBackends, actualConfig.Backends)
			assert.Equal(t, test.expectedFrontends, actualConfig.Frontends)
		})
	}
}

func TestTaskFilter(t *testing.T) {
	testCases := []struct {
		desc             string
		mesosTask        taskData
		exposedByDefault bool
		expected         bool
	}{
		{
			desc:             "no task",
			mesosTask:        taskData{},
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc:             "task not healthy",
			mesosTask:        aTaskData("test", "", withStatus(withState("TASK_RUNNING"))),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "exposedByDefault false and traefik.enable false",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "false"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: false,
			expected:         false,
		},
		{
			desc: "traefik.enable = true",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: false,
			expected:         true,
		},
		{
			desc: "exposedByDefault true and traefik.enable true",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "exposedByDefault true and traefik.enable false",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "false"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "traefik.portIndex and traefik.port both set",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortIndex, "1"),
				withLabel(label.TraefikPort, "80"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "valid traefik.portIndex",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortIndex, "1"),
				withInfo("test", withPorts(
					withPortTCP(80, "WEB"),
					withPortTCP(443, "WEB HTTPS"),
				)),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "valid traefik.portName",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortName, "https"),
				withInfo("test", withPorts(
					withPortTCP(80, "http"),
					withPortTCP(443, "https"),
				)),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "missing traefik.portName",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortName, "foo"),
				withInfo("test", withPorts(
					withPortTCP(80, "http"),
					withPortTCP(443, "https"),
				)),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "default to first port index",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withInfo("test", withPorts(
					withPortTCP(80, "WEB"),
					withPortTCP(443, "WEB HTTPS"),
				)),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "traefik.portIndex and discoveryPorts don't correspond",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortIndex, "1"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "traefik.portIndex and discoveryPorts correspond",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPortIndex, "0"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "traefik.port is not an integer",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPort, "TRAEFIK"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "traefik.port is not the same as discovery.port",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPort, "443"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
		{
			desc: "traefik.port is the same as discovery.port",
			mesosTask: aTaskData("test", "",
				withDefaultStatus(),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPort, "80"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "healthy nil",
			mesosTask: aTaskData("test", "",
				withStatus(
					withState("TASK_RUNNING"),
				),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPort, "80"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         true,
		},
		{
			desc: "healthy false",
			mesosTask: aTaskData("test", "",
				withStatus(
					withState("TASK_RUNNING"),
					withHealthy(false),
				),
				withLabel(label.TraefikEnable, "true"),
				withLabel(label.TraefikPort, "80"),
				withInfo("test", withPorts(withPortTCP(80, "WEB"))),
			),
			exposedByDefault: true,
			expected:         false,
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual := taskFilter(test.mesosTask, test.exposedByDefault)
			ok := assert.Equal(t, test.expected, actual)
			if !ok {
				t.Logf("Statuses : %v", test.mesosTask.Statuses)
				t.Logf("Label : %v", test.mesosTask.Labels)
				t.Logf("DiscoveryInfo : %v", test.mesosTask.DiscoveryInfo)
				t.Fatalf("Expected %v, got %v", test.expected, actual)
			}
		})
	}
}

func TestGetServerPort(t *testing.T) {
	testCases := []struct {
		desc     string
		task     taskData
		expected string
	}{
		{
			desc:     "port missing",
			task:     aTaskData("", ""),
			expected: "",
		},
		{
			desc:     "numeric port",
			task:     aTaskData("", "", withLabel(label.TraefikPort, "80")),
			expected: "80",
		},
		{
			desc: "string port",
			task: aTaskData("", "",
				withLabel(label.TraefikPort, "foobar"),
				withInfo("", withPorts(withPort("TCP", 80, ""))),
			),
			expected: "",
		},
		{
			desc: "negative port",
			task: aTaskData("", "",
				withLabel(label.TraefikPort, "-1"),
				withInfo("", withPorts(withPort("TCP", 80, ""))),
			),
			expected: "",
		},
		{
			desc: "task port available",
			task: aTaskData("", "",
				withInfo("", withPorts(withPort("TCP", 80, ""))),
			),
			expected: "80",
		},
		{
			desc: "multiple task ports available",
			task: aTaskData("", "",
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "80",
		},
		{
			desc: "numeric port index specified",
			task: aTaskData("", "",
				withLabel(label.TraefikPortIndex, "1"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "443",
		},
		{
			desc: "string port name specified",
			task: aTaskData("", "",
				withLabel(label.TraefikPortName, "https"),
				withInfo("", withPorts(
					withPort("TCP", 80, "http"),
					withPort("TCP", 443, "https"),
				)),
			),
			expected: "443",
		},
		{
			desc: "string port index specified",
			task: aTaskData("", "",
				withLabel(label.TraefikPortIndex, "foobar"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
				)),
			),
			expected: "80",
		},
		{
			desc: "port and port index specified",
			task: aTaskData("", "",
				withLabel(label.TraefikPort, "80"),
				withLabel(label.TraefikPortIndex, "1"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "80",
		},
		{
			desc: "multiple task ports with service index available",
			task: aTaskData("", "http",
				withSegmentLabel(label.TraefikPortIndex, "0", "http"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "80",
		},
		{
			desc: "multiple task ports with service port available",
			task: aTaskData("", "https",
				withSegmentLabel(label.TraefikPort, "443", "https"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "443",
		},
		{
			desc: "multiple task ports with service port name available",
			task: aTaskData("", "https",
				withSegmentLabel(label.TraefikPortName, "b", "https"),
				withInfo("", withPorts(
					withPort("TCP", 80, "a"),
					withPort("TCP", 443, "b"),
				)),
			),
			expected: "443",
		},
		{
			desc: "multiple task ports with segment matching port name",
			task: aTaskData("", "b",
				withInfo("", withPorts(
					withPort("TCP", 80, "a"),
					withPort("TCP", 443, "b"),
				)),
			),
			expected: "443",
		},
		{
			desc: "multiple task ports with services but default port available",
			task: aTaskData("", "http",
				withSegmentLabel(label.TraefikWeight, "100", "http"),
				withInfo("", withPorts(
					withPort("TCP", 80, ""),
					withPort("TCP", 443, ""),
				)),
			),
			expected: "80",
		},
	}

	p := &Provider{
		ExposedByDefault: true,
		IPSources:        "host",
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual := p.getServerPort(test.task)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetSubDomain(t *testing.T) {
	providerGroups := &Provider{GroupsAsSubDomains: true}
	providerNoGroups := &Provider{GroupsAsSubDomains: false}

	testCases := []struct {
		path     string
		expected string
		provider *Provider
	}{
		{"/test", "test", providerNoGroups},
		{"/test", "test", providerGroups},
		{"/a/b/c/d", "d.c.b.a", providerGroups},
		{"/b/a/d/c", "c.d.a.b", providerGroups},
		{"/d/c/b/a", "a.b.c.d", providerGroups},
		{"/c/d/a/b", "b.a.d.c", providerGroups},
		{"/a/b/c/d", "a-b-c-d", providerNoGroups},
		{"/b/a/d/c", "b-a-d-c", providerNoGroups},
		{"/d/c/b/a", "d-c-b-a", providerNoGroups},
		{"/c/d/a/b", "c-d-a-b", providerNoGroups},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.path, func(t *testing.T) {
			t.Parallel()

			actual := test.provider.getSubDomain(test.path)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetServers(t *testing.T) {
	testCases := []struct {
		desc     string
		tasks    []taskData
		expected map[string]types.Server
	}{
		{
			desc: "",
			tasks: []taskData{
				// App 1
				aTaskData("ID1", "",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				aTaskData("ID2", "",
					withIP("10.10.10.11"),
					withLabel(label.TraefikWeight, "18"),
					withInfo("name1",
						withPorts(withPort("TCP", 81, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				// App 2
				aTaskData("ID3", "",
					withLabel(label.TraefikWeight, "12"),
					withIP("20.10.10.10"),
					withInfo("name2",
						withPorts(withPort("TCP", 80, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
				aTaskData("ID4", "",
					withLabel(label.TraefikWeight, "6"),
					withIP("20.10.10.11"),
					withInfo("name2",
						withPorts(withPort("TCP", 81, "WEB"))),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
			},
			expected: map[string]types.Server{
				"server-ID1": {
					URL:    "http://10.10.10.10:80",
					Weight: label.DefaultWeight,
				},
				"server-ID2": {
					URL:    "http://10.10.10.11:81",
					Weight: 18,
				},
				"server-ID3": {
					URL:    "http://20.10.10.10:80",
					Weight: 12,
				},
				"server-ID4": {
					URL:    "http://20.10.10.11:81",
					Weight: 6,
				},
			},
		},
		{
			desc: "with segments matching port names",
			tasks: segmentedTaskData([]string{"WEB1", "WEB2", "WEB3"},
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(
							withPort("TCP", 81, "WEB1"),
							withPort("TCP", 82, "WEB2"),
							withPort("TCP", 83, "WEB3"),
						)),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
			),
			expected: map[string]types.Server{
				"server-ID1-service-WEB1": {
					URL:    "http://10.10.10.10:81",
					Weight: label.DefaultWeight,
				},
				"server-ID1-service-WEB2": {
					URL:    "http://10.10.10.10:82",
					Weight: label.DefaultWeight,
				},
				"server-ID1-service-WEB3": {
					URL:    "http://10.10.10.10:83",
					Weight: label.DefaultWeight,
				},
			},
		},
		{
			desc: "with segments and portname labels",
			tasks: segmentedTaskData([]string{"a", "b", "c"},
				aTask("ID1",
					withIP("10.10.10.10"),
					withInfo("name1",
						withPorts(
							withPort("TCP", 81, "WEB1"),
							withPort("TCP", 82, "WEB2"),
							withPort("TCP", 83, "WEB3"),
						)),
					withSegmentLabel(label.TraefikPortName, "WEB2", "a"),
					withSegmentLabel(label.TraefikPortName, "WEB3", "b"),
					withSegmentLabel(label.TraefikPortName, "WEB1", "c"),
					withStatus(withHealthy(true), withState("TASK_RUNNING")),
				),
			),

			expected: map[string]types.Server{
				"server-ID1-service-a": {
					URL:    "http://10.10.10.10:82",
					Weight: label.DefaultWeight,
				},
				"server-ID1-service-b": {
					URL:    "http://10.10.10.10:83",
					Weight: label.DefaultWeight,
				},
				"server-ID1-service-c": {
					URL:    "http://10.10.10.10:81",
					Weight: label.DefaultWeight,
				},
			},
		},
	}

	p := &Provider{
		Domain:           "docker.localhost",
		ExposedByDefault: true,
		IPSources:        "host",
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual := p.getServers(test.tasks)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetBackendName(t *testing.T) {
	testCases := []struct {
		desc      string
		mesosTask taskData
		expected  string
	}{
		{
			desc: "label missing",
			mesosTask: aTaskData("group-app-taskID", "",
				withInfo("/group/app"),
			),
			expected: "group-app",
		},
		{
			desc: "label existing",
			mesosTask: aTaskData("", "",
				withInfo(""),
				withLabel(label.TraefikBackend, "bar"),
			),
			expected: "bar",
		},
		{
			desc: "segment label existing",
			mesosTask: aTaskData("", "app",
				withInfo(""),
				withSegmentLabel(label.TraefikBackend, "bar", "app"),
			),
			expected: "bar",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			actual := getBackendName(test.mesosTask)

			assert.Equal(t, test.expected, actual)
		})
	}
}

func TestGetFrontendRule(t *testing.T) {
	p := Provider{
		Domain: "mesos.localhost",
	}

	testCases := []struct {
		desc      string
		mesosTask taskData
		expected  string
	}{
		{
			desc: "label missing",
			mesosTask: aTaskData("test", "",
				withInfo("foo"),
			),
			expected: "Host:foo.mesos.localhost",
		},
		{
			desc: "label domain",
			mesosTask: aTaskData("test", "",
				withInfo("foo"),
				withLabel(label.TraefikDomain, "traefik.localhost"),
			),
			expected: "Host:foo.traefik.localhost",
		},
		{
			desc: "with segment",
			mesosTask: aTaskData("test", "bar",
				withInfo("foo"),
				withLabel(label.TraefikDomain, "traefik.localhost"),
			),
			expected: "Host:bar.foo.traefik.localhost",
		},
		{
			desc: "frontend rule available",
			mesosTask: aTaskData("test", "",
				withInfo("foo"),
				withLabel(label.TraefikFrontendRule, "Host:foo.bar"),
			),
			expected: "Host:foo.bar",
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			rule := p.getFrontendRule(test.mesosTask)

			assert.Equal(t, test.expected, rule)
		})
	}
}
