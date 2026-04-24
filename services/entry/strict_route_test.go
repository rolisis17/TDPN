package entry

import "testing"

func TestIsDisallowedStrictRouteHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "loopback ipv4", host: "127.0.0.1", want: true},
		{name: "loopback shorthand", host: "127.1", want: true},
		{name: "loopback decimal alias", host: "2130706433", want: true},
		{name: "localhost trailing dot", host: "localhost.", want: true},
		{name: "private ipv4", host: "10.0.0.5", want: true},
		{name: "private ipv6 ula", host: "fd00::1", want: true},
		{name: "zoned ipv6", host: "fe80::1%eth0", want: true},
		{name: "public ipv4", host: "8.8.8.8", want: false},
		{name: "hostname", host: "relay.example", want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isDisallowedStrictRouteHost(tc.host); got != tc.want {
				t.Fatalf("isDisallowedStrictRouteHost(%q)=%t want=%t", tc.host, got, tc.want)
			}
		})
	}
}

func TestValidateStrictExitControlRouteRejectsPrivateIPHost(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("http://10.0.0.9:8084", "10.0.0.9:51820"); err == nil {
		t.Fatal("expected private control host to be rejected")
	}
}

func TestValidateStrictExitControlRouteRejectsLoopbackAliasHost(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("http://127.1:8084", "127.1:51820"); err == nil {
		t.Fatal("expected loopback alias control host to be rejected")
	}
}

func TestValidateStrictExitControlRouteAllowsPublicIPHost(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("https://8.8.8.8:8084", "8.8.8.8:51820"); err != nil {
		t.Fatalf("expected public control host to be accepted, got %v", err)
	}
}

func TestValidateStrictExitControlRouteRejectsPublicHTTPHost(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("http://8.8.8.8:8084", "8.8.8.8:51820"); err == nil {
		t.Fatal("expected strict mode to reject non-https control host")
	}
}

func TestValidateStrictExitControlRouteRejectsControlURLPathPrefix(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("https://8.8.8.8:8084/internal", "8.8.8.8:51820"); err == nil {
		t.Fatal("expected strict mode to reject control url path prefixes")
	}
}

func TestValidateStrictExitControlRouteRejectsZonedIPv6Host(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("http://[fe80::1%25eth0]:8084", "[fe80::1%25eth0]:51820"); err == nil {
		t.Fatal("expected zoned ipv6 host to be rejected")
	}
}

func TestValidateStrictExitControlRouteRejectsInvalidEndpoint(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("https://8.8.8.8:8084", "8.8.8.8"); err == nil {
		t.Fatal("expected strict mode to reject endpoint missing host:port")
	}
}

func TestValidateStrictExitControlRouteRejectsZonedIPv6Endpoint(t *testing.T) {
	t.Parallel()

	if err := validateStrictExitControlRoute("https://8.8.8.8:8084", "[fe80::1%25eth0]:51820"); err == nil {
		t.Fatal("expected strict mode to reject zoned ipv6 endpoint")
	}
}
