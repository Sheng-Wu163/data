package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/Sheng-Wu163/data/internal/fingerprint"
	"github.com/Sheng-Wu163/data/internal/model"
	"github.com/Sheng-Wu163/data/rules"
)

func newEngine(t *testing.T) *fingerprint.Engine {
	t.Helper()
	set, err := rules.Load("")
	if err != nil {
		t.Fatalf("load embedded rules: %v", err)
	}
	return fingerprint.New(set)
}

// TestIdentifyKnownBanners covers the self-test fixtures plus the variants
// listed in the task input, asserting the exact depth the task example shows.
func TestIdentifyKnownBanners(t *testing.T) {
	e := newEngine(t)

	cases := []struct {
		name     string
		in       model.Input
		protocol string
		product  string
		version  string
		osHint   string
		conf     float64
	}{
		{"openssh-ubuntu", model.Input{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95},
		{"nginx", model.Input{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", "", 0.9},
		{"apache", model.Input{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", "", 0.9},
		{"mysql-8", model.Input{IP: "1.2.3.7", Port: 3306, Banner: "J\x00\x00\x00\n8.0.32\x00"}, "MySQL", "MySQL", "8.0.32", "", 0.9},
		{"redis-err", model.Input{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", "", 0.7},
		{"proftpd", model.Input{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", "", 0.9},
		{"jetty", model.Input{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", "", 0.85},
		{"openssh-debian", model.Input{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian", 0.95},
		{"nginx-ubuntu", model.Input{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu", 0.9},
		{"apache-ubuntu", model.Input{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, "HTTP", "Apache", "2.4.41", "Ubuntu", 0.9},
		{"mysql-57", model.Input{IP: "1.2.3.14", Port: 3306, Banner: "J\x00\x00\x00\n5.7.42\x00"}, "MySQL", "MySQL", "5.7.42", "", 0.9},
		{"redis-pong", model.Input{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"}, "Redis", "Redis", "", "", 0.7},
		{"vsftpd", model.Input{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "FTP", "vsFTPd", "3.0.5", "", 0.9},
		{"nginx-8443", model.Input{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, "HTTP", "nginx", "1.25.3", "", 0.9},
		{"openssh-old", model.Input{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", "", 0.95},
		{"tls-hello", model.Input{IP: "1.2.3.19", Port: 9999, Banner: "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1"}, "TLS", "", "", "", 0.6},
		{"iis", model.Input{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft-IIS", "10.0", "", 0.9},
		{"redis-noauth", model.Input{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."}, "Redis", "Redis", "", "", 0.7},
		{"pureftpd", model.Input{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", "", 0.9},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := e.Identify(tc.in)
			if got.Protocol != tc.protocol {
				t.Errorf("protocol = %q, want %q", got.Protocol, tc.protocol)
			}
			if got.Product != tc.product {
				t.Errorf("product = %q, want %q", got.Product, tc.product)
			}
			if got.Version != tc.version {
				t.Errorf("version = %q, want %q", got.Version, tc.version)
			}
			if got.OSHint != tc.osHint {
				t.Errorf("os_hint = %q, want %q", got.OSHint, tc.osHint)
			}
			if got.Confidence != tc.conf {
				t.Errorf("confidence = %v, want %v", got.Confidence, tc.conf)
			}
		})
	}
}

// TestExtendedVariants covers daemon variants beyond the base fixtures.
func TestExtendedVariants(t *testing.T) {
	e := newEngine(t)

	cases := []struct {
		name     string
		in       model.Input
		protocol string
		product  string
		version  string
	}{
		{"mariadb", model.Input{IP: "10.0.0.7", Port: 3306, Banner: "J\x00\x00\x00\n5.5.5-10.3.34-MariaDB\x00"}, "MySQL", "MariaDB", "10.3.34"},
		{"dropbear", model.Input{IP: "10.0.0.1", Port: 22, Banner: "SSH-2.0-dropbear_2020.81"}, "SSH", "dropbear", "2020.81"},
		{"jetty-paren", model.Input{IP: "10.0.0.8", Port: 8080, Banner: "HTTP/1.1 200 OK\r\nServer: Jetty(9.4.51.v20230217)"}, "HTTP", "Jetty", "9.4.51"},
		{"nginx-no-version", model.Input{IP: "10.0.0.2", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx"}, "HTTP", "nginx", ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := e.Identify(tc.in)
			if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version {
				t.Errorf("got %s/%s/%s, want %s/%s/%s", got.Protocol, got.Product, got.Version, tc.protocol, tc.product, tc.version)
			}
		})
	}
}

// TestUnknownIsNotAnError verifies unrecognised input degrades gracefully and
// that address/port are always echoed back.
func TestUnknownIsNotAnError(t *testing.T) {
	e := newEngine(t)

	cases := []model.Input{
		{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"},
		{IP: "1.2.3.24", Port: 1, Banner: ""},
		{IP: "1.2.3.25", Port: 2, Banner: "\xff\xfe\x00garbage"},
		{IP: "1.2.3.26", Port: 3, Banner: strings.Repeat("A", 1<<16)},
		{IP: "1.2.3.27", Port: 4, Banner: "220 mail.example.com ESMTP Postfix"}, // SMTP must not be misread as FTP
		{IP: "1.2.3.28", Port: 5, Banner: "hello, world"},
	}

	for _, in := range cases {
		got := e.Identify(in)
		if got.Protocol != "unknown" {
			t.Errorf("%s:%d protocol = %q, want unknown", in.IP, in.Port, got.Protocol)
		}
		if got.IP != in.IP || got.Port != in.Port {
			t.Errorf("address not echoed: got %s:%d, want %s:%d", got.IP, got.Port, in.IP, in.Port)
		}
		if got.Confidence != 0 {
			t.Errorf("%s:%d confidence = %v, want 0 for unknown", in.IP, in.Port, got.Confidence)
		}
	}
}

// TestLiteralEscapeNormalization ensures banners that carry literal "\x00"
// text (as they appear in raw scanner JSON) are still recognised.
func TestLiteralEscapeNormalization(t *testing.T) {
	e := newEngine(t)

	got := e.Identify(model.Input{IP: "9.9.9.9", Port: 3306, Banner: `J\x00\x00\x00\n8.0.32\x00`})
	if got.Protocol != "MySQL" || got.Version != "8.0.32" {
		t.Fatalf("literal-escape MySQL: got %+v", got)
	}
}

// TestIdentifyAllPreservesOrderAndLength guards batch behaviour.
func TestIdentifyAllPreservesOrderAndLength(t *testing.T) {
	e := newEngine(t)
	items := []model.Input{
		{IP: "a", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1"},
		{IP: "b", Port: 9999, Banner: "nonsense"},
		{IP: "c", Port: 6379, Banner: "+PONG"},
	}
	results := e.IdentifyAll(items)
	if len(results) != len(items) {
		t.Fatalf("len = %d, want %d", len(results), len(items))
	}
	if results[0].Protocol != "SSH" || results[1].Protocol != "unknown" || results[2].Protocol != "Redis" {
		t.Fatalf("unexpected batch results: %+v", results)
	}
}

// TestEmptyBatch returns an empty (non-nil) slice so it marshals as [].
func TestEmptyBatch(t *testing.T) {
	e := newEngine(t)
	results := e.IdentifyAll(nil)
	if results == nil {
		t.Fatal("expected non-nil slice")
	}
	if len(results) != 0 {
		t.Fatalf("len = %d, want 0", len(results))
	}
}
