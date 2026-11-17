package cycletls

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordingDialer dials target whatever address it is asked for, and records
// the addresses: a test server stands in for a host only the dialer can reach.
type recordingDialer struct {
	target string
	mu     sync.Mutex
	addrs  []string
}

func (d *recordingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.target)
}

func (d *recordingDialer) dials() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// failingDialer fails every dial with err.
type failingDialer struct{ err error }

func (d failingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, d.err
}

func newDialerTestServer(t *testing.T, tlsServer bool) *httptest.Server {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok " + r.Host)) })
	var srv *httptest.Server
	if tlsServer {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv
}

// The dialer is given the request's host:port, name unresolved, and makes the
// connection: the name below exists nowhere but in it.
func TestDoDialsThroughOptionsDialer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tls    bool
		scheme string
		port   string
	}{
		{"http", false, "http", "80"},
		{"https", true, "https", "443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newDialerTestServer(t, tc.tls)
			d := &recordingDialer{target: srv.Listener.Addr().String()}
			c := Init()
			defer c.Close()

			resp, err := c.Do(tc.scheme+"://only-the-dialer.invalid/", Options{
				Dialer:             d,
				InsecureSkipVerify: true,
				ForceHTTP1:         true,
				Timeout:            10,
			}, "GET")
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if resp.Status != 200 || !strings.HasPrefix(resp.Body, "ok ") {
				t.Fatalf("got %d %q, want 200 from the test server", resp.Status, resp.Body)
			}
			want := "only-the-dialer.invalid:" + tc.port
			if got := d.dials(); len(got) == 0 || got[0] != want {
				t.Fatalf("dialer asked for %v, want %q", got, want)
			}
		})
	}
}

// The client pool is process-wide and keyed on the fingerprint: two dialers
// with the same fingerprint must not share a client, or one caller's requests
// would leave through the other's connections.
func TestPoolKeepsDialersApart(t *testing.T) {
	srv := newDialerTestServer(t, false)
	c := Init()
	defer c.Close()

	do := func(d *recordingDialer, key string) {
		t.Helper()
		resp, err := c.Do("http://pooled.invalid/", Options{
			Dialer:                d,
			DialerKey:             key,
			EnableConnectionReuse: true,
			Timeout:               10,
		}, "GET")
		if err != nil || resp.Status != 200 {
			t.Fatalf("Do: %v (status %d, body %q)", err, resp.Status, resp.Body)
		}
	}

	a := &recordingDialer{target: srv.Listener.Addr().String()}
	b := &recordingDialer{target: srv.Listener.Addr().String()}
	do(a, "slot-a")
	do(b, "slot-b")
	if len(b.dials()) != 1 {
		t.Fatalf("slot-b's request did not go through its own dialer: a=%v b=%v", a.dials(), b.dials())
	}

	// The same key is the same client, and its connection is reused.
	do(a, "slot-a")
	if n := len(a.dials()); n != 1 {
		t.Errorf("slot-a dialled %d times, want its pooled connection reused", n)
	}

	// No key: never pooled, so even the same dialer dials anew.
	nk := &recordingDialer{target: srv.Listener.Addr().String()}
	do(nk, "")
	do(nk, "")
	if n := len(nk.dials()); n != 2 {
		t.Errorf("unkeyed dialer dialled %d times, want 2 (no pooling)", n)
	}
}

// What would bypass the dialer is refused rather than dialled directly.
func TestDialerRefusesWhatBypassesIt(t *testing.T) {
	d := &recordingDialer{target: "127.0.0.1:1"}
	c := Init()
	defer c.Close()

	for _, tc := range []struct {
		name string
		opts Options
		want error
	}{
		{"proxy", Options{Dialer: d, Proxy: "http://127.0.0.1:1"}, errDialerWithProxy},
		{"http3", Options{Dialer: d, ForceHTTP3: true}, errDialerHTTP3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Do("https://refused.invalid/", tc.opts, "GET")
			if !errors.Is(err, tc.want) {
				t.Fatalf("Do: err %v, want %v", err, tc.want)
			}
		})
	}
	if got := d.dials(); len(got) != 0 {
		t.Fatalf("dialer used for a refused request: %v", got)
	}
}

// A request whose Dialer fails gets no response, and Response.Err says why:
// the Dialer's own error, which the guessed Status cannot carry.
func TestResponseErrCarriesTheDialerError(t *testing.T) {
	refused := errors.New("refused by the dialer")
	resp, err := Init().Do("http://site.invalid/", Options{Dialer: failingDialer{refused}, DialerKey: "k", EnableConnectionReuse: false}, "GET")
	if err != nil {
		t.Fatalf("Do: %v, want the failure in the Response as before", err)
	}
	if !errors.Is(resp.Err, refused) {
		t.Fatalf("Response.Err = %v, want the dialer's error", resp.Err)
	}

	srv := newDialerTestServer(t, false)
	resp, err = Init().Do(srv.URL, Options{EnableConnectionReuse: false}, "GET")
	if err != nil || resp.Status != 200 || resp.Err != nil {
		t.Fatalf("answered request: err %v, status %d, Response.Err %v", err, resp.Status, resp.Err)
	}
}
