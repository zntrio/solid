// Licensed to SolID under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. SolID licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package httpfetch

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestFetcher builds a Fetcher whose transport dials the given test
// server and whose pre-flight SSRF check is replaced by a stub (the test
// server lives on loopback, which the real check forbids on purpose — see
// TestRejectsSpecialUseIP for that behavior).
func newTestFetcher(ts *httptest.Server, maxResponseBytes int64) *fetcher {
	f := NewTestFetcher(ts.Client(), maxResponseBytes).(*fetcher) //nolint:forcetypeassert // fixed type
	return f
}

func TestFetch(t *testing.T) {
	t.Run("ValidDocument", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 0)
		b, err := f.Fetch(context.Background(), ts.URL+"/doc.json")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(b) != `{"ok":true}` {
			t.Errorf("body = %s", b)
		}
	})

	t.Run("Non200Status", func(t *testing.T) {
		for _, code := range []int{301, 302, 404, 500} {
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			f := newTestFetcher(ts, 0)
			if _, err := f.Fetch(context.Background(), ts.URL+"/doc.json"); err == nil {
				t.Errorf("expected error for status %d", code)
			} else if (code == 301 || code == 302) && !strings.Contains(err.Error(), "status code") {
				t.Errorf("redirect must surface as non-200, got: %v", err)
			}
			ts.Close()
		}
	})

	t.Run("RedirectRejected", func(t *testing.T) {
		final := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer final.Close()

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, final.URL+"/doc.json", nil), final.URL+"/doc.json", http.StatusFound)
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 0)
		_, err := f.Fetch(context.Background(), ts.URL+"/doc.json")
		if err == nil {
			t.Fatal("expected redirect to be rejected")
		}
		if !strings.Contains(err.Error(), "status code 302") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("OversizeBody", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// 6 kB body, over the 5120-byte default cap.
			_, _ = w.Write(make([]byte, 6*1024))
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 0)
		_, err := f.Fetch(context.Background(), ts.URL+"/doc.json")
		if err == nil {
			t.Fatal("expected oversize error")
		}
		if !strings.Contains(err.Error(), "exceeds maximum size") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("CustomMaxBytes", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, 200))
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 100)
		if _, err := f.Fetch(context.Background(), ts.URL+"/doc.json"); err == nil {
			t.Fatal("expected oversize error for custom max")
		}
	})

	t.Run("SlowBodyKilledByDeadline", func(t *testing.T) {
		// Slow-loris: the server drips bytes slower than the wall-clock
		// deadline; the fetch must fail instead of hanging.
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			flusher, _ := w.(http.Flusher)
			// First chunk arrives quickly so headers complete...
			_, _ = w.Write(make([]byte, 10))
			if flusher != nil {
				flusher.Flush()
			}
			// ...then the body drips past DefaultTimeout (12s total, well
			// beyond the 10s deadline but quick to tear down).
			for i := 0; i < 24; i++ {
				time.Sleep(500 * time.Millisecond)
				_, _ = w.Write(make([]byte, 10))
				if flusher != nil {
					flusher.Flush()
				}
			}
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 0)

		start := time.Now()
		_, err := f.Fetch(context.Background(), ts.URL+"/doc.json")
		if err == nil {
			t.Fatal("expected deadline error for slow body")
		}
		if elapsed := time.Since(start); elapsed > DefaultTimeout+2*time.Second {
			t.Errorf("fetch outlived the deadline: %s", elapsed)
		}
	})

	t.Run("CallerContextDeadlineRespected", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(2 * time.Second)
		}))
		defer ts.Close()

		f := newTestFetcher(ts, 0)

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		_, err := f.Fetch(ctx, ts.URL+"/doc.json")
		if err == nil {
			t.Fatal("expected context deadline error")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("caller deadline was not respected: %s", elapsed)
		}
	})

	t.Run("RejectsSpecialUseIP", func(t *testing.T) {
		f := &fetcher{
			client:    http.DefaultClient,
			maxBytes:  DefaultMaxResponseBytes,
			preflight: rejectSpecialUseHost,
		}
		for _, id := range []string{
			"https://127.0.0.1/doc.json",
			"https://127.0.0.1:8443/doc.json",
			"https://10.0.0.5/doc.json",
			"https://192.168.1.10/doc.json",
			"https://192.0.2.7/doc.json",
			"https://198.51.100.7/doc.json",
			"https://203.0.113.7/doc.json",
			"https://169.254.169.254/doc.json", // cloud metadata endpoint
			"https://[::1]/doc.json",
			"https://[fe80::1]/doc.json",
			"https://[fc00::1]/doc.json",
			"https://[2001:db8::1]/doc.json",
		} {
			if _, err := f.Fetch(context.Background(), id); err == nil {
				t.Errorf("expected special-use rejection for %s", id)
			}
		}
	})

	t.Run("PublicLiteralIPNotSpecialUse", func(t *testing.T) {
		// Classification only: a global unicast literal is not
		// special-use; no real network connection is attempted.
		if err := rejectSpecialUseHost("https://93.184.216.34/doc.json"); err != nil {
			t.Errorf("public IP wrongly classified as special-use: %v", err)
		}
		if err := rejectSpecialUseHost("https://[2606:2800:220:1:248:1893:25c8:1946]/doc.json"); err != nil {
			t.Errorf("public IPv6 wrongly classified as special-use: %v", err)
		}
	})

	t.Run("DefaultClientRejectsLoopbackDial", func(t *testing.T) {
		// Defense-in-depth: even without the pre-flight check, the default
		// transport dial refuses loopback.
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("{}"))
		}))
		defer ts.Close()

		f := New(nil, 0).(*fetcher) //nolint:forcetypeassert // constructor return type is fixed
		// Bypass pre-flight to prove the dial guard itself.
		f.preflight = func(string) error { return nil }
		if _, err := f.Fetch(context.Background(), ts.URL+"/doc.json"); err == nil {
			t.Fatal("expected dial guard to refuse loopback")
		}
	})

	t.Run("CallerTransportPreserved", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer ts.Close()

		// Caller-provided insecure client (tests only) keeps working.
		insecure := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only
		}}
		f := NewTestFetcher(insecure, 0)
		if _, err := f.Fetch(context.Background(), ts.URL+"/doc.json"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("ImplementsFetcher", func(t *testing.T) {
		var _ Fetcher = New(nil, 0)
	})
}
