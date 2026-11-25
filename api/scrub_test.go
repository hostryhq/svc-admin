package api

import "testing"

func TestScrubRefusesWhatTheBrowserMustNeverSee(t *testing.T) {
	refuse := []struct{ name, body string }{
		{"full number with country code", `{"name":"Call +919876543210"}`},
		{"full number without country code", `{"note":"9876543210"}`},
		{"number deep in a list", `{"items":[{"a":{"b":["x","+916123456789"]}}]}`},
		{"mobile field", `{"mobile_e164":"+91*******210"}`},
		{"phone field", `{"phone":"x"}`},
		{"customer email", `{"items":[{"email":"owner@customer.example"}]}`},
		{"key material", `{"public_key":"abc"}`},
		{"proof key", `{"device":{"proof_key":"abc"}}`},
		{"pin verifier", `{"pin_verifier":"abc"}`},
		{"an access token", `{"access_token":"tok"}`},
		{"a renewal handle", `{"renewal_handle":"h"}`},
		{"a password", `{"password":"p"}`},
	}
	for _, c := range refuse {
		t.Run("refuses "+c.name, func(t *testing.T) {
			if err := scrub([]byte(c.body), scrubOpts{}); err == nil {
				t.Fatalf("%s was let through", c.body)
			}
		})
	}
	allow := []struct {
		name, body string
		o          scrubOpts
	}{
		{"masked number", `{"mobile_masked":"+91*******210"}`, scrubOpts{}},
		{"ids and timestamps", `{"id":"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60","at":"2026-11-24T13:05:11.120Z","n":1234567890}`, scrubOpts{}},
		{"a GSTIN", `{"gstin":"33ABCDE1234F1Z5"}`, scrubOpts{}},
		{"staff email on staff records", `{"email":"staff@example.invalid"}`, scrubOpts{allowEmail: true}},
		{"a ten digit number in a JSON number", `{"amount":9876543210}`, scrubOpts{}},
	}
	for _, c := range allow {
		t.Run("allows "+c.name, func(t *testing.T) {
			if err := scrub([]byte(c.body), c.o); err != nil {
				t.Fatalf("%s refused: %v", c.body, err)
			}
		})
	}
}

func TestNormaliseIDPattern(t *testing.T) {
	for id, want := range map[string]bool{
		"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60": true,
		"01ARZ3NDEKTSV4RRFFQ69G5FAV":           true,
		"0190a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a60": false, // not a version 7 id
		"../x":                                 false,
		"":                                     false,
	} {
		if got := idRe.MatchString(id); got != want {
			t.Errorf("idRe(%q) = %v, want %v", id, got, want)
		}
	}
}
