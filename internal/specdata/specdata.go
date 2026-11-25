// Package specdata exposes the operations and response examples of the identity, tenancy, billing and
// admin OpenAPI documents, extracted by cmd/genspec (make gen). The admin double and the
// upstream fakes serve these examples, so they cannot drift from the contract.
package specdata

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

//go:embed identity.json tenancy.json billing.json admin.json
var files embed.FS

// Response is one declared response of an operation.
type Response struct {
	Status      int            `json:"status"`
	ContentType string         `json:"content_type"`
	Examples    map[string]any `json:"examples"`
	Headers     []string       `json:"headers"`
}

// Operation is one operation of a document.
type Operation struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Permission string `json:"permission"`
	// PermissionByKind is x-permission-by-kind (approval operations).
	PermissionByKind map[string]string `json:"permission_by_kind"`
	// World is the operation's x-example-world; empty means the default world "base".
	World string `json:"world"`
	// RequiresGrant: the operation takes the Hostry-Vendor-Approval header.
	RequiresGrant  bool       `json:"requires_grant"`
	ServiceCallers []string   `json:"service_callers"`
	Security       [][]string `json:"security"`
	Responses      []Response `json:"responses"`

	segs []string
}

// Doc is one service's operations.
type Doc struct {
	Service string `json:"service"`
	// Worlds are the example worlds the spec declares (info.x-example-worlds).
	Worlds     []string    `json:"worlds"`
	Operations []Operation `json:"operations"`
}

var (
	mu    sync.Mutex
	cache = map[string]*Doc{}
)

// Load returns the document for service ("identity", "tenancy" or "admin").
func Load(service string) (*Doc, error) {
	mu.Lock()
	defer mu.Unlock()
	if d, ok := cache[service]; ok {
		return d, nil
	}
	b, err := files.ReadFile(service + ".json")
	if err != nil {
		return nil, fmt.Errorf("specdata: unknown service %q", service)
	}
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	for i := range d.Operations {
		d.Operations[i].segs = strings.Split(strings.Trim(d.Operations[i].Path, "/"), "/")
	}
	// Literal segments win over templates: sort by number of template segments.
	sort.SliceStable(d.Operations, func(i, j int) bool {
		return templates(d.Operations[i].segs) < templates(d.Operations[j].segs)
	})
	cache[service] = &d
	return &d, nil
}

// MustLoad is Load for tests and doubles.
func MustLoad(service string) *Doc {
	d, err := Load(service)
	if err != nil {
		panic(err)
	}
	return d
}

func templates(segs []string) int {
	n := 0
	for _, s := range segs {
		if strings.HasPrefix(s, "{") {
			n++
		}
	}
	return n
}

// Op returns an operation by id.
func (d *Doc) Op(id string) (*Operation, bool) {
	for i := range d.Operations {
		if d.Operations[i].ID == id {
			return &d.Operations[i], true
		}
	}
	return nil, false
}

// Match finds the operation for a method and path and returns its path parameters. pathKnown
// reports whether the path matches some operation under another method (405).
func (d *Doc) Match(method, path string) (op *Operation, params map[string]string, pathKnown bool) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i := range d.Operations {
		o := &d.Operations[i]
		p, ok := matchSegs(o.segs, segs)
		if !ok {
			continue
		}
		pathKnown = true
		if o.Method == method {
			return o, p, true
		}
	}
	return nil, nil, pathKnown
}

func matchSegs(tmpl, segs []string) (map[string]string, bool) {
	if len(tmpl) != len(segs) {
		return nil, false
	}
	var params map[string]string
	for i, t := range tmpl {
		if strings.HasPrefix(t, "{") {
			if params == nil {
				params = map[string]string{}
			}
			params[strings.Trim(t, "{}")] = segs[i]
			continue
		}
		if t != segs[i] {
			return nil, false
		}
	}
	return params, true
}

// Success is the lowest 2xx response.
func (o *Operation) Success() *Response {
	for i := range o.Responses {
		if o.Responses[i].Status >= 200 && o.Responses[i].Status < 300 {
			return &o.Responses[i]
		}
	}
	return nil
}

// Response returns the declared response for a status.
func (o *Operation) Response(status int) (*Response, bool) {
	for i := range o.Responses {
		if o.Responses[i].Status == status {
			return &o.Responses[i], true
		}
	}
	return nil, false
}

// Example returns the named example ("" means "default", else the first by name).
func (r *Response) Example(name string) (any, bool) {
	if name != "" {
		v, ok := r.Examples[name]
		return v, ok
	}
	if v, ok := r.Examples["default"]; ok {
		return v, true
	}
	names := make([]string, 0, len(r.Examples))
	for n := range r.Examples {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, false
	}
	return r.Examples[names[0]], true
}

// Write writes the response with its example body (empty for no content).
func (r *Response) Write(w http.ResponseWriter, example string) {
	if r.ContentType != "" {
		w.Header().Set("Content-Type", r.ContentType)
	}
	for _, h := range r.Headers {
		if h == "Retry-After" {
			w.Header().Set("Retry-After", "1")
		}
	}
	w.WriteHeader(r.Status)
	if v, ok := r.Example(example); ok {
		if s, isStr := v.(string); isStr && !strings.Contains(r.ContentType, "json") {
			_, _ = w.Write([]byte(s)) // text/csv and the like are written as they are
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}
}

// Methods lists the methods the document declares for a path (for an Allow header).
func (d *Doc) Methods(path string) []string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var ms []string
	for i := range d.Operations {
		if _, ok := matchSegs(d.Operations[i].segs, segs); ok {
			ms = append(ms, d.Operations[i].Method)
		}
	}
	sort.Strings(ms)
	return ms
}
