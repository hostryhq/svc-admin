// Command genspec reads bundled OpenAPI documents and writes, per service, a JSON file of its
// operations (method, path, permission, callers, security) and every response example. The
// admin double and the upstream test fakes serve these examples. Output is committed.
//
// Usage: genspec -out internal/specdata build/identity.yaml build/tenancy.yaml build/admin.yaml
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type response struct {
	Status      int            `json:"status"`
	ContentType string         `json:"content_type,omitempty"`
	Examples    map[string]any `json:"examples,omitempty"`
	Headers     []string       `json:"headers,omitempty"`
}

type operation struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Permission string `json:"permission,omitempty"`
	// PermissionByKind is x-permission-by-kind: the permission each kind of an approval needs on
	// top of the gate permission.
	PermissionByKind map[string]string `json:"permission_by_kind,omitempty"`
	// World is x-example-world: the named fixture the operation's examples assume.
	World          string     `json:"world,omitempty"`
	ServiceCallers []string   `json:"service_callers,omitempty"`
	Security       [][]string `json:"security"`
	Responses      []response `json:"responses"`
}

type document struct {
	Service string `json:"service"`
	// Worlds are the names declared in info.x-example-worlds.
	Worlds     []string    `json:"worlds,omitempty"`
	Operations []operation `json:"operations"`
}

var methods = []string{"get", "put", "post", "delete", "patch"}

func main() {
	out := flag.String("out", ".", "output directory")
	flag.Parse()
	for _, in := range flag.Args() {
		if err := run(in, *out); err != nil {
			fmt.Fprintln(os.Stderr, "genspec:", err)
			os.Exit(1)
		}
	}
}

func run(in, out string) error {
	b, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var raw map[string]any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return err
	}
	name := strings.TrimSuffix(filepath.Base(in), filepath.Ext(in))
	doc := document{Service: name}
	if info, ok := raw["info"].(map[string]any); ok {
		if ws, ok := info["x-example-worlds"].(map[string]any); ok {
			for w := range ws {
				doc.Worlds = append(doc.Worlds, w)
			}
			sort.Strings(doc.Worlds)
		}
	}
	paths, _ := raw["paths"].(map[string]any)
	for path, item := range paths {
		im, _ := item.(map[string]any)
		for _, m := range methods {
			om, ok := im[m].(map[string]any)
			if !ok {
				continue
			}
			doc.Operations = append(doc.Operations, buildOp(m, path, om, components(raw)))
		}
	}
	sort.Slice(doc.Operations, func(i, j int) bool { return doc.Operations[i].ID < doc.Operations[j].ID })
	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, name+".json"), append(data, '\n'), 0o644)
}

func buildOp(method, path string, om map[string]any, comps map[string]any) operation {
	op := operation{ID: str(om["operationId"]), Method: strings.ToUpper(method), Path: path,
		Permission: str(om["x-permission"]), Security: [][]string{}}
	op.World = str(om["x-example-world"])
	if pk, ok := om["x-permission-by-kind"].(map[string]any); ok {
		op.PermissionByKind = map[string]string{}
		for k, v := range pk {
			op.PermissionByKind[k] = str(v)
		}
	}
	if cs, ok := om["x-service-callers"].([]any); ok {
		for _, c := range cs {
			op.ServiceCallers = append(op.ServiceCallers, str(c))
		}
	}
	if sec, ok := om["security"].([]any); ok {
		for _, req := range sec {
			var names []string
			if rm, ok := req.(map[string]any); ok {
				for n := range rm {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			op.Security = append(op.Security, names)
		}
	}
	rs, _ := om["responses"].(map[string]any)
	for code, rv := range rs {
		st, err := strconv.Atoi(code)
		if err != nil {
			continue
		}
		r := response{Status: st}
		rm, _ := rv.(map[string]any)
		if ref, ok := rm["$ref"].(string); ok {
			rm, _ = comps[strings.TrimPrefix(ref, "#/components/responses/")].(map[string]any)
		}
		if hm, ok := rm["headers"].(map[string]any); ok {
			for h := range hm {
				r.Headers = append(r.Headers, h)
			}
			sort.Strings(r.Headers)
		}
		if cm, ok := rm["content"].(map[string]any); ok {
			for ct, mv := range cm {
				r.ContentType = ct
				mm, _ := mv.(map[string]any)
				r.Examples = map[string]any{}
				if ex, ok := mm["example"]; ok {
					r.Examples["default"] = ex
				}
				if exs, ok := mm["examples"].(map[string]any); ok {
					for n, e := range exs {
						if em, ok := e.(map[string]any); ok {
							r.Examples[n] = em["value"]
						}
					}
				}
			}
		}
		op.Responses = append(op.Responses, r)
	}
	sort.Slice(op.Responses, func(i, j int) bool { return op.Responses[i].Status < op.Responses[j].Status })
	return op
}

func components(raw map[string]any) map[string]any {
	c, _ := raw["components"].(map[string]any)
	r, _ := c["responses"].(map[string]any)
	return r
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
