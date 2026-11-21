package pca

// Replays the reference corpus for the Cloudflare Worker adapter: decide, strip inbound x-pca-* headers, deny JSON, the forged-header
// 400. A request is {method, url, headers}; next and respond are injected.

import (
	"sort"
	"strings"
	"testing"
)

func TestGatewayWorkerVectors(t *testing.T) {
	replayVectors(t, "ref-gateway-worker.json.gz", map[string]vecFn{
		"workerScenario": func(a []any) (any, error) {
			s := vecObj(vecArg(a, 0))
			ev := vecObj(s["events"].([]any)[0])
			hdrs := map[string]string{}
			for k, v := range vecObj(ev["headers"]) {
				hdrs[k] = v.(string)
			}
			wo := GatewayWorkerOptions{Gateway: gwTestOptions(s)}
			wo.Next = func(r GatewayWorkerRequest) (any, error) {
				h := map[string]any{}
				for k, v := range r.Headers {
					h[strings.ToLower(k)] = v
				}
				return map[string]any{"forwarded": map[string]any{"method": r.Method, "url": r.URL, "headers": h}}, nil
			}
			wo.Respond = func(body string, status int, headers map[string]string) any {
				v, _ := ParseJSONLenient([]byte(body))
				return map[string]any{"status": status, "headers": gwHeaderAny(headers), "body": v}
			}
			switch ev["rewrite"] {
			case "null":
				wo.NoRewrite = true
			case "custom":
				wo.Rewrite = func(r GatewayWorkerRequest, drop []string) (GatewayWorkerRequest, bool) {
					kept := map[string]string{}
					for k, v := range r.Headers {
						if !contains(drop, k) {
							kept[k] = v
						}
					}
					d := append([]string{}, drop...)
					sort.Strings(d)
					kept["x-rewritten"] = strings.Join(d, ",")
					r.Headers = kept
					return r, true
				}
			}
			w, err := GatewayCloudflareWorker(wo)
			if err != nil {
				return map[string]any{"create": err.Error()}, nil
			}
			out, err := w(GatewayWorkerRequest{Method: vecStr(ev, "method"), URL: vecStr(ev, "url"), Headers: hdrs})
			if err != nil {
				return map[string]any{"threw": err.Error()}, nil
			}
			return gwTestMask(out), nil
		},
	})
}
