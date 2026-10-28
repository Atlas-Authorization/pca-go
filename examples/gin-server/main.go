package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"

	pca "github.com/Atlas-Authorization/pca-go"
)

func main() {
	audience := flag.String("audience", "payments-rs", "this server's id; proofs must be signed for it")
	grantsFile := flag.String("grants", "grants.json", "JSON array of the grants this server accepts")
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	raw, err := os.ReadFile(*grantsFile)
	if err != nil {
		log.Fatal(err)
	}
	var grants []map[string]any
	if err := json.Unmarshal(raw, &grants); err != nil {
		log.Fatal(err)
	}

	p := pca.Protect(pca.ProtectOptions{Audience: *audience, Grants: grants, Operation: operationFor})
	log.Fatal(newRouter(p).Run(*addr))
}
