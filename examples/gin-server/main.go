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
	mediatorsFile := flag.String("mediators", "", "JSON array of the agent-harness keys to pin: [{mediator, kid, pk, pq_pk?}]")
	flag.Parse()

	raw, err := os.ReadFile(*grantsFile)
	if err != nil {
		log.Fatal(err)
	}
	var grants []map[string]any
	if err := json.Unmarshal(raw, &grants); err != nil {
		log.Fatal(err)
	}

	// provenance by default: without a pinned harness every payment escalates to the principal
	var pins []pca.ProvMediatorPin
	if *mediatorsFile != "" {
		raw, err := os.ReadFile(*mediatorsFile)
		if err != nil {
			log.Fatal(err)
		}
		var list []map[string]string
		if err := json.Unmarshal(raw, &list); err != nil {
			log.Fatal(err)
		}
		for _, m := range list {
			pins = append(pins, pca.ProvMediatorPin{Mediator: m["mediator"], Kid: m["kid"], PK: m["pk"], PQPK: m["pq_pk"]})
		}
	}

	p := pca.Protect(pca.ProtectOptions{Audience: *audience, Grants: grants, Operation: operationFor,
		Authorize: &pca.AuthorizeOptions{ArgProvenance: &pca.ArgProvenanceOptions{Mediators: pins}}})
	log.Fatal(newRouter(p).Run(*addr))
}
