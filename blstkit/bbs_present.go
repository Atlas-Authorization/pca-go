package blstkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
)

// BbsAPIID is the BBS API identifier of the ciphersuite (the domain tag of the hash-to-scalar and generator derivations).
const BbsAPIID = bbsAPIID

// BbsMessagesToScalars maps each message octet string to its scalar (draft section 4.2).
func BbsMessagesToScalars(messages [][]byte) []*big.Int { return messagesToScalars(messages) }

// BbsSkToBytes is the 32-octet big-endian secret scalar (to serialize a given SK).
func BbsSkToBytes(sk *big.Int) ([]byte, error) { return i2osp(sk, 32) }

// BbsSkFromBytes parses a 32-octet secret scalar; zero and values at or above the group order are refused.
func BbsSkFromBytes(b []byte) (*big.Int, error) {
	if len(b) != 32 {
		return nil, errors.New("bbs: SK must be 32 octets")
	}
	sk := new(big.Int).SetBytes(b)
	if sk.Sign() == 0 || sk.Cmp(BbsR) >= 0 {
		return nil, errors.New("bbs: SK out of range")
	}
	return sk, nil
}

// BbsPresentCredential produces a selective-disclosure proof revealing only the named attributes of a credential.
// presentationHeader binds the proof to a context (the action digest or a nonce). An unknown attribute name is an error.
func BbsPresentCredential(cred map[string]any, disclose []string, presentationHeader []byte) (map[string]any, error) {
	pks, ok1 := jsonStr(cred, "issuerPublicKey")
	hs, ok2 := jsonStr(cred, "header")
	ss, ok3 := jsonStr(cred, "signature")
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("presentCredential: malformed credential")
	}
	pk, ok1 := unb64u(pks)
	header, ok2 := unb64u(hs)
	sig, ok3 := unb64u(ss)
	attrs, ok4 := attrsOf(cred["attributes"])
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, errors.New("presentCredential: malformed credential")
	}
	wanted := map[string]bool{}
	for _, n := range disclose {
		wanted[n] = true
	}
	msgs, err := encodeAll(attrs)
	if err != nil {
		return nil, err
	}
	var idxs []int
	var shown []any
	seen := map[string]bool{}
	for _, a := range attrs {
		if wanted[a.name] {
			idxs = append(idxs, a.index)
			shown = append(shown, attrJSON(a))
			seen[a.name] = true
		}
	}
	var missing []string
	for n := range wanted {
		if !seen[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("presentCredential: unknown attribute(s): %v", missing)
	}
	proof, err := BbsProofGen(pk, sig, header, presentationHeader, msgs, idxs, nil)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"issuerPublicKey":    pks,
		"header":             hs,
		"presentationHeader": b64u.EncodeToString(presentationHeader),
		"messageCount":       json.Number(strconv.Itoa(len(attrs))),
		"disclosed":          shown,
		"proof":              b64u.EncodeToString(proof),
	}, nil
}
