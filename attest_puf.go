package pca

// The PUF attestation root (attest-puf): a physically unclonable function response is turned into a stable key by a code-offset
// fuzzy extractor (repetition code, HKDF-SHA-256), the key seeds an Ed25519 / ML-DSA identity, and the device signs statements bound
// to holder, grant, epoch and nonce. The verifier checks them against an enrollment of the derived public key. Unclonability is
// classical; the derived key may carry a post-quantum suite. This is software-level attestation (weights_measured is false); the
// simulated provider is for tests and the TPM EK provider reads an endorsement key through tpm2-tools (injectable runner).

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"
)

const (
	// PufExtractInfo is the HKDF info of the fuzzy-extractor key extraction.
	PufExtractInfo = "atlas-pca/puf-extract/v1"
	// PufAttestDomain separates PUF attestation statements from every other signed surface.
	PufAttestDomain = "atlas-pca/attest-puf/v1\x00"
	// PufKeyBytes is the length of the extracted key (the seed of the derived identity).
	PufKeyBytes = 32
	// TpmEkPufDomain is the HKDF salt of the TPM EK provider's response derivation.
	TpmEkPufDomain = "atlas-pca/puf-tpm-ek/v1"
)

// FuzzyExtractorParams are the repetition code parameters: Rep (odd, the repetition factor) and MessageBits; a response is Rep*MessageBits bits.
type FuzzyExtractorParams struct{ Rep, MessageBits int }

// FuzzyExtractorHelper is the public helper data: the packed sketch and salt (base64url) and the parameters.
type FuzzyExtractorHelper struct {
	Sketch, Salt        string
	Rep, MessageBits, N int
}

func (h FuzzyExtractorHelper) wire() map[string]any {
	return map[string]any{"sketch": h.Sketch, "salt": h.Salt, "rep": h.Rep, "messageBits": h.MessageBits, "n": h.N}
}

// RepetitionCorrectionBound is the number of bit flips per codeword the repetition code corrects: floor((rep-1)/2) (the floor, as for a
// non-positive rep, where it is negative).
func RepetitionCorrectionBound(rep int) int { return (rep - 1) >> 1 }

func pufAssertBits(b []byte, where string) error {
	for _, x := range b {
		if x > 1 {
			return fmt.Errorf("%s: response must be a 0/1 bit array", where)
		}
	}
	return nil
}

func pufXor(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = (a[i] ^ b[i]) & 1
	}
	return out
}

func pufRepEncode(msg []byte, rep int) []byte {
	out := make([]byte, len(msg)*rep)
	for i, m := range msg {
		for j := 0; j < rep; j++ {
			out[i*rep+j] = m & 1
		}
	}
	return out
}

func pufRepDecode(code []byte, rep int) []byte {
	k := len(code) / rep
	out := make([]byte, k)
	for i := 0; i < k; i++ {
		ones := 0
		for j := 0; j < rep; j++ {
			ones += int(code[i*rep+j] & 1)
		}
		if ones*2 > rep { // strict majority; ties (even rep) resolve to 0, so use an odd rep
			out[i] = 1
		}
	}
	return out
}

func pufPack(bits []byte) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b&1 == 1 {
			out[i>>3] |= 1 << (i & 7)
		}
	}
	return out
}

func pufUnpack(packed []byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = (packed[i>>3] >> (i & 7)) & 1
	}
	return out
}

func pufExtractKey(bits, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, pufPack(bits), salt, PufExtractInfo, PufKeyBytes)
}

// FuzzyEnroll enrolls a response: it draws a random message and salt through randomBytes, publishes the sketch (codeword XOR response)
// and returns the extracted key with the helper data. rep must be odd and positive; the response must be exactly rep*messageBits bits.
func FuzzyEnroll(responseBits []byte, p FuzzyExtractorParams, randomBytes func(n int) ([]byte, error)) (key []byte, helper FuzzyExtractorHelper, err error) {
	if p.Rep < 1 || p.Rep%2 == 0 {
		return nil, helper, errors.New("fuzzyEnroll: rep must be an odd positive integer")
	}
	if p.MessageBits < 1 {
		return nil, helper, errors.New("fuzzyEnroll: messageBits must be a positive integer")
	}
	n := p.Rep * p.MessageBits
	if len(responseBits) != n {
		return nil, helper, fmt.Errorf("fuzzyEnroll: response length %d != rep*messageBits %d", len(responseBits), n)
	}
	if err = pufAssertBits(responseBits, "fuzzyEnroll"); err != nil {
		return
	}
	mr, err := randomBytes(p.MessageBits)
	if err != nil {
		return nil, helper, err
	}
	m := make([]byte, p.MessageBits)
	for i := range m {
		m[i] = mr[i] & 1
	}
	sketch := pufXor(pufRepEncode(m, p.Rep), responseBits)
	salt, err := randomBytes(32)
	if err != nil {
		return nil, helper, err
	}
	if key, err = pufExtractKey(responseBits, salt); err != nil {
		return nil, helper, err
	}
	return key, FuzzyExtractorHelper{Sketch: b64.EncodeToString(pufPack(sketch)), Salt: b64.EncodeToString(salt), Rep: p.Rep, MessageBits: p.MessageBits, N: n}, nil
}

// FuzzyReproduce recovers the enrolled key from a noisy response and the helper data, correcting up to RepetitionCorrectionBound flips
// per codeword. A malformed helper or response is an error.
func FuzzyReproduce(responseBits []byte, h FuzzyExtractorHelper) ([]byte, error) {
	if h.Rep < 1 || h.Rep%2 == 0 || h.MessageBits < 1 {
		return nil, errors.New("fuzzyReproduce: malformed helper params")
	}
	n := h.Rep * h.MessageBits
	if h.N != n {
		return nil, errors.New("fuzzyReproduce: helper.n inconsistent with rep*messageBits")
	}
	if len(responseBits) != n {
		return nil, fmt.Errorf("fuzzyReproduce: response length %d != %d", len(responseBits), n)
	}
	if err := pufAssertBits(responseBits, "fuzzyReproduce"); err != nil {
		return nil, err
	}
	packed, ok1 := DecodeB64uStrict(h.Sketch, -1)
	salt, ok2 := DecodeB64uStrict(h.Salt, -1)
	if !ok1 || !ok2 {
		return nil, errors.New("fuzzyReproduce: helper sketch or salt is not canonical base64url")
	}
	if len(packed) != (n+7)/8 {
		return nil, errors.New("fuzzyReproduce: helper sketch has the wrong length")
	}
	if len(salt) != 32 {
		return nil, errors.New("fuzzyReproduce: helper salt has the wrong length")
	}
	sketch := pufUnpack(packed, n)
	mHat := pufRepDecode(pufXor(responseBits, sketch), h.Rep)
	return pufExtractKey(pufXor(pufRepEncode(mHat, h.Rep), sketch), salt)
}

// PufProvider yields the (noisy) response of a PUF to a challenge as a 0/1 bit array.
type PufProvider interface {
	ID() string
	Response(challenge []byte) ([]byte, error)
}

func pufStream(prefix []byte, nbits int) []byte {
	nblocks := max(1, ((nbits+7)/8+31)/32)
	stream := make([]byte, 0, nblocks*32)
	for blk := 0; blk < nblocks; blk++ {
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], uint32(blk))
		h := sha256.Sum256(append(slices.Clone(prefix), ctr[:]...))
		stream = append(stream, h[:]...)
	}
	bits := make([]byte, nbits)
	for i := range bits {
		bits[i] = (stream[i>>3] >> (i & 7)) & 1
	}
	return bits
}

type simulatedPuf struct {
	id     string
	seed   []byte
	length int
	flip   []int
}

func (s *simulatedPuf) ID() string { return s.id }
func (s *simulatedPuf) Response(challenge []byte) ([]byte, error) {
	bits := pufStream(append(slices.Clone(s.seed), challenge...), s.length)
	for _, p := range s.flip {
		if p >= 0 && p < len(bits) {
			bits[p] ^= 1
		}
	}
	return bits, nil
}

// NewSimulatedPuf is a deterministic simulated PUF (test and demo use): a SHA-256 stream over seed and challenge, with the listed bit
// positions flipped to model noise.
func NewSimulatedPuf(id string, seed []byte, length int, flip []int) PufProvider {
	// the reference keeps the flips in a Set: a position listed twice is flipped once
	uniq := make([]int, 0, len(flip))
	for _, f := range flip {
		if !slices.Contains(uniq, f) {
			uniq = append(uniq, f)
		}
	}
	return &simulatedPuf{id: id, seed: slices.Clone(seed), length: length, flip: uniq}
}

// TpmCommandResult is the outcome of running a TPM tool. Status is nil when the process did not start; Error then says why.
type TpmCommandResult struct {
	Status *int
	Stdout []byte
	Stderr string
	Error  string
}

// TpmCommandRunner runs a tpm2-tools command and returns its output; a nil result is refused (fail closed).
type TpmCommandRunner func(command string, args []string) *TpmCommandResult

// DefaultTpmCommandRunner runs the command with a 15 second timeout and a 1 MiB output cap; a failure to start is Status nil with Error set.
func DefaultTpmCommandRunner(command string, args []string) *TpmCommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout, cmd.Stderr = &limitedWriter{w: &out, n: 1 << 20}, &errb
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			st := ee.ExitCode()
			return &TpmCommandResult{Status: &st, Stdout: out.Bytes(), Stderr: errb.String()}
		}
		return &TpmCommandResult{Stdout: out.Bytes(), Stderr: errb.String(), Error: command + ": " + err.Error()}
	}
	zero := 0
	return &TpmCommandResult{Status: &zero, Stdout: out.Bytes()}
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.w.Len()+len(p) > l.n {
		return 0, errors.New("output exceeds the cap")
	}
	return l.w.Write(p)
}

// TpmEkPufOptions configure NewTpmEkPufProvider. Length is the enrolled rep*messageBits. Run defaults to DefaultTpmCommandRunner, Tool
// to tpm2_readpublic, EkHandle to 0x81010001, MinEkBytes to 64.
type TpmEkPufOptions struct {
	ID         string
	Length     int
	Run        TpmCommandRunner
	Tool       string
	EkHandle   string
	Args       []string
	MinEkBytes int
}

// TpmEkPufProvider derives a PUF response from the TPM endorsement key public part: a software stand-in for a physical PUF, tied to the
// chip. Any failure to read the key is an error (fail closed).
type TpmEkPufProvider struct {
	id                 string
	length, minEkBytes int
	run                TpmCommandRunner
	tool               string
	args               []string
}

// NewTpmEkPufProvider validates the options and builds the provider.
func NewTpmEkPufProvider(o TpmEkPufOptions) (*TpmEkPufProvider, error) {
	if o.ID == "" {
		return nil, errors.New("TpmEkPufProvider: id must be a non-empty string")
	}
	if o.Length < 1 {
		return nil, errors.New("TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)")
	}
	if o.MinEkBytes < 0 {
		return nil, errors.New("TpmEkPufProvider: minEkBytes must be a positive integer")
	}
	p := &TpmEkPufProvider{id: o.ID, length: o.Length, run: o.Run, tool: o.Tool, minEkBytes: o.MinEkBytes, args: o.Args}
	if p.run == nil {
		p.run = DefaultTpmCommandRunner
	}
	if p.tool == "" {
		p.tool = "tpm2_readpublic"
	}
	if p.minEkBytes == 0 {
		p.minEkBytes = 64
	}
	if p.args == nil {
		h := o.EkHandle
		if h == "" {
			h = "0x81010001"
		}
		p.args = []string{"-c", h, "-f", "der", "-o", "/dev/stdout", "-Q"}
	}
	return p, nil
}

// ID implements PufProvider.
func (p *TpmEkPufProvider) ID() string { return p.id }

// ReadEkPublic reads the EK public key (DER) through the tool; any failure or a short answer is an error.
func (p *TpmEkPufProvider) ReadEkPublic() (ek []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			ek, err = nil, fmt.Errorf("TpmEkPufProvider: tpm2-tools invocation threw (fail closed): %v", r)
		}
	}()
	res := p.run(p.tool, p.args)
	if res == nil {
		return nil, errors.New("TpmEkPufProvider: command runner returned no result (fail closed)")
	}
	if res.Error != "" {
		return nil, fmt.Errorf("TpmEkPufProvider: tpm2-tools unavailable (fail closed): %s", res.Error)
	}
	if res.Status == nil || *res.Status != 0 {
		st := "null"
		if res.Status != nil {
			st = fmt.Sprint(*res.Status)
		}
		msg := ""
		if s := strings.TrimSpace(res.Stderr); s != "" {
			msg = ": " + s
		}
		return nil, fmt.Errorf("TpmEkPufProvider: '%s' exited with status %s (fail closed)%s", p.tool, st, msg)
	}
	if len(res.Stdout) < p.minEkBytes {
		return nil, fmt.Errorf("TpmEkPufProvider: EK public too short (%d < %d bytes) — TPM unavailable or wrong handle (fail closed)", len(res.Stdout), p.minEkBytes)
	}
	return res.Stdout, nil
}

// Response implements PufProvider: HKDF(EK public, salt = domain, info = challenge) expanded into Length bits.
func (p *TpmEkPufProvider) Response(challenge []byte) ([]byte, error) {
	ek, err := p.ReadEkPublic()
	if err != nil {
		return nil, err
	}
	secret, err := hkdf.Key(sha256.New, ek, []byte(TpmEkPufDomain), string(challenge), 32)
	if err != nil {
		return nil, err
	}
	return pufStream(secret, p.length), nil
}

// PufSuites are the suites a PUF-derived key supports.
var PufSuites = []string{"ed25519", "ml-dsa-65", "ml-dsa-87"}

func pufSigner(alg string, seed []byte) (public string, opts *SuiteOpts, ed *KeyPair, err error) {
	switch alg {
	case "ed25519":
		kp, err := KeyPairFromSeedB64u(b64.EncodeToString(seed))
		if err != nil {
			return "", nil, nil, err
		}
		return kp.Public, &SuiteOpts{Alg: alg}, kp, nil
	case "ml-dsa-65", "ml-dsa-87":
		fam := map[string]string{"ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87"}[alg]
		pq, err := GeneratePqKeyPairFromSeed(fam, seed)
		if err != nil {
			return "", nil, nil, err
		}
		return pq.Public, &SuiteOpts{Alg: alg, Pq: pq}, nil, nil
	}
	return "", nil, nil, fmt.Errorf("PUF root: unsupported derived suite '%s' (use ed25519, ml-dsa-65 or ml-dsa-87)", alg)
}

// PufEnrollment is the public enrollment of a device: the challenge, the derived suite and public key, the helper data and its
// commitment (a verifier refuses tampered helper data).
type PufEnrollment struct {
	ProviderID, Challenge, Alg, PublicKey string
	Helper                                FuzzyExtractorHelper
	HelperCommitment                      string
	NotAfter                              *int64 // epoch ms; nil: never
}

func pufHelperCommitment(h FuzzyExtractorHelper) (string, error) {
	n, err := normObj(h.wire())
	if err != nil {
		return "", err
	}
	return HashCanonical(n)
}

// EnrollPufOptions configure EnrollPuf. Alg defaults to ml-dsa-65; RandomBytes to crypto/rand.
type EnrollPufOptions struct {
	FuzzyExtractorParams
	Alg         string
	RandomBytes func(n int) ([]byte, error)
}

func pufRandom(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// EnrollPuf enrolls a device: it reads the response to the challenge, runs the fuzzy extractor, derives the identity key of the suite
// from the extracted key and returns the public enrollment (the key itself is discarded).
func EnrollPuf(p PufProvider, challenge []byte, o EnrollPufOptions) (*PufEnrollment, error) {
	alg := o.Alg
	if alg == "" {
		alg = "ml-dsa-65"
	}
	if !slices.Contains(PufSuites, alg) {
		return nil, fmt.Errorf("PUF root: unsupported derived suite '%s' (use ed25519, ml-dsa-65 or ml-dsa-87)", alg)
	}
	rnd := o.RandomBytes
	if rnd == nil {
		rnd = pufRandom
	}
	bits, err := p.Response(challenge)
	if err != nil {
		return nil, err
	}
	key, helper, err := FuzzyEnroll(bits, o.FuzzyExtractorParams, rnd)
	if err != nil {
		return nil, err
	}
	pub, _, _, err := pufSigner(alg, key)
	clear(key)
	if err != nil {
		return nil, err
	}
	hc, err := pufHelperCommitment(helper)
	if err != nil {
		return nil, err
	}
	return &PufEnrollment{ProviderID: p.ID(), Challenge: b64.EncodeToString(challenge), Alg: alg, PublicKey: pub, Helper: helper, HelperCommitment: hc}, nil
}

// PufClaims are the claims a PUF attestor signs; an empty WeightsDigest is omitted.
type PufClaims struct {
	Measurement, WeightsDigest, HolderPub, GrantRef, Nonce string
	Epoch                                                  float64
}

func pufStatementMessage(body map[string]any) ([]byte, error) {
	cb, err := CanonicalBytes(body)
	if err != nil {
		return nil, err
	}
	return append([]byte(PufAttestDomain), cb...), nil
}

// PufAttestor signs statements by re-deriving the device key from a fresh noisy response.
type PufAttestor struct {
	provider PufProvider
	enr      PufEnrollment
	chal     []byte
}

// CreatePufAttestor binds a provider to its enrollment; an unsupported enrolled suite or a malformed challenge is an error.
func CreatePufAttestor(p PufProvider, e PufEnrollment) (*PufAttestor, error) {
	if !slices.Contains(PufSuites, e.Alg) {
		return nil, fmt.Errorf("PUF root: unsupported derived suite '%s' (use ed25519, ml-dsa-65 or ml-dsa-87)", e.Alg)
	}
	chal, ok := DecodeB64uStrict(e.Challenge, -1)
	if !ok {
		return nil, errors.New("createPufAttestor: the enrolled challenge is not canonical base64url")
	}
	return &PufAttestor{provider: p, enr: e, chal: chal}, nil
}

// Attest reproduces the key from the device and signs a statement bound to holder, grant, epoch and nonce.
func (a *PufAttestor) Attest(c PufClaims) (map[string]any, error) {
	bits, err := a.provider.Response(a.chal)
	if err != nil {
		return nil, err
	}
	key, err := FuzzyReproduce(bits, a.enr.Helper)
	if err != nil {
		return nil, err
	}
	_, opts, ed, err := pufSigner(a.enr.Alg, key)
	clear(key)
	if err != nil {
		return nil, err
	}
	binding, err := AttestationBindingB64u(ExpectedAttestationBinding{HolderPub: c.HolderPub, GrantRef: c.GrantRef, Epoch: c.Epoch, Nonce: c.Nonce})
	if err != nil {
		return nil, err
	}
	body := map[string]any{"provider_id": a.provider.ID(), "measurement": c.Measurement, "binding": binding, "alg": a.enr.Alg}
	if c.WeightsDigest != "" {
		body["weights_digest"] = c.WeightsDigest
	}
	n, err := normObj(body)
	if err != nil {
		return nil, err
	}
	msg, err := pufStatementMessage(n)
	if err != nil {
		return nil, err
	}
	sig, pqSig, err := signWithSuite(opts, ed, msg)
	if err != nil {
		return nil, err
	}
	n["sig"] = sig
	if pqSig != "" {
		n["pq_sig"] = pqSig
	}
	return n, nil
}

// PufEnrollmentRegistry is an in-memory enrollment set with revocation (a revoked provider no longer resolves).
type PufEnrollmentRegistry struct {
	byID    map[string]PufEnrollment
	revoked map[string]bool
}

// NewPufEnrollmentRegistry builds a registry over the enrollments (later duplicates overwrite).
func NewPufEnrollmentRegistry(enrollments ...PufEnrollment) *PufEnrollmentRegistry {
	r := &PufEnrollmentRegistry{byID: map[string]PufEnrollment{}, revoked: map[string]bool{}}
	for _, e := range enrollments {
		r.Register(e)
	}
	return r
}

// Register adds or replaces an enrollment.
func (r *PufEnrollmentRegistry) Register(e PufEnrollment) { r.byID[e.ProviderID] = e }

// Lookup returns the enrollment of a provider, or false when unknown or revoked.
func (r *PufEnrollmentRegistry) Lookup(id string) (PufEnrollment, bool) {
	if r.revoked[id] {
		return PufEnrollment{}, false
	}
	e, ok := r.byID[id]
	return e, ok
}

// Revoke marks a provider revoked.
func (r *PufEnrollmentRegistry) Revoke(id string) { r.revoked[id] = true }

// IsRevoked reports whether a provider is revoked.
func (r *PufEnrollmentRegistry) IsRevoked(id string) bool { return r.revoked[id] }

// PufPolicy is the acceptance policy of the PUF root. Measurements is a required non-empty allowlist.
type PufPolicy struct {
	Measurements        []string
	WeightsMeasurements []string
	// DeriveIdentity maps a statement to the measured identity (default: weights_measured false, runtime = measurement).
	DeriveIdentity func(statement map[string]any, e PufEnrollment) MeasuredIdentity
}

// PufVerifierOptions configure CreatePufVerifier.
type PufVerifierOptions struct {
	ResolveEnrollment func(providerID string, doc, ctx map[string]any) (PufEnrollment, bool)
	Policy            PufPolicy
	// RequirePq refuses a classical derived suite.
	RequirePq bool
	IsRevoked func(providerID string) bool
	// ResolveEvidence finds the statement of an action; nil means none is configured (fail closed).
	ResolveEvidence func(doc, ctx map[string]any) map[string]any
}

// PufVerifier is the PUF root as an AttestationHardwareVerifier, labelled software / puf.
type PufVerifier struct {
	o                     PufVerifierOptions
	measurements, weights []string
}

// CreatePufVerifier builds the verifier; it errors without a non-empty measurement allowlist or without ResolveEnrollment.
func CreatePufVerifier(o PufVerifierOptions) (*PufVerifier, error) {
	if len(o.Policy.Measurements) == 0 {
		return nil, errors.New("createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
	}
	if o.ResolveEnrollment == nil {
		return nil, errors.New("createPufVerifier: resolveEnrollment is required")
	}
	return &PufVerifier{o: o, measurements: slices.Clone(o.Policy.Measurements), weights: slices.Clone(o.Policy.WeightsMeasurements)}, nil
}

// Assurance implements AssuranceLabeler.
func (v *PufVerifier) Assurance() AssuranceLabel {
	return AssuranceLabel{Level: "software", Vendor: "puf"}
}

// VerifyHardware implements AttestationHardwareVerifier. It never panics.
func (v *PufVerifier) VerifyHardware(doc, ctx map[string]any, nowMs int64, expected ExpectedAttestationBinding) (res HardwareResult) {
	defer func() {
		if r := recover(); r != nil {
			res = hwFail(fmt.Sprintf("puf verification error (fail closed): %v", r))
		}
	}()
	if v.o.ResolveEvidence == nil {
		return hwFail("no PUF evidence resolver configured (fail closed)")
	}
	st := v.o.ResolveEvidence(doc, ctx)
	pid, pok := st["provider_id"].(string)
	alg, aok := st["alg"].(string)
	if st == nil || !pok || !aok {
		return hwFail("no PUF attestation statement for this action")
	}
	if v.o.IsRevoked != nil && v.o.IsRevoked(pid) {
		return hwFail(fmt.Sprintf("PUF enrollment for provider '%s' is revoked", pid))
	}
	enr, found := v.o.ResolveEnrollment(pid, doc, ctx)
	if !found {
		return hwFail(fmt.Sprintf("no PUF enrollment registered for provider '%s'", pid))
	}
	if enr.NotAfter != nil && !(nowMs < *enr.NotAfter) {
		return hwFail("PUF enrollment has expired")
	}
	if hc, err := pufHelperCommitment(enr.Helper); err != nil || enr.HelperCommitment != hc {
		return hwFail("PUF enrollment helper commitment mismatch (helper tampered)")
	}
	if alg != enr.Alg {
		return hwFail(fmt.Sprintf("PUF statement suite '%s' does not match the enrolled suite '%s'", alg, enr.Alg))
	}
	su, ok := resolveSigAlg(alg, true)
	if !ok {
		return hwFail(fmt.Sprintf("PUF statement declares an unknown signature alg '%s'", alg))
	}
	if v.o.RequirePq && !pqSuiteHasPq(su) {
		return hwFail(fmt.Sprintf("PQ required: PUF-derived suite '%s' is classical", su.alg))
	}
	body := make(map[string]any, len(st))
	for k, val := range st {
		if k != "sig" && k != "pq_sig" {
			body[k] = val
		}
	}
	msg, err := pufStatementMessage(body)
	if err != nil {
		return hwFail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)")
	}
	key := PinnedPqKey{}
	if su.needsPqPk {
		key = callerVouchedPqKey(enr.PublicKey)
	}
	if !verifyLeafSuite(alg, true, enr.PublicKey, key, msg, st["sig"], st["pq_sig"]) {
		return hwFail("PUF statement signature does not verify under the enrolled public key (wrong/cloned device or excessive noise)")
	}
	if expected == (ExpectedAttestationBinding{}) { // nothing supplied (the reference's missing `expected`)
		return hwFail("no expected attestation binding supplied")
	}
	want, err := AttestationBindingB64u(expected)
	if err != nil {
		return hwFail("binding not constructible: " + err.Error())
	}
	if b, ok := st["binding"].(string); !ok || b != want {
		return hwFail("PUF statement binding mismatch (holder/grant/epoch/nonce)")
	}
	if m, ok := st["measurement"].(string); !ok || !slices.Contains(v.measurements, m) {
		return hwFail("measurement not in policy allowlist")
	}
	if len(v.weights) > 0 {
		if w, ok := st["weights_digest"].(string); !ok || !slices.Contains(v.weights, w) {
			return hwFail("measured weights digest not in policy allowlist")
		}
	}
	id := MeasuredIdentity{RuntimeMeasurement: fmt.Sprint(st["measurement"])}
	if w, ok := st["weights_digest"].(string); ok {
		id.WeightsDigest = w
	}
	if v.o.Policy.DeriveIdentity != nil {
		id = v.o.Policy.DeriveIdentity(st, enr)
	}
	return HardwareResult{OK: true, Bound: true, Measured: id.Map(), HostAsserted: map[string]string{"provider_id": pid, "suite": su.alg}}
}
