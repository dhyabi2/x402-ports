package x402gateway

// XNO on Nano, checked against the operator's own Nano node, opt-in.
//
// A port of python/x402_gateway/src/x402_gateway/nano.py (itself a port of
// src/nano.js and src/nano-claims-file.js from @profullstack/x402-gateway),
// the "XNO checked by your own node" mode.
//
// A Nano block has no memo, so a confirmed send proves money reached an
// account and says nothing about which sale it paid for, and its hash is
// public, so anyone who reads the ledger can present it. Two checks close
// that, following the xno-binding v1 order commitment
// (https://github.com/dhyabi2/xno-call-binding/blob/main/docs/BINDING-STANDARD.md,
// option C):
//
//   - Bound to the order. The payer picks a random order id and signs its
//     send with representative set to SHA-256("xno-binding/v1/rep|" + orderId
//     + "|" + payTo + "|" + amountRaw), encoded as a nano_ account. The gateway
//     recomputes that from the order id in the proof and the offered payee and
//     amount, so a block only proves the order it was signed for.
//   - Single-use, across restarts. A verified block is claimed in a store the
//     operator supplies (block hash and order id, each at most once).
//     FileClaims appends and fsyncs every claim and reads them back on start.
//
// No key, no seed, no signing: the node is only read (block_info). Amounts
// are integer raw (1 XNO = 10^30 raw) and must match exactly. Addresses are
// checksum-validated. Standard library only.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RawPerXNO is raw per XNO. Every Nano amount here is an integer number of raw.
var RawPerXNO = new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)

// ------------------------------------------------------------- accounts --

const nanoAlphabet = "13456789abcdefghijkmnopqrstuwxyz"

var nanoAccountRe = regexp.MustCompile(`^(nano|xrb)_([13][13456789abcdefghijkmnopqrstuwxyz]{59})$`)

func encode32(v *big.Int, chars int) string {
	out := make([]byte, chars)
	n := new(big.Int).Set(v)
	five := big.NewInt(31)
	for i := chars - 1; i >= 0; i-- {
		out[i] = nanoAlphabet[new(big.Int).And(n, five).Int64()]
		n.Rsh(n, 5)
	}
	return string(out)
}

func decode32(s string) *big.Int {
	v := new(big.Int)
	for i := 0; i < len(s); i++ {
		v.Lsh(v, 5)
		v.Or(v, big.NewInt(int64(strings.IndexByte(nanoAlphabet, s[i]))))
	}
	return v
}

// nanoChecksum is the 5-byte BLAKE2b checksum of a public key, in the order the address writes it.
func nanoChecksum(key []byte) []byte {
	d := blake2b(key, 5)
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
	return d
}

// AccountFromKey writes a 32-byte public key (or any 32 bytes) as a nano_ account.
func AccountFromKey(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("an account is 32 bytes")
	}
	return "nano_" + encode32(new(big.Int).SetBytes(key), 52) + encode32(new(big.Int).SetBytes(nanoChecksum(key)), 8), nil
}

// AccountKey is the 32-byte public key of a nano_ or xrb_ account, or nil if
// the text is not one or its checksum does not match. A mistyped address that
// still fits the alphabet fails here rather than taking payments for an
// account nobody holds.
func AccountKey(address string) []byte {
	m := nanoAccountRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(address)))
	if m == nil {
		return nil
	}
	k := decode32(m[2][:52])
	if k.BitLen() > 256 {
		return nil
	}
	key := k.FillBytes(make([]byte, 32))
	if new(big.Int).SetBytes(nanoChecksum(key)).Cmp(decode32(m[2][52:])) != 0 {
		return nil
	}
	return key
}

// CanonicalAccount is a checksum-valid account in canonical nano_ form, or "".
func CanonicalAccount(address string) string {
	key := AccountKey(address)
	if key == nil {
		return ""
	}
	a, _ := AccountFromKey(key)
	return a
}

// NanoPayee is a Nano payee in canonical nano_ form, or "" if it is not one.
func NanoPayee(address string) string { return CanonicalAccount(address) }

func jsRound(x, scale float64) *big.Int {
	f := x * scale
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return new(big.Int)
	}
	b, _ := big.NewFloat(math.Floor(f + 0.5)).Int(nil)
	return b
}

// XNORaw is a price in raw XNO, rounded UP, at rate units of the price's
// currency per XNO. Integer arithmetic throughout: the rate is read to 10^-9
// and the price to 10^-6 of a cent, as the reference does. "" if either is
// not a positive number.
func XNORaw(priceCents, rate float64) string {
	cents := jsRound(priceCents, 1e6)
	per := jsRound(rate, 1e9)
	if cents.Sign() <= 0 || per.Sign() <= 0 {
		return ""
	}
	// raw = (cents / 100) / rate * 10^30 = (cents*1e6) * 10^31 / (rate*1e9)
	num := new(big.Int).Mul(cents, new(big.Int).Exp(big.NewInt(10), big.NewInt(31), nil))
	num.Add(num, new(big.Int).Sub(per, big.NewInt(1)))
	return num.Quo(num, per).String()
}

// -------------------------------------------------------------- binding --

// NanoBinding marks an offer entry whose proof must be bound to its order (xno-binding v1).
const NanoBinding = "xno-binding/v1/rep"

var orderIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
var rawRe = regexp.MustCompile(`^[1-9][0-9]*$`)

// NewOrderID is a fresh random order id: 16 bytes, base64url, 22 characters.
func NewOrderID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("x402gateway: no randomness for an order id: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// IsOrderID reports whether an order id is long and plain enough to be a secret the payer chose at random.
func IsOrderID(orderID string) bool { return orderIDRe.MatchString(orderID) }

// OrderCommitment is SHA-256("xno-binding/v1/rep|" + orderId + "|" + payTo + "|" + amountRaw).
func OrderCommitment(orderID, payTo, amount string) []byte {
	h := sha256.Sum256([]byte(NanoBinding + "|" + orderID + "|" + payTo + "|" + amount))
	return h[:]
}

// OrderRepresentative is the representative a payer sets on its send to bind it to this order.
func OrderRepresentative(orderID, payTo, amount string) string {
	a, _ := AccountFromKey(OrderCommitment(orderID, payTo, amount))
	return a
}

// ------------------------------------------------------------- the node --

var loopbackRe = regexp.MustCompile(`(?i)^(localhost|127(?:\.\d{1,3}){3}|::1)$`)

// NodeURL is the node URL if it is one the gateway will read money from:
// https, or plain http only on loopback (a node beside the gateway). "" otherwise.
func NodeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.User != nil {
		return ""
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return ""
		}
	}
	if u.Scheme == "https" || (u.Scheme == "http" && loopbackRe.MatchString(u.Hostname())) {
		u.Fragment = ""
		if u.Path == "" {
			u.Path = "/"
		}
		return u.String()
	}
	return ""
}

const nanoMaxBody = 64 * 1024

// nanoBlock is one block as the node reports it.
type nanoBlock struct {
	account, to, representative, amount, subtype, kind string
	confirmed                                          bool
}

func readBlock(ctx context.Context, client *http.Client, blockHash, rpcURL string) (nanoBlock, string) {
	body, _ := json.Marshal(map[string]string{"action": "block_info", "json_block": "true", "hash": blockHash})
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		return nanoBlock{}, "the Nano node did not answer"
	}
	req.Header.Set("content-type", "application/json")
	if client == nil {
		client = http.DefaultClient
	}
	res, err := client.Do(req)
	if err != nil {
		return nanoBlock{}, "the Nano node did not answer"
	}
	defer res.Body.Close()
	text, err := io.ReadAll(io.LimitReader(res.Body, nanoMaxBody+1))
	if err != nil {
		return nanoBlock{}, "the Nano node did not answer"
	}
	if len(text) > nanoMaxBody {
		return nanoBlock{}, "the Nano node answer is too large"
	}
	var info map[string]any
	if json.Unmarshal(text, &info) != nil {
		return nanoBlock{}, "the Nano node answer is not JSON"
	}
	c, ok := info["contents"].(map[string]any)
	if e := str(info["error"]); e != "" || !ok {
		detail := ""
		if e != "" {
			detail = " (" + e + ")"
		}
		return nanoBlock{}, "the Nano node does not know this block" + detail
	}
	account := str(info["block_account"])
	if account == "" {
		account = str(c["account"])
	}
	return nanoBlock{
		account:        CanonicalAccount(account),
		to:             CanonicalAccount(str(c["link_as_account"])),
		representative: CanonicalAccount(str(c["representative"])),
		amount:         str(info["amount"]),
		subtype:        str(info["subtype"]),
		kind:           str(c["type"]),
		confirmed:      info["confirmed"] == true || info["confirmed"] == "true",
	}, ""
}

// --------------------------------------------------------------- claims --

// Claim is the outcome of claiming a block: "new" (credit it), "same" (this
// block was already claimed by this same order, at At) or "taken".
type Claim struct {
	Status string
	At     int64
}

// NanoClaims remembers which Nano blocks were credited: each block hash and
// each order id at most once. Production stores must survive a restart
// (FileClaims, or a table with both columns UNIQUE).
type NanoClaims interface {
	Claim(blockHash, orderID string, at int64) Claim
}

type claimHeld struct {
	order string
	at    int64
}

// MemoryClaims keeps claims in memory. For tests and for trying the flow out
// only: a restart forgets every claim, and every block it forgot can be
// presented again.
type MemoryClaims struct {
	mu      sync.Mutex
	byHash  map[string]claimHeld
	byOrder map[string]string
}

// NewMemoryClaims is an empty in-memory store.
func NewMemoryClaims() *MemoryClaims {
	return &MemoryClaims{byHash: map[string]claimHeld{}, byOrder: map[string]string{}}
}

func (m *MemoryClaims) held(blockHash, orderID string) (Claim, bool) {
	if h, ok := m.byHash[blockHash]; ok {
		if h.order == orderID {
			return Claim{Status: "same", At: h.at}, true
		}
		return Claim{Status: "taken"}, true
	}
	if _, ok := m.byOrder[orderID]; ok {
		return Claim{Status: "taken"}, true
	}
	return Claim{}, false
}

func (m *MemoryClaims) keep(blockHash, orderID string, at int64) {
	m.byHash[blockHash] = claimHeld{orderID, at}
	m.byOrder[orderID] = blockHash
}

// Claim claims a block for an order.
func (m *MemoryClaims) Claim(blockHash, orderID string, at int64) Claim {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.held(blockHash, orderID); ok {
		return c
	}
	m.keep(blockHash, orderID, at)
	return Claim{Status: "new", At: at}
}

// Len is the number of claims held.
func (m *MemoryClaims) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byHash)
}

var claimLineRe = regexp.MustCompile(`^([0-9A-F]{64}) ([A-Za-z0-9_-]{22,128}) (\d+)$`)

// FileClaims keeps Nano claims in a file, so a restart does not make old
// blocks spendable again.
//
// One line per claim, "<BLOCK HASH> <order id> <unix seconds>", appended and
// fsynced before the claim is reported as new, and read back on start. A torn
// last line from a crash mid-write is skipped. One process per file: the
// check-then-append is atomic inside this process (a mutex covers
// goroutines), not across processes.
type FileClaims struct {
	MemoryClaims
	path string
}

// NewFileClaims opens (or starts) a claims file.
func NewFileClaims(path string) (*FileClaims, error) {
	if path == "" {
		return nil, errors.New("FileClaims needs a path")
	}
	f := &FileClaims{MemoryClaims: MemoryClaims{byHash: map[string]claimHeld{}, byOrder: map[string]string{}}, path: path}
	text, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, line := range strings.Split(string(text), "\n") {
		m := claimLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		if _, ok := f.byHash[m[1]]; ok {
			continue
		}
		if _, ok := f.byOrder[m[2]]; ok {
			continue
		}
		at, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			continue
		}
		f.keep(m[1], m[2], at)
	}
	return f, nil
}

// Claim claims a block for an order, writing it to the file first.
func (f *FileClaims) Claim(blockHash, orderID string, at int64) Claim {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.held(blockHash, orderID); ok {
		return c
	}
	line := blockHash + " " + orderID + " " + strconv.FormatInt(at, 10)
	if !claimLineRe.MatchString(line) {
		return Claim{Status: "taken"}
	}
	fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return Claim{Status: "taken"}
	}
	// A newline first, so a torn line left by a crash cannot swallow this one.
	_, werr := fh.WriteString("\n" + line + "\n")
	serr := fh.Sync()
	cerr := fh.Close()
	if werr != nil || serr != nil || cerr != nil {
		return Claim{Status: "taken"}
	}
	f.keep(blockHash, orderID, at)
	return Claim{Status: "new", At: at}
}

// --------------------------------------------------------------- settle --

var blockHashRe = regexp.MustCompile(`^[0-9A-F]{64}$`)

// SettleNano checks a Nano proof against the node and claims it.
//
// expected is the offered entry's amount and payTo for the days the proof
// pays for. The Settlement is OK with the payer and the block hash as Ref, or
// carries the reason; Replay with ClaimedAt (unix seconds) means the block is
// already claimed by this same order, which is the payer retrying after
// losing the answer.
func SettleNano(ctx context.Context, client *http.Client, payment any, expected Expected, rpcURL string, claims NanoClaims, now int64) Settlement {
	refuse := func(reason string) Settlement { return Settlement{Reason: reason} }
	blockHash := strings.ToUpper(str(get(payment, "payload", "blockHash")))
	if !blockHashRe.MatchString(blockHash) {
		return refuse("A Nano proof needs payload.blockHash, the 64-hex hash of the send block.")
	}
	orderID, _ := get(payment, "payload", "orderId").(string)
	if !IsOrderID(orderID) {
		return refuse("A Nano proof needs payload.orderId, the random order id (22 to 128 of A-Z a-z 0-9 _ -) the send committed to in its representative (" + NanoBinding + ").")
	}
	payTo := CanonicalAccount(expected.PayTo)
	amount := expected.Amount
	if payTo == "" || !rawRe.MatchString(amount) {
		return refuse("No Nano offer to hold this proof to.")
	}

	block, errText := readBlock(ctx, client, blockHash, rpcURL)
	if errText != "" {
		return refuse(errText)
	}
	if !block.confirmed {
		return refuse("The Nano block is not confirmed yet. Present it again once it is.")
	}
	if block.kind != "state" || block.subtype != "send" {
		return refuse("The Nano block is not a send.")
	}
	if block.to != payTo {
		return refuse("The Nano block does not pay this gateway.")
	}
	if block.amount != amount {
		sent := block.amount
		if sent == "" {
			sent = "nothing"
		}
		return refuse("The Nano block sends " + sent + " raw; this offer is exactly " + amount + " raw.")
	}
	representative := OrderRepresentative(orderID, payTo, amount)
	if block.representative != representative {
		return refuse("The Nano block is not bound to this order: its representative must be " + representative + " (" + NanoBinding + ").")
	}

	switch c := claims.Claim(blockHash, orderID, now); c.Status {
	case "new":
		return Settlement{OK: true, Payer: block.account, Ref: blockHash}
	case "same":
		return Settlement{Reason: "This Nano block was already used for this order.", Replay: true, ClaimedAt: c.At}
	}
	return refuse("This Nano block or order id has already been used.")
}

// NanoOptions switch on XNO, checked on the operator's own Nano node.
type NanoOptions struct {
	PayTo    string                  // a checksum-valid nano_ (or xrb_) account
	Rate     float64                 // the price of 1 XNO in Options.Currency
	RateFunc func() (float64, error) // read per offer instead of Rate, when set
	RPCURL   string                  // the operator's own node: https, or http on localhost
	Claims   NanoClaims              // a store that remembers credited blocks across restarts (NewFileClaims)
}

type nanoConfig struct {
	payTo  string
	rate   func() (float64, error)
	rpcURL string
	claims NanoClaims
}

// normaliseNano is the Nano settings, or nil when there is no valid payee.
// This port reads Nano proofs from the operator's own node only, so a payee
// comes with RPCURL and Claims or not at all: reading blocks from a node
// without remembering which ones were credited would sell the same block
// again and again.
func normaliseNano(n *NanoOptions) (*nanoConfig, error) {
	if n == nil {
		return nil, nil
	}
	payTo := NanoPayee(n.PayTo)
	if payTo == "" {
		return nil, nil
	}
	if n.RPCURL == "" {
		return nil, errors.New("x402gateway: Nano needs RPCURL: this port checks Nano proofs on your own node (block_info, no key)")
	}
	rpcURL := NodeURL(n.RPCURL)
	if rpcURL == "" {
		return nil, errors.New("x402gateway: Nano RPCURL must be https, or http on localhost")
	}
	if n.Claims == nil {
		return nil, errors.New("x402gateway: Nano RPCURL needs Nano Claims, a store that remembers credited blocks across restarts (NewFileClaims)")
	}
	rate := n.RateFunc
	if rate == nil {
		r := n.Rate
		rate = func() (float64, error) { return r, nil }
	}
	return &nanoConfig{payTo: payTo, rate: rate, rpcURL: rpcURL, claims: n.Claims}, nil
}

// --------------------------------------------------------------- BLAKE2b --

// blake2b is unkeyed BLAKE2b (RFC 7693) with a digest of size bytes (1 to 64),
// here only for the 5-byte Nano address checksum: the standard library has none.
func blake2b(msg []byte, size int) []byte {
	iv := [8]uint64{
		0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	h := iv
	h[0] ^= 0x01010000 ^ uint64(size)
	var t uint64
	block := make([]byte, 128)
	for len(msg) > 128 {
		copy(block, msg[:128])
		t += 128
		blake2bCompress(&h, &iv, block, t, false)
		msg = msg[128:]
	}
	for i := range block {
		block[i] = 0
	}
	copy(block, msg)
	t += uint64(len(msg))
	blake2bCompress(&h, &iv, block, t, true)
	out := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out[:size]
}

var blake2bSigma = [12][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

func blake2bCompress(h, iv *[8]uint64, block []byte, t uint64, last bool) {
	var m [16]uint64
	for i := range m {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}
	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], iv[:])
	v[12] ^= t
	if last {
		v[14] = ^v[14]
	}
	g := func(a, b, c, d int, x, y uint64) {
		v[a] = v[a] + v[b] + x
		v[d] = bits.RotateLeft64(v[d]^v[a], -32)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -24)
		v[a] = v[a] + v[b] + y
		v[d] = bits.RotateLeft64(v[d]^v[a], -16)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -63)
	}
	for r := 0; r < 12; r++ {
		s := &blake2bSigma[r]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}
