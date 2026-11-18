package x402gateway

// XNO on Nano, checked by the operator's own node: the cases of the Python
// port's tests/test_nano.py (themselves the JS reference's test/nano.test.js
// and the "XNO on Nano, opt-in" block of test/gateway.test.js), with the same
// constants.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const (
	// The all-zero key: the burn account, which every Nano tool prints the same way.
	nBurn  = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
	nPayTo = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
	// The key 0x01 * 32, so the payer is an account nobody is.
	nPayer = "nano_11a3161i41a3161i41a3161i41a3161i41a3161i41a3161i41a3bqbhquyj"
	nOrder = "Qm9yZGVyLWlkLWZvci10ZXN0cw"
	nSite  = "https://example.test"
	nEVM   = "0x1111111111111111111111111111111111111111"
	// 1.00 at 0.80 per XNO: 1.25 XNO.
	nRawAt080 = "1250000000000000000000000000000"
	nGOrder   = "b3JkZXItZm9yLWdhdGV3YXk"
)

var (
	nHash  = strings.Repeat("B", 64)
	nBlock = strings.Repeat("A", 64)
	// 0.05 XNO, derived, not typed.
	nAmount = new(big.Int).Quo(new(big.Int).Mul(big.NewInt(5), RawPerXNO), big.NewInt(100)).String()
)

// fakeNode knows one block and counts the reads. Anything not sent to /rpc is a CoinPay call.
type fakeNode struct {
	mu                                         sync.Mutex
	srv                                        *httptest.Server
	amount, confirmed, subtype, to, rep, known string
	confirmedBool                              *bool
	calls                                      []map[string]string
	coinpay                                    []string
}

type nodeOpt func(*fakeNode)

func newNode(t *testing.T, opts ...nodeOpt) *fakeNode {
	n := &fakeNode{amount: nAmount, confirmed: "true", subtype: "send", to: nPayTo, known: nHash}
	order, payTo := nOrder, nPayTo
	for _, o := range opts {
		o(n)
	}
	if n.rep == "" {
		n.rep = OrderRepresentative(order, payTo, n.amount)
	}
	n.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		if r.URL.Path != "/rpc" {
			n.coinpay = append(n.coinpay, r.URL.Path)
			w.WriteHeader(500)
			_, _ = w.Write([]byte("{}"))
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		n.calls = append(n.calls, req)
		if req["hash"] != n.known {
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Block not found"})
			return
		}
		var confirmed any = n.confirmed
		if n.confirmedBool != nil {
			confirmed = *n.confirmedBool
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"block_account": nPayer, "amount": n.amount, "confirmed": confirmed, "subtype": n.subtype,
			"contents": map[string]any{"type": "state", "account": nPayer, "representative": n.rep, "link_as_account": n.to},
		})
	}))
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) url() string { return n.srv.URL + "/rpc" }

func (n *fakeNode) reads() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.calls)
}

func withAmount(a string) nodeOpt { return func(n *fakeNode) { n.amount = a } }
func withKnown(h string) nodeOpt  { return func(n *fakeNode) { n.known = h } }
func withRepFor(order, amount string) nodeOpt {
	return func(n *fakeNode) { n.rep = OrderRepresentative(order, nPayTo, amount) }
}

func nProof(payload map[string]any) map[string]any {
	p := map[string]any{"blockHash": nHash, "orderId": nOrder}
	for k, v := range payload {
		if v == nil {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return map[string]any{"network": "nano", "payload": p}
}

func settleWith(n *fakeNode, p map[string]any, claims NanoClaims, now int64) Settlement {
	if claims == nil {
		claims = NewMemoryClaims()
	}
	return SettleNano(t0ctx(), n.srv.Client(), p, Expected{Amount: nAmount, PayTo: nPayTo}, n.url(), claims, now)
}

func TestNanoBlake2b(t *testing.T) {
	// Digests from Python's hashlib.blake2b, across one, two and three blocks.
	cases := []struct {
		msg  []byte
		want string
	}{
		{nil, "7d64c5272e"},
		{[]byte("abc"), "44229fc0ef"},
		{[]byte(strings.Repeat("x", 128)), "b5cf59d107"},
		{[]byte(strings.Repeat("y", 129)), "5040a225e8"},
		{[]byte(strings.Repeat("z", 256)), "8f4382f608"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(blake2b(c.msg, 5)); got != c.want {
			t.Errorf("blake2b-40(%d bytes) = %s want %s", len(c.msg), got, c.want)
		}
	}
	seq := make([]byte, 200)
	for i := range seq {
		seq[i] = byte(i)
	}
	if got := hex.EncodeToString(blake2b(seq, 64))[:32]; got != "fb3c1f0f56a56f8e316fdf5d853c8c87" {
		t.Errorf("blake2b-512 prefix %s", got)
	}
	if got := hex.EncodeToString(blake2b([]byte("abc"), 64))[:32]; got != "ba80a53f981c4d0d6a2797b69f12f6e9" {
		t.Errorf("blake2b-512(abc) prefix %s (RFC 7693 appendix A)", got)
	}
}

func TestNanoAccounts(t *testing.T) {
	burn, _ := AccountFromKey(make([]byte, 32))
	if burn != nBurn {
		t.Fatalf("burn %s", burn)
	}
	if hex.EncodeToString(AccountKey(nBurn)) != strings.Repeat("00", 32) {
		t.Error("burn key")
	}
	key := AccountKey(nPayTo)
	if key == nil {
		t.Fatal("pay-to key")
	}
	if a, _ := AccountFromKey(key); a != nPayTo {
		t.Errorf("round trip %s", a)
	}
	if CanonicalAccount("xrb_"+nPayTo[5:]) != nPayTo || CanonicalAccount(strings.ToUpper(nPayTo)) != nPayTo {
		t.Error("xrb_ and upper case spellings")
	}
	if a, _ := AccountFromKey([]byte(strings.Repeat("\x01", 32))); a != nPayer {
		t.Errorf("payer %s", a)
	}
	if _, err := AccountFromKey(make([]byte, 31)); err == nil {
		t.Error("31 bytes is not an account")
	}
	c := "5"
	if nPayTo[10] == '5' {
		c = "6"
	}
	last := "3"
	if strings.HasSuffix(nPayTo, "3") {
		last = "4"
	}
	for _, bad := range []string{nPayTo[:10] + c + nPayTo[11:], nPayTo[:len(nPayTo)-1] + last, "nano_123", ""} {
		if AccountKey(bad) != nil || CanonicalAccount(bad) != "" {
			t.Errorf("accepted %q", bad)
		}
	}
	if NanoPayee(nEVM) != "" {
		t.Error("an EVM address is not a Nano payee")
	}
}

func TestNanoOrderBinding(t *testing.T) {
	amount := "50000000000000000000000000000"
	if amount != nAmount {
		t.Fatalf("0.05 XNO is %s raw", nAmount)
	}
	if got := hex.EncodeToString(OrderCommitment("order-0001", nBurn, amount)); got != "86e75a339b908cc926a478c1a0e5eb5dd6fc612c1d3251eb661faa78135c36cf" {
		t.Errorf("commitment %s", got)
	}
	if got := OrderRepresentative("order-0001", nBurn, amount); got != "nano_33q9dassq66es6mcay83n5kypqgpzjikr9bkc9ope9xch1borfphgehj4ozj" {
		t.Errorf("representative %s", got)
	}
	base := OrderRepresentative(nOrder, nPayTo, nAmount)
	for _, other := range []string{
		OrderRepresentative(nOrder+"x", nPayTo, nAmount),
		OrderRepresentative(nOrder, nBurn, nAmount),
		OrderRepresentative(nOrder, nPayTo, nAmount+"0"),
	} {
		if other == base {
			t.Error("the representative must change with the order, the payee and the amount")
		}
	}
	a := NewOrderID()
	if !IsOrderID(a) || len(a) != 22 || a == NewOrderID() {
		t.Errorf("order id %q", a)
	}
	for _, bad := range []string{"order-0001", nOrder + " ", nOrder + "\n", ""} {
		if IsOrderID(bad) {
			t.Errorf("accepted order id %q", bad)
		}
	}
}

func TestNanoNodeURL(t *testing.T) {
	cases := map[string]string{
		"https://node.example/rpc": "https://node.example/rpc",
		"http://127.0.0.1:7076":    "http://127.0.0.1:7076/",
		"http://localhost:7076":    "http://localhost:7076/",
		"http://[::1]:7076":        "http://[::1]:7076/",
		"http://node.example/rpc":  "",
		"ftp://node.example":       "",
		"":                         "",
		"https://node.example:x/":  "",
	}
	for in, want := range cases {
		if got := NodeURL(in); got != want {
			t.Errorf("NodeURL(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNanoSettle(t *testing.T) {
	t.Run("reads block_info from the configured node and accepts a bound confirmed exact send", func(t *testing.T) {
		n := newNode(t)
		r := settleWith(n, nProof(nil), nil, 100)
		if !r.OK || r.Payer != nPayer || r.Ref != nHash {
			t.Fatalf("%+v", r)
		}
		want := map[string]string{"action": "block_info", "json_block": "true", "hash": nHash}
		for k, v := range want {
			if n.calls[0][k] != v {
				t.Errorf("node call %v", n.calls[0])
			}
		}
	})
	t.Run("accepts a lower case block hash as the same block", func(t *testing.T) {
		if r := settleWith(newNode(t), nProof(map[string]any{"blockHash": strings.ToLower(nHash)}), nil, 1); !r.OK {
			t.Fatal(r.Reason)
		}
	})
	t.Run("refuses a block hash without its order id or with another one", func(t *testing.T) {
		n := newNode(t)
		if r := settleWith(n, nProof(map[string]any{"orderId": nil}), nil, 1); !strings.Contains(r.Reason, "orderId") {
			t.Error(r.Reason)
		}
		r := settleWith(n, nProof(map[string]any{"orderId": nOrder + "-other"}), nil, 1)
		if r.OK || !strings.Contains(r.Reason, "not bound to this order") {
			t.Error(r.Reason)
		}
	})
	t.Run("refuses unconfirmed, wrong payee, short, over and non-send blocks", func(t *testing.T) {
		no := false
		cases := []struct {
			opt    nodeOpt
			reason string
		}{
			{func(n *fakeNode) { n.confirmed = "false" }, "not confirmed"},
			{func(n *fakeNode) { n.confirmedBool = &no }, "not confirmed"},
			{func(n *fakeNode) { n.to = nBurn }, "does not pay this gateway"},
			{func(n *fakeNode) { n.amount = add(nAmount, -1); n.rep = OrderRepresentative(nOrder, nPayTo, nAmount) }, "exactly"},
			{func(n *fakeNode) { n.amount = add(nAmount, 1); n.rep = OrderRepresentative(nOrder, nPayTo, nAmount) }, "exactly"},
			{func(n *fakeNode) { n.subtype = "receive" }, "not a send"},
		}
		for _, c := range cases {
			r := settleWith(newNode(t, c.opt), nProof(nil), nil, 1)
			if r.OK || !strings.Contains(r.Reason, c.reason) {
				t.Errorf("want %q, got %+v", c.reason, r)
			}
		}
	})
	t.Run("refuses a block the node does not know and a node that does not answer", func(t *testing.T) {
		n := newNode(t)
		if r := settleWith(n, nProof(map[string]any{"blockHash": strings.Repeat("C", 64)}), nil, 1); !strings.Contains(r.Reason, "does not know this block") {
			t.Error(r.Reason)
		}
		if _, e := readBlock(t0ctx(), nil, nHash, "http://127.0.0.1:1/rpc"); !strings.Contains(e, "did not answer") {
			t.Error(e)
		}
		big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat("x", 70000)))
		}))
		defer big.Close()
		if _, e := readBlock(t0ctx(), nil, nHash, big.URL); !strings.Contains(e, "too large") {
			t.Error(e)
		}
		html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html>"))
		}))
		defer html.Close()
		if _, e := readBlock(t0ctx(), nil, nHash, html.URL); !strings.Contains(e, "not JSON") {
			t.Error(e)
		}
	})
	t.Run("credits a block once; the same order again is a replay; another order is refused", func(t *testing.T) {
		n := newNode(t)
		claims := NewMemoryClaims()
		if r := settleWith(n, nProof(nil), claims, 100); !r.OK {
			t.Fatal(r.Reason)
		}
		again := settleWith(n, nProof(nil), claims, 200)
		if again.OK || !again.Replay || again.ClaimedAt != 100 {
			t.Fatalf("%+v", again)
		}
		// The same order id on a second block is a second payment for one order: refused, not credited.
		if c := claims.Claim(strings.Repeat("D", 64), nOrder, 300); c.Status != "taken" {
			t.Errorf("%+v", c)
		}
	})
	t.Run("refuses a malformed hash before reading the node", func(t *testing.T) {
		n := newNode(t)
		if r := settleWith(n, nProof(map[string]any{"blockHash": "xyz"}), nil, 1); !strings.Contains(r.Reason, "blockHash") {
			t.Error(r.Reason)
		}
		if n.reads() != 0 {
			t.Error("the node was read")
		}
	})
	t.Run("holds the proof to the offer, not to itself", func(t *testing.T) {
		n := newNode(t)
		for _, e := range []Expected{{Amount: "0", PayTo: nPayTo}, {Amount: nAmount, PayTo: nPayTo[:len(nPayTo)-1] + "1"}} {
			r := SettleNano(t0ctx(), nil, nProof(nil), e, n.url(), NewMemoryClaims(), 1)
			if !strings.Contains(r.Reason, "No Nano offer") {
				t.Error(r.Reason)
			}
		}
		if n.reads() != 0 {
			t.Error("the node was read")
		}
	})
}

func TestNanoFileClaims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claims.log")
	t.Run("keeps a claim across a restart", func(t *testing.T) {
		n := newNode(t)
		first, err := NewFileClaims(path)
		if err != nil {
			t.Fatal(err)
		}
		if r := settleWith(n, nProof(nil), first, 100); !r.OK {
			t.Fatal(r.Reason)
		}
		// A new process: a new store over the same file.
		second, _ := NewFileClaims(path)
		after := settleWith(n, nProof(nil), second, 500)
		if after.OK || !after.Replay || after.ClaimedAt != 100 {
			t.Fatalf("%+v", after)
		}
		text, _ := os.ReadFile(path)
		if !strings.Contains(string(text), nHash+" "+nOrder+" 100") {
			t.Errorf("file %q", text)
		}
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	})
	t.Run("holds each hash and each order id once", func(t *testing.T) {
		c, _ := NewFileClaims(filepath.Join(t.TempDir(), "c.log"))
		for i, want := range []struct{ hash, order, status string }{
			{nHash, nOrder, "new"}, {nHash, nOrder, "same"}, {nHash, nOrder + "-b", "taken"}, {strings.Repeat("E", 64), nOrder, "taken"},
		} {
			if got := c.Claim(want.hash, want.order, int64(i+1)).Status; got != want.status {
				t.Errorf("%d: %s want %s", i, got, want.status)
			}
		}
		if c.Len() != 1 {
			t.Errorf("len %d", c.Len())
		}
	})
	t.Run("skips a torn last line and still appends cleanly after it", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "torn.log")
		c, _ := NewFileClaims(p)
		c.Claim(nHash, nOrder, 1)
		f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.WriteString("FFFF partial")
		_ = f.Close()
		c2, _ := NewFileClaims(p)
		if c2.Len() != 1 {
			t.Fatalf("len %d", c2.Len())
		}
		if s := c2.Claim(strings.Repeat("F", 64), nOrder+"-c", 2).Status; s != "new" {
			t.Fatal(s)
		}
		c3, _ := NewFileClaims(p)
		if c3.Len() != 2 {
			t.Errorf("len %d", c3.Len())
		}
	})
	t.Run("starts empty when the file does not exist yet", func(t *testing.T) {
		c, err := NewFileClaims(filepath.Join(t.TempDir(), "none.log"))
		if err != nil || c.Len() != 0 {
			t.Fatal(err)
		}
		if _, err := NewFileClaims(""); err == nil || !strings.Contains(err.Error(), "needs a path") {
			t.Error(err)
		}
	})
}

// ------------------------------------------------------------ the gateway --

func nGateway(t *testing.T, n *fakeNode, nano *NanoOptions, onSale func(Sale), now int64) *Gateway {
	g, err := New(Options{
		SiteURL: nSite, CoinPayAPIKey: "cp_live_test", CoinPayBaseURL: n.srv.URL, PayTo: nEVM, Nano: nano,
		OnSale: onSale, HTTPClient: n.srv.Client(), Now: func() int64 { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func nOptions(n *fakeNode, claims NanoClaims) *NanoOptions {
	return &NanoOptions{PayTo: nPayTo, Rate: 0.8, RPCURL: n.url(), Claims: claims}
}

func nOffer(t *testing.T, g *Gateway, path string) Receipt {
	r := httptest.NewRequest(http.MethodGet, nSite+path, nil)
	r.Header.Set("accept", "application/json")
	r.Header.Set("user-agent", "GPTBot/1.0")
	a := g.Handle(r)
	var body Receipt
	if err := json.Unmarshal(a.Body, &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func nB64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(raw)
}

func nGatewayProof(order, amount string) string {
	return nB64(map[string]any{
		"x402Version": 2,
		"accepted":    map[string]any{"scheme": "exact", "network": "nano", "amount": amount, "asset": "XNO", "payTo": nPayTo},
		"payload":     map[string]any{"blockHash": nBlock, "orderId": order},
	})
}

func nBuy(t *testing.T, g *Gateway, proof string) (int, map[string]any) {
	r := httptest.NewRequest(http.MethodGet, nSite+"/crawl", nil)
	r.Header.Set("x-payment", proof)
	a := g.Handle(r)
	var body map[string]any
	_ = json.Unmarshal(a.Body, &body)
	return a.Status, body
}

func wire(t *testing.T, amount string) *fakeNode {
	return newNode(t, withAmount(amount), withKnown(nBlock), withRepFor(nGOrder, amount))
}

func TestNanoGatewayOptIn(t *testing.T) {
	t.Run("lists a nano entry in raw after the USDC ones", func(t *testing.T) {
		n := wire(t, nRawAt080)
		body := nOffer(t, nGateway(t, n, nOptions(n, NewMemoryClaims()), nil, 1_000_000), "/crawl")
		if len(body.Accepts) != len(Methods)+1 {
			t.Fatalf("%d entries", len(body.Accepts))
		}
		for i, m := range Methods {
			if body.Accepts[i].Network != m.Network {
				t.Errorf("entry %d is %s", i, body.Accepts[i].Network)
			}
		}
		x := body.Accepts[3]
		if x.Network != "nano" || x.Amount != nRawAt080 || x.PayTo != nPayTo || x.Asset != "XNO" || x.Scheme != "exact" {
			t.Errorf("%+v", x)
		}
		// The USDC entries are the ones a gateway without a Nano payee offers.
		plain := nOffer(t, nGateway(t, n, nil, nil, 1_000_000), "/crawl")
		a, _ := json.Marshal(body.Accepts[:3])
		b, _ := json.Marshal(plain.Accepts)
		if string(a) != string(b) {
			t.Errorf("USDC entries changed:\n%s\n%s", a, b)
		}
	})
	t.Run("offers the binding and an order id", func(t *testing.T) {
		n := wire(t, nRawAt080)
		x := nOffer(t, nGateway(t, n, nOptions(n, NewMemoryClaims()), nil, 1), "/crawl").Accepts[3]
		if x.Extra.Binding != NanoBinding || x.Extra.Decimals != 30 || !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(x.Extra.OrderID) || x.Extra.Name != "" {
			t.Errorf("%+v", x.Extra)
		}
	})
	t.Run("offers nothing new without a valid nano payee", func(t *testing.T) {
		plain, _ := BuildOffer(OfferOptions{PayTo: nEVM, PriceCents: 100, Resource: "r"})
		for _, ne := range []*NanoEntry{nil, {PayTo: nEVM, Amount: "1"}, {PayTo: nPayTo, Amount: "0"}} {
			o, _ := BuildOffer(OfferOptions{PayTo: nEVM, PriceCents: 100, Resource: "r", Nano: ne})
			a, _ := json.Marshal(o)
			b, _ := json.Marshal(plain)
			if string(a) != string(b) {
				t.Errorf("%+v changed the offer", ne)
			}
		}
		n := wire(t, nRawAt080)
		for _, opts := range []*NanoOptions{nil, {PayTo: ""}, {PayTo: nEVM, Rate: 0.8},
			{PayTo: nPayTo, Rate: 0, RPCURL: n.url(), Claims: NewMemoryClaims()},
			{PayTo: nPayTo, RateFunc: func() (float64, error) { return 0, errors.New("feed down") }, RPCURL: n.url(), Claims: NewMemoryClaims()},
			{PayTo: nPayTo, RateFunc: func() (float64, error) { panic("feed down") }, RPCURL: n.url(), Claims: NewMemoryClaims()},
		} {
			if got := len(nOffer(t, nGateway(t, n, opts, nil, 1), "/crawl").Accepts); got != 3 {
				t.Errorf("%+v: %d entries", opts, got)
			}
		}
	})
	t.Run("normalises a legacy xrb_ payee to nano_", func(t *testing.T) {
		if NanoPayee("xrb_"+nPayTo[5:]) != nPayTo || NanoPayee(strings.ToUpper(nPayTo)) != nPayTo || NanoPayee("nano_123") != "" {
			t.Error("payee spellings")
		}
		o, _ := BuildOffer(OfferOptions{PayTo: nEVM, PriceCents: 100, Resource: "r", Nano: &NanoEntry{PayTo: "xrb_" + nPayTo[5:], Amount: nRawAt080}})
		if o.Accepts[3].PayTo != nPayTo {
			t.Error(o.Accepts[3].PayTo)
		}
		extra, _ := json.Marshal(o.Accepts[3].Extra)
		if string(extra) != `{"decimals":30}` {
			t.Errorf("extra %s", extra)
		}
	})
	t.Run("prices in raw with integers, rounding up", func(t *testing.T) {
		if XNORaw(100, 0.8) != nRawAt080 || XNORaw(100, 0.7) != "1428571428571428571428571428572" || XNORaw(100, 1) != RawPerXNO.String() {
			t.Error(XNORaw(100, 0.8), XNORaw(100, 0.7), XNORaw(100, 1))
		}
		zero := 0.0
		if XNORaw(100, 0) != "" || XNORaw(100, zero/zero) != "" || XNORaw(0, 1) != "" {
			t.Error("a non-positive price or rate must price nothing")
		}
	})
	t.Run("settles a bound block with the node, not CoinPay, and credits it once", func(t *testing.T) {
		n := wire(t, nRawAt080)
		var sales []Sale
		g := nGateway(t, n, nOptions(n, NewMemoryClaims()), func(s Sale) { sales = append(sales, s) }, 1_000_000)
		status, body := nBuy(t, g, nGatewayProof(nGOrder, nRawAt080))
		if status != 200 || body["replayed"] != false {
			t.Fatalf("%d %v", status, body)
		}
		if n.calls[0]["hash"] != nBlock || len(n.coinpay) != 0 || len(sales) != 1 || sales[0].Ref != nBlock {
			t.Errorf("calls %v coinpay %v sales %+v", n.calls, n.coinpay, sales)
		}
		// Lost the answer, asked again with the same block and order: a pass, no second sale.
		status, again := nBuy(t, g, nGatewayProof(nGOrder, nRawAt080))
		if status != 200 || again["replayed"] != true || again["expires_at"] != body["expires_at"] || len(sales) != 1 {
			t.Errorf("%d %v sales %d", status, again, len(sales))
		}
	})
	t.Run("a restarted gateway does not credit the block again", func(t *testing.T) {
		n := wire(t, nRawAt080)
		path := filepath.Join(t.TempDir(), "claims.log")
		sales := 0
		c1, _ := NewFileClaims(path)
		first := nGateway(t, n, nOptions(n, c1), func(Sale) { sales++ }, 1_000_000)
		if s, b := nBuy(t, first, nGatewayProof(nGOrder, nRawAt080)); s != 200 {
			t.Fatalf("%d %v", s, b)
		}
		// A new process over the same claims file, two days later: the first pass has ended.
		c2, _ := NewFileClaims(path)
		later := nGateway(t, n, nOptions(n, c2), func(Sale) { sales++ }, 1_000_000+2*86400)
		s, b := nBuy(t, later, nGatewayProof(nGOrder, nRawAt080))
		if s != 402 || !strings.Contains(str(b["error"]), "already used") || sales != 1 {
			t.Errorf("%d %v sales %d", s, b, sales)
		}
	})
	t.Run("refuses the same block hash with an order id it was not signed for", func(t *testing.T) {
		n := wire(t, nRawAt080)
		s, b := nBuy(t, nGateway(t, n, nOptions(n, NewMemoryClaims()), nil, 1), nGatewayProof("c29tZW9uZS1lbHNlcy1vcmRlcg", nRawAt080))
		if s != 402 || !strings.Contains(str(b["error"]), "not bound to this order") {
			t.Errorf("%d %v", s, b)
		}
	})
	t.Run("buys n days with n times one day in raw", func(t *testing.T) {
		one, _ := new(big.Int).SetString(XNORaw(100, 0.7), 10)
		three := new(big.Int).Mul(one, big.NewInt(3)).String()
		n := wire(t, three)
		opts := nOptions(n, NewMemoryClaims())
		opts.RateFunc = func() (float64, error) { return 0.7, nil }
		g := nGateway(t, n, opts, nil, 1_000_000)
		if got := nOffer(t, g, "/crawl?days=3").Accepts[3].Amount; got != three {
			t.Errorf("offered %s want %s", got, three)
		}
		s, b := nBuy(t, g, nGatewayProof(nGOrder, three))
		if s != 200 || b["days"] != float64(3) {
			t.Errorf("%d %v", s, b)
		}
	})
	t.Run("a rate that fails mid-sale never sells n days for one", func(t *testing.T) {
		one := XNORaw(100, 0.8)
		reads := 0
		// The block pays one day; the proof claims three.
		n := wire(t, one)
		opts := nOptions(n, NewMemoryClaims())
		opts.RateFunc = func() (float64, error) {
			reads++
			if reads > 1 {
				return 0, errors.New("price feed down")
			}
			return 0.8, nil
		}
		g := nGateway(t, n, opts, nil, 1_000_000)
		s, b := nBuy(t, g, nGatewayProof(nGOrder, mul(one, 3)))
		if s != 402 || !strings.Contains(str(b["error"]), "exactly") {
			t.Errorf("%d %v", s, b)
		}
	})
	t.Run("will not read a node without a claims store or over plain http off localhost", func(t *testing.T) {
		cases := []struct {
			opts *NanoOptions
			want string
		}{
			{&NanoOptions{PayTo: nPayTo, Rate: 0.8, RPCURL: "https://node.test/rpc"}, "Claims"},
			{&NanoOptions{PayTo: nPayTo, Rate: 0.8, RPCURL: "http://node.test", Claims: NewMemoryClaims()}, "https"},
			{&NanoOptions{PayTo: nPayTo, Rate: 0.8}, "RPCURL"},
		}
		for _, c := range cases {
			if _, err := New(Options{SiteURL: nSite, CoinPayAPIKey: "cp_live_test", PayTo: nEVM, Nano: c.opts}); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%+v: %v", c.opts, err)
			}
		}
	})
	t.Run("a nano proof without nano switched on matches no offered network", func(t *testing.T) {
		n := wire(t, nRawAt080)
		s, b := nBuy(t, nGateway(t, n, nil, nil, 1), nGatewayProof(nGOrder, nRawAt080))
		if s != 402 || !strings.Contains(str(b["error"]), "offered network") || n.reads() != 0 {
			t.Errorf("%d %v reads %d", s, b, n.reads())
		}
	})
	t.Run("leaves the EVM proof path as it was", func(t *testing.T) {
		evm := DecodePayment(nB64(map[string]any{"x402Version": 2, "network": "eip155:8453", "payload": map[string]any{"authorization": map[string]any{"nonce": "0xabc", "validBefore": "9999999999", "value": "1000000"}}}))
		if get(evm, "x402Version") != float64(2) || NonceOf(evm) != "0xabc" || ValidBeforeOf(evm) != 9999999999 || PaidValueOf(evm).String() != "1000000" {
			t.Errorf("%v", evm)
		}
		if _, lifted := get(evm, "payload").(map[string]any)["network"]; lifted {
			t.Error("an EVM payload was rewritten")
		}
		nano := DecodePayment(nB64(map[string]any{"network": "nano", "payload": map[string]any{"blockHash": nBlock}}))
		if ValidBeforeOf(nano) != 0 || NonceOf(nano) != nBlock {
			t.Errorf("%v", nano)
		}
	})
}

func t0ctx() context.Context { return context.Background() }

func add(raw string, d int64) string {
	v, _ := new(big.Int).SetString(raw, 10)
	return v.Add(v, big.NewInt(d)).String()
}

func mul(raw string, k int64) string {
	v, _ := new(big.Int).SetString(raw, 10)
	return v.Mul(v, big.NewInt(k)).String()
}
