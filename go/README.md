# x402gateway for Go

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Go port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures. Standard library only.

```
go get github.com/profullstack/x402-ports/go/x402gateway
```

## net/http (also chi, gorilla, echo's WrapMiddleware, gin's WrapH)

```go
gw, err := x402gateway.New(x402gateway.Options{
    SiteURL:       "https://your-site.com",
    CoinPayAPIKey: os.Getenv("COINPAY_X402_KEY"), // a SCOPED CoinPay key (cp_live_…)
    PayTo:         os.Getenv("CRAWL_PAY_TO"),     // EVM address that receives the USDC
})
mux := http.NewServeMux()
mux.Handle("/robots.txt", gw.RobotsHandler(x402gateway.RobotsOptions{Disallow: []string{"/login", "/api/"}}))
mux.Handle("/", site)
http.ListenAndServe(":8080", gw.Middleware(mux))
```

## Anything else

`gw.Handle(r *http.Request)` returns an `*Answer` (status, headers, body) to send, or nil to carry on. `answer.Write(w)` sends it.

## Options

Same names as the reference, in Go casing: `PriceCents` (100), `PassMinutes` (1440), `MaxDays` (30), `Header` (`x-crawl-pass`), `Path` (`/crawl`), `OpenPaths`, `IsPaidAgent`, `DenyCIDRs`, `ChargeSpoofedBrowsers`, `Exempt func(*http.Request) bool`, `Secret`, `Page`, `Contact`, `OnSale`, `HTTPClient`, `Nano` (off; see below). Without `CoinPayAPIKey` and `PayTo` the gateway still answers training crawlers with 402 and the page says payments are off.

## XNO checked by your own node (opt-in)

The reference's `nano` option in its own-node form, as the Python port has it. With `Nano` set, the offer gets one more entry, last: `scheme: "exact"`, `network: "nano"`, `asset: "XNO"`, the amount in raw (10^30 per XNO, rounded up from `PriceCents` at `Rate`, the price of 1 XNO in `Currency`; or `RateFunc`, read per offer). Without it the offer and every other path are exactly as before.

```go
claims, err := x402gateway.NewFileClaims("/var/lib/x402-gateway/nano-claims.log")
if err != nil {
	log.Fatal(err)
}
gw, err := x402gateway.New(x402gateway.Options{
	SiteURL:       "https://your-site.com",
	CoinPayAPIKey: os.Getenv("COINPAY_X402_KEY"),
	PayTo:         os.Getenv("CRAWL_PAY_TO"),
	Nano: &x402gateway.NanoOptions{
		PayTo:  "nano_…",
		Rate:   0.8,
		RPCURL: "https://your-node.example/rpc", // https, or http on localhost
		Claims: claims,
	},
})
```

- **Bound to the order** ([xno-binding v1](https://github.com/dhyabi2/xno-call-binding/blob/main/docs/BINDING-STANDARD.md), option C). The entry's `extra` carries `binding: "xno-binding/v1/rep"` and a random `orderId`. The payer signs its send with `representative` set to the account encoding of `SHA-256("xno-binding/v1/rep|" + orderId + "|" + payTo + "|" + amountRaw)` (`OrderRepresentative()` computes it), and presents `payload.orderId` with `payload.blockHash`. A block hash without the order id it was signed for is refused.
- **Exact.** The gateway reads the block with `block_info` (no key, no seed) and requires a confirmed send to `PayTo` of exactly the offered raw amount for the days paid. CoinPay is not asked about Nano proofs.
- **Once, across restarts.** Each block hash and each order id is credited once; `FileClaims` appends and fsyncs every claim and reads the file back on start (one process per file). The same block with the same order id again gets back a pass that ends where the first one did. Any `NanoClaims` backed by a table with both columns UNIQUE works too.
- The payee's checksum is checked, and an `xrb_` payee is written as `nano_`. `Nano` without `RPCURL` and `Claims` is refused by `New`. Standard library only: the address checksum uses a small BLAKE2b in `nano.go`.

## coinpay launcher

```
go install github.com/profullstack/x402-ports/go/cmd/coinpay@latest
coinpay x402 pay https://rssamplifier.com/crawl --output pass.json
```

Runs the CoinPay CLI (`@profullstack/coinpay` on npm) through an installed `coinpay`, `npx`, `bunx`, `pnpm dlx` or `deno`. Node.js 20+, Bun or Deno is required.

## Test

```
go test ./...
```
