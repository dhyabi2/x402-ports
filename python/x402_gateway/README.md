# profullstack-x402-gateway

Sell crawl access to AI training crawlers, by the day, over [x402](https://x402.org), settled by [CoinPay](https://coinpayportal.com). A Python port of [@profullstack/x402-gateway](https://github.com/profullstack/x402-gateway): same 402 body, same signed passes, same robots.txt, checked against the same fixtures.

People read your site free. So do search engines and the retrieval crawlers behind AI answers. A crawler that copies pages into a training corpus pays: every page answers `402 Payment Required` with an x402 offer, paying the offer returns a signed pass, and the pass opens the site for a day.

Zero dependencies. Python 3.9+. ASGI and WSGI.

```
pip install profullstack-x402-gateway
```

## FastAPI / Starlette

```python
import os
from x402_gateway import Gateway
from x402_gateway.asgi import X402Middleware

gateway = Gateway(
    "https://your-site.com",
    coinpay_api_key=os.environ["COINPAY_X402_KEY"],   # a SCOPED CoinPay key (cp_live_…)
    pay_to=os.environ["CRAWL_PAY_TO"],                # EVM address that receives the USDC
)
app.add_middleware(X402Middleware, gateway=gateway)

@app.get("/robots.txt")
def robots():
    return PlainTextResponse(gateway.robots_txt(disallow=["/login", "/api/"]))
```

## Flask / Django (WSGI)

```python
from x402_gateway.wsgi import X402Middleware
app.wsgi_app = X402Middleware(app.wsgi_app, gateway)           # Flask
application = X402Middleware(get_wsgi_application(), gateway)  # Django wsgi.py
```

Django on ASGI: wrap `get_asgi_application()` with `x402_gateway.asgi.X402Middleware` the same way.

## Anything else

`gateway.handle(Request(url, headers))` returns a `Response(status, headers, body)` to send, or `None` to carry on. Headers are a dict of lower-cased names.

## Options

| Option | Default | |
| --- | --- | --- |
| `site_url` | required | canonical origin, no trailing slash |
| `coinpay_api_key` | | scoped CoinPay key with `payments:create`. The legacy business key is refused by CoinPay's x402 routes. |
| `pay_to` | | EVM address that receives the USDC, on Base, Polygon and Ethereum alike |
| `price_cents` | `100` | |
| `pass_minutes` | `1440` | a day: the term one payment buys |
| `max_days` | `30` | the most terms one proof may buy at once (`?days=N` on the sales page quotes N) |
| `header` | `x-crawl-pass` | where the pass goes; `Authorization: Bearer` works too |
| `path` | `/crawl` | the sales page, answered for every user agent |
| `open_paths` | `[]` | extra paths a refused crawler may read (`robots.txt`, the sales page, `security.txt` and `.well-known/` always are) |
| `is_paid_agent` | training list | `(user_agent) -> bool` |
| `deny_cidrs` | `[]` | IPv4 ranges answered with a tiny `403` before anything else |
| `charge_spoofed_browsers` | `False` | charge a request that claims `Chrome/…` but sends no `Sec-Fetch-Mode` |
| `exempt` | | `(request) -> bool`, never charged: e.g. a request carrying your signed-in cookie |
| `secret` | the CoinPay key | pass signing secret |
| `page` | built in | `(ctx) -> html` |
| `contact` | | mailto: or URL for bulk deals |
| `on_sale` | | `(sale) -> None`, for accounting |
| `nano` | off | `{"pay_to": "nano_…", "rate": …, "rpc_url": …, "claims": …}`: also offer XNO on network `nano`, checked on your own Nano node. See below |

Without `coinpay_api_key` and `pay_to` the gateway still answers training crawlers with 402 and the page says payments are off.

## XNO checked by your own node (opt-in)

The reference's `nano` option, in its own-node form. With it set, the offer gets one more entry, last: `scheme: "exact"`, `network: "nano"`, `asset: "XNO"`, the amount in raw (10^30 per XNO, rounded up from `price_cents` at `rate`, the price of 1 XNO in `currency`, a number or a callable read per offer). Without it the offer and every other path are exactly as before.

```python
from x402_gateway import Gateway, FileClaims

gateway = Gateway(
    "https://your-site.com",
    coinpay_api_key=os.environ["COINPAY_X402_KEY"],
    pay_to=os.environ["CRAWL_PAY_TO"],
    nano={
        "pay_to": "nano_…",
        "rate": 0.8,
        "rpc_url": "https://your-node.example/rpc",   # https, or http on localhost
        "claims": FileClaims("/var/lib/x402-gateway/nano-claims.log"),
    },
)
```

- **Bound to the order** ([xno-binding v1](https://github.com/dhyabi2/xno-call-binding/blob/main/docs/BINDING-STANDARD.md), option C). The entry's `extra` carries `binding: "xno-binding/v1/rep"` and a random `orderId`. The payer signs its send with `representative` set to the account encoding of `SHA-256("xno-binding/v1/rep|" + orderId + "|" + payTo + "|" + amountRaw)` (`order_representative()` computes it), and presents `payload.orderId` with `payload.blockHash`. A block hash without the order id it was signed for is refused.
- **Exact.** The gateway reads the block with `block_info` (no key, no seed) and requires a confirmed send to `pay_to` of exactly the offered raw amount for the days paid. CoinPay is not asked about Nano proofs.
- **Once, across restarts.** Each block hash and each order id is credited once; `FileClaims` appends and fsyncs every claim and reads the file back on start (one process per file). The same block with the same order id again gets back a pass that ends where the first one did.
- The payee's checksum is checked, and an `xrb_` payee is written as `nano_`. A `nano` setting without `rpc_url` and `claims` is refused at start: this port does not take the CoinPay-only form.

## Test

```
python -m unittest discover -s tests
```

The fixtures are `spec/vectors.json` at the repo root, generated from the JavaScript reference.
