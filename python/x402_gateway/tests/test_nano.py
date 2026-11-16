"""XNO on Nano, checked by the operator's own node: the cases of the JS reference's test/nano.test.js
and the "XNO on Nano, opt-in" block of test/gateway.test.js, with the same constants."""

import base64
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from x402_gateway import METHODS, Gateway, Request, build_offer, decode_payment  # noqa: E402
from x402_gateway.core import nonce_of, valid_before_of  # noqa: E402
from x402_gateway.nano import (  # noqa: E402
    BINDING,
    RAW_PER_XNO,
    FileClaims,
    MemoryClaims,
    account_from_key,
    account_key,
    canonical_account,
    is_order_id,
    nano_payee,
    new_order_id,
    node_url,
    order_commitment,
    order_representative,
    read_block,
    settle_nano,
    xno_raw,
)

# The all-zero key: the burn account, which every Nano tool prints the same way.
BURN = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
PAY_TO = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
# The key 0x01 * 32, so the payer is an account nobody is.
PAYER = "nano_11a3161i41a3161i41a3161i41a3161i41a3161i41a3161i41a3bqbhquyj"
AMOUNT = str(5 * RAW_PER_XNO // 100)  # 0.05 XNO, derived, not typed
ORDER = "Qm9yZGVyLWlkLWZvci10ZXN0cw"
HASH = "B" * 64
NODE = "https://node.test/rpc"


def node_with(amount=AMOUNT, confirmed="true", subtype="send", to=PAY_TO, representative=None, order=ORDER, pay_to=PAY_TO, known=HASH):
    """A node that knows one block, and counts the reads. Anything not sent to NODE is a CoinPay call."""
    rep = representative or order_representative(order, pay_to, amount)
    calls, coinpay = [], []

    def post(url, headers, body):
        if not url.startswith(NODE):
            coinpay.append(url)
            return 500, "{}"
        req = json.loads(body)
        calls.append(req)
        if req["hash"] != known:
            return 200, json.dumps({"error": "Block not found"})
        return 200, json.dumps(
            {
                "block_account": PAYER,
                "amount": amount,
                "confirmed": confirmed,
                "subtype": subtype,
                "contents": {"type": "state", "account": PAYER, "representative": rep, "link_as_account": to},
            }
        )

    post.calls = calls
    post.coinpay = coinpay
    return post


def proof(**extra):
    payload = {"blockHash": HASH, "orderId": ORDER}
    payload.update(extra)
    return {"network": "nano", "payload": {k: v for k, v in payload.items() if v is not None}}


EXPECTED = {"amount": AMOUNT, "payTo": PAY_TO}


def settle(p, post, claims=None, now=100):
    return settle_nano(p, EXPECTED, NODE, claims if claims is not None else MemoryClaims(), post, lambda: now)


class Blake2b(unittest.TestCase):
    """hashlib.blake2b is the standard library's; the checksum relies on its 5-byte digest."""

    def test_five_byte_digest_of_the_zero_key(self):
        # The burn account's last 8 characters are this checksum.
        self.assertEqual(account_from_key(bytes(32))[-8:], "hifc8npp")


class NanoAccounts(unittest.TestCase):
    def test_encodes_the_all_zero_key_as_the_burn_account(self):
        self.assertEqual(account_from_key(bytes(32)), BURN)
        self.assertEqual(account_key(BURN).hex(), "00" * 32)

    def test_round_trips_a_real_account_and_its_xrb_spelling(self):
        key = account_key(PAY_TO)
        self.assertIsNotNone(key)
        self.assertEqual(account_from_key(key), PAY_TO)
        self.assertEqual(canonical_account("xrb_" + PAY_TO[5:]), PAY_TO)
        self.assertEqual(canonical_account(PAY_TO.upper()), PAY_TO)
        self.assertEqual(account_from_key(b"\x01" * 32), PAYER)

    def test_refuses_an_address_whose_checksum_does_not_match(self):
        typo = PAY_TO[:10] + ("6" if PAY_TO[10] == "5" else "5") + PAY_TO[11:]
        self.assertIsNone(account_key(typo))
        self.assertIsNone(canonical_account(PAY_TO[:-1] + ("4" if PAY_TO.endswith("3") else "3")))
        self.assertIsNone(canonical_account("nano_123"))
        self.assertIsNone(canonical_account(""))
        self.assertIsNone(canonical_account(None))


class OrderBinding(unittest.TestCase):
    def test_reproduces_the_published_test_vector(self):
        amount = "50000000000000000000000000000"
        self.assertEqual(amount, str(5 * RAW_PER_XNO // 100))
        self.assertEqual(order_commitment("order-0001", BURN, amount).hex(), "86e75a339b908cc926a478c1a0e5eb5dd6fc612c1d3251eb661faa78135c36cf")
        self.assertEqual(order_representative("order-0001", BURN, amount), "nano_33q9dassq66es6mcay83n5kypqgpzjikr9bkc9ope9xch1borfphgehj4ozj")

    def test_changes_with_the_order_the_payee_and_the_amount(self):
        base = order_representative(ORDER, PAY_TO, AMOUNT)
        self.assertNotEqual(order_representative(ORDER + "x", PAY_TO, AMOUNT), base)
        self.assertNotEqual(order_representative(ORDER, BURN, AMOUNT), base)
        self.assertNotEqual(order_representative(ORDER, PAY_TO, AMOUNT + "0"), base)

    def test_makes_random_order_ids_long_enough_to_be_a_secret_and_refuses_short_ones(self):
        a = new_order_id()
        self.assertTrue(is_order_id(a))
        self.assertEqual(len(a), 22)
        self.assertNotEqual(a, new_order_id())
        self.assertFalse(is_order_id("order-0001"))
        self.assertFalse(is_order_id(ORDER + " "))
        self.assertFalse(is_order_id(ORDER + "\n"))
        self.assertFalse(is_order_id(None))


class NodeUrl(unittest.TestCase):
    def test_takes_https_anywhere_and_http_only_on_loopback(self):
        self.assertEqual(node_url("https://node.example/rpc"), "https://node.example/rpc")
        self.assertEqual(node_url("http://127.0.0.1:7076"), "http://127.0.0.1:7076/")
        self.assertEqual(node_url("http://localhost:7076"), "http://localhost:7076/")
        self.assertEqual(node_url("http://[::1]:7076"), "http://[::1]:7076/")
        self.assertIsNone(node_url("http://node.example/rpc"))
        self.assertIsNone(node_url("ftp://node.example"))
        self.assertIsNone(node_url(""))


class SettleNano(unittest.TestCase):
    def test_reads_block_info_from_the_configured_node_and_accepts_a_bound_confirmed_exact_send(self):
        post = node_with()
        r = settle(proof(), post)
        self.assertEqual(r, {"ok": True, "payer": PAYER, "ref": HASH, "txHash": HASH, "network": "nano"})
        self.assertEqual(post.calls[0], {"action": "block_info", "json_block": "true", "hash": HASH})

    def test_accepts_a_lower_case_block_hash_as_the_same_block(self):
        self.assertTrue(settle(proof(blockHash=HASH.lower()), node_with())["ok"])

    def test_refuses_a_block_hash_presented_without_its_order_id_or_with_another_one(self):
        post = node_with()
        self.assertIn("orderId", settle(proof(orderId=None), post)["reason"])
        other = settle(proof(orderId=ORDER + "-other"), post)
        self.assertFalse(other["ok"])
        self.assertIn("not bound to this order", other["reason"])

    def test_refuses_unconfirmed_wrong_payee_short_over_and_non_send_blocks(self):
        cases = [
            ({"confirmed": "false"}, "not confirmed"),
            ({"confirmed": False}, "not confirmed"),
            ({"to": BURN}, "does not pay this gateway"),
            ({"amount": str(int(AMOUNT) - 1)}, "exactly"),
            ({"amount": str(int(AMOUNT) + 1)}, "exactly"),
            ({"subtype": "receive"}, "not a send"),
        ]
        for over, reason in cases:
            r = settle(proof(), node_with(**over))
            self.assertFalse(r["ok"], over)
            self.assertIn(reason, r["reason"], over)

    def test_refuses_a_block_the_node_does_not_know_and_a_node_that_does_not_answer(self):
        r = settle(proof(blockHash="C" * 64), node_with())
        self.assertIn("does not know this block", r["reason"])

        def down(url, headers, body):
            raise OSError("connection refused")

        self.assertIn("did not answer", read_block(HASH, NODE, down)["error"])
        self.assertIn("too large", read_block(HASH, NODE, lambda u, h, b: (200, "x" * 70000))["error"])
        self.assertIn("not JSON", read_block(HASH, NODE, lambda u, h, b: (200, "<html>"))["error"])

    def test_credits_a_block_once_the_same_order_again_is_a_replay_another_order_is_refused(self):
        post = node_with()
        claims = MemoryClaims()
        self.assertTrue(settle(proof(), post, claims, now=100)["ok"])
        again = settle(proof(), post, claims, now=200)
        self.assertFalse(again["ok"])
        self.assertTrue(again["replay"])
        self.assertEqual(again["claimedAt"], 100)
        # The same order id on a second block is a second payment for one order: refused, not credited.
        self.assertEqual(claims.claim("D" * 64, ORDER, 300), {"status": "taken"})

    def test_refuses_a_malformed_hash_before_reading_the_node(self):
        post = node_with()
        self.assertIn("blockHash", settle(proof(blockHash="xyz"), post)["reason"])
        self.assertEqual(post.calls, [])

    def test_holds_the_proof_to_the_offer_not_to_itself(self):
        # No payee or amount to hold it to: refused before the node is read.
        post = node_with()
        r = settle_nano(proof(), {"amount": "0", "payTo": PAY_TO}, NODE, MemoryClaims(), post, lambda: 1)
        self.assertIn("No Nano offer", r["reason"])
        r = settle_nano(proof(), {"amount": AMOUNT, "payTo": PAY_TO[:-1] + "1"}, NODE, MemoryClaims(), post, lambda: 1)
        self.assertIn("No Nano offer", r["reason"])
        self.assertEqual(post.calls, [])


class FileClaimsTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="nano-claims-")
        self.path = os.path.join(self.dir, "claims.log")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_keeps_a_claim_across_a_restart(self):
        post = node_with()
        self.assertTrue(settle(proof(), post, FileClaims(self.path), now=100)["ok"])
        # A new process: a new store over the same file.
        after = settle(proof(), post, FileClaims(self.path), now=500)
        self.assertFalse(after["ok"])
        self.assertTrue(after["replay"])
        self.assertEqual(after["claimedAt"], 100)
        with open(self.path, encoding="utf-8") as f:
            self.assertIn(f"{HASH} {ORDER} 100", f.read())
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_holds_each_hash_and_each_order_id_once(self):
        claims = FileClaims(self.path)
        self.assertEqual(claims.claim(HASH, ORDER, 1)["status"], "new")
        self.assertEqual(claims.claim(HASH, ORDER, 2)["status"], "same")
        self.assertEqual(claims.claim(HASH, ORDER + "-b", 3)["status"], "taken")
        self.assertEqual(claims.claim("E" * 64, ORDER, 4)["status"], "taken")
        self.assertEqual(len(claims), 1)

    def test_skips_a_torn_last_line_and_still_appends_cleanly_after_it(self):
        FileClaims(self.path).claim(HASH, ORDER, 1)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write("FFFF partial")
        claims = FileClaims(self.path)
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims.claim("F" * 64, ORDER + "-c", 2)["status"], "new")
        self.assertEqual(len(FileClaims(self.path)), 2)

    def test_starts_empty_when_the_file_does_not_exist_yet(self):
        self.assertEqual(len(FileClaims(self.path)), 0)
        with self.assertRaisesRegex(ValueError, "needs a path"):
            FileClaims("")


# ------------------------------------------------------------ the gateway --

SITE = "https://example.test"
EVM = "0x1111111111111111111111111111111111111111"
RAW_AT_080 = "1250000000000000000000000000000"  # 1.00 at 0.80 per XNO: 1.25 XNO
G_ORDER = "b3JkZXItZm9yLWdhdGV3YXk"
BLOCK = "A" * 64


def b64(obj):
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


def gateway(nano=None, post=None, on_sale=None, now=1_000_000):
    return Gateway(SITE, coinpay_api_key="cp_live_test", pay_to=EVM, nano=nano, post=post or node_with(), on_sale=on_sale, now=lambda: now)


def offer_json(g, path="/crawl"):
    res = g.handle(Request(SITE + path, {"accept": "application/json", "user-agent": "GPTBot/1.0"}))
    return json.loads(res.body)


def nano_proof(order=G_ORDER, amount=RAW_AT_080):
    return b64({"x402Version": 2, "accepted": {"scheme": "exact", "network": "nano", "amount": amount, "asset": "XNO", "payTo": PAY_TO}, "payload": {"blockHash": BLOCK, "orderId": order}})


def wire(amount=RAW_AT_080, order=G_ORDER):
    return node_with(amount=amount, order=order, known=BLOCK)


class XnoOptIn(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="nano-gw-")
        self.claims_path = os.path.join(self.dir, "claims.log")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def nano(self, **over):
        n = {"pay_to": PAY_TO, "rate": 0.8, "rpc_url": NODE, "claims": FileClaims(self.claims_path)}
        n.update(over)
        return n

    def test_lists_a_nano_entry_in_raw_after_the_usdc_ones(self):
        body = offer_json(gateway(self.nano()))
        self.assertEqual([a["network"] for a in body["accepts"]], [m["network"] for m in METHODS] + ["nano"])
        xno = body["accepts"][3]
        self.assertEqual(xno["amount"], RAW_AT_080)
        self.assertEqual(xno["payTo"], PAY_TO)
        self.assertEqual(xno["asset"], "XNO")
        self.assertEqual(xno["scheme"], "exact")
        # The USDC entries are the ones a gateway without a Nano payee offers.
        self.assertEqual(body["accepts"][:3], offer_json(gateway())["accepts"])

    def test_offers_the_binding_and_an_order_id(self):
        xno = offer_json(gateway(self.nano()))["accepts"][3]
        self.assertEqual(xno["extra"]["binding"], BINDING)
        self.assertEqual(xno["extra"]["decimals"], 30)
        self.assertRegex(xno["extra"]["orderId"], r"^[A-Za-z0-9_-]{22}$")

    def test_offers_nothing_new_without_a_valid_nano_payee(self):
        plain = build_offer(EVM, 100, "r")
        self.assertEqual(build_offer(EVM, 100, "r", nano=None), plain)
        self.assertEqual(build_offer(EVM, 100, "r", nano={"pay_to": EVM, "amount": "1"}), plain)
        self.assertEqual(build_offer(EVM, 100, "r", nano={"pay_to": PAY_TO, "amount": "0"}), plain)
        for nano in [None, {"pay_to": ""}, {"pay_to": EVM, "rate": 0.8}, self.nano(rate=0), self.nano(rate=None), self.nano(rate="x")]:
            self.assertEqual(len(offer_json(gateway(nano))["accepts"]), 3, nano)

    def test_normalises_a_legacy_xrb_payee_to_nano(self):
        self.assertEqual(nano_payee("xrb_" + PAY_TO[5:]), PAY_TO)
        self.assertEqual(nano_payee(PAY_TO.upper()), PAY_TO)
        self.assertIsNone(nano_payee("nano_123"))
        offer = build_offer(EVM, 100, "r", nano={"pay_to": "xrb_" + PAY_TO[5:], "amount": RAW_AT_080})
        self.assertEqual(offer["accepts"][3]["payTo"], PAY_TO)
        self.assertEqual(offer["accepts"][3]["extra"], {"decimals": 30})

    def test_prices_in_raw_with_integers_rounding_up(self):
        self.assertEqual(xno_raw(100, 0.8), RAW_AT_080)
        self.assertEqual(xno_raw(100, 0.7), "1428571428571428571428571428572")
        self.assertEqual(xno_raw(100, 1), str(RAW_PER_XNO))
        self.assertIsNone(xno_raw(100, 0))
        self.assertIsNone(xno_raw(100, float("nan")))
        self.assertIsNone(xno_raw(100, True))

    def test_settles_a_bound_block_with_the_node_not_coinpay_and_credits_it_once(self):
        post = wire()
        sales = []
        g = gateway(self.nano(), post=post, on_sale=sales.append)
        first = g.handle(Request(SITE + "/crawl", {"x-payment": nano_proof()}))
        self.assertEqual(first.status, 200, first.body)
        body = json.loads(first.body)
        self.assertFalse(body["replayed"])
        self.assertEqual(post.calls[0]["hash"], BLOCK)
        self.assertEqual(post.coinpay, [])
        self.assertEqual(len(sales), 1)
        self.assertEqual(sales[0]["ref"], BLOCK)
        # Lost the answer, asked again with the same block and order: a pass, no second sale.
        again = json.loads(g.handle(Request(SITE + "/crawl", {"x-payment": nano_proof()})).body)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["expires_at"], body["expires_at"])
        self.assertEqual(len(sales), 1)

    def test_a_restarted_gateway_does_not_credit_the_block_again(self):
        post = wire()
        sales = []
        first = gateway(self.nano(), post=post, on_sale=sales.append, now=1_000_000)
        self.assertEqual(first.handle(Request(SITE + "/crawl", {"x-payment": nano_proof()})).status, 200)
        # A new process over the same claims file, two days later: the first pass has ended.
        later = gateway(self.nano(claims=FileClaims(self.claims_path)), post=post, on_sale=sales.append, now=1_000_000 + 2 * 86400)
        res = later.handle(Request(SITE + "/crawl", {"x-payment": nano_proof()}))
        self.assertEqual(res.status, 402)
        self.assertIn("already used", json.loads(res.body)["error"])
        self.assertEqual(len(sales), 1)

    def test_refuses_the_same_block_hash_with_an_order_id_it_was_not_signed_for(self):
        g = gateway(self.nano(), post=wire())
        res = g.handle(Request(SITE + "/crawl", {"x-payment": nano_proof("c29tZW9uZS1lbHNlcy1vcmRlcg")}))
        self.assertEqual(res.status, 402)
        self.assertIn("not bound to this order", json.loads(res.body)["error"])

    def test_buys_n_days_with_n_times_one_day_in_raw(self):
        three = str(3 * int(xno_raw(100, 0.7)))
        post = wire(amount=three)
        g = gateway(self.nano(rate=lambda: 0.7), post=post)
        offered = offer_json(g, "/crawl?days=3")["accepts"][3]["amount"]
        self.assertEqual(offered, three)
        res = g.handle(Request(SITE + "/crawl", {"x-payment": nano_proof(amount=three)}))
        self.assertEqual(res.status, 200, res.body)
        self.assertEqual(json.loads(res.body)["days"], 3)

    def test_a_rate_that_fails_mid_sale_never_sells_n_days_for_one(self):
        one = xno_raw(100, 0.8)
        reads = []

        def rate():
            reads.append(1)
            if len(reads) > 1:
                raise RuntimeError("price feed down")
            return 0.8

        # The block pays one day; the proof claims three.
        g = gateway(self.nano(rate=rate), post=wire(amount=one))
        res = g.handle(Request(SITE + "/crawl", {"x-payment": nano_proof(amount=str(3 * int(one)))}))
        self.assertEqual(res.status, 402)
        self.assertIn("exactly", json.loads(res.body)["error"])

    def test_will_not_read_a_node_without_a_claims_store_or_over_plain_http_off_localhost(self):
        with self.assertRaisesRegex(ValueError, "claims"):
            gateway({"pay_to": PAY_TO, "rate": 0.8, "rpc_url": NODE})
        with self.assertRaisesRegex(ValueError, "https"):
            gateway(self.nano(rpc_url="http://node.test"))
        with self.assertRaisesRegex(ValueError, "rpc_url"):
            gateway({"pay_to": PAY_TO, "rate": 0.8})

    def test_a_nano_proof_without_nano_switched_on_matches_no_offered_network(self):
        post = wire()
        res = gateway(None, post=post).handle(Request(SITE + "/crawl", {"x-payment": nano_proof()}))
        self.assertEqual(res.status, 402)
        self.assertIn("offered network", json.loads(res.body)["error"])
        self.assertEqual(post.calls, [])

    def test_leaves_the_evm_proof_path_as_it_was(self):
        evm = decode_payment(b64({"x402Version": 2, "network": "eip155:8453", "payload": {"authorization": {"nonce": "0xabc", "validBefore": "9999999999", "value": "1000000"}}}))
        self.assertEqual(evm["x402Version"], 2)
        self.assertEqual(nonce_of(evm), "0xabc")
        self.assertEqual(valid_before_of(evm), 9999999999)
        nano = decode_payment(b64({"network": "nano", "payload": {"blockHash": BLOCK}}))
        self.assertIsNone(valid_before_of(nano))
        self.assertEqual(nonce_of(nano), BLOCK)


if __name__ == "__main__":
    unittest.main()
