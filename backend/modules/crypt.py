import re
from datetime import datetime

import requests

HEADERS = {"User-Agent": "Mozilla/5.0"}


# ============ ПАРСЕР ВВОДА ============
def detect_chain(addr: str) -> str:
    """Определяет блокчейн по формату адреса."""
    a = addr.strip()

    # TON — base64url 48 символов, начинается с EQ или UQ
    if re.fullmatch(r"[EU]Q[A-Za-z0-9_\-]{46}", a):
        return "ton"
    if re.fullmatch(r"0:[a-fA-F0-9]{64}", a):
        return "ton"

    # Bitcoin — legacy (1...), P2SH (3...), bech32 (bc1...)
    if re.fullmatch(r"1[a-km-zA-HJ-NP-Z1-9]{25,34}", a):
        return "btc"
    if re.fullmatch(r"3[a-km-zA-HJ-NP-Z1-9]{25,34}", a):
        return "btc"
    if re.fullmatch(r"bc1[a-z0-9]{39,59}", a):
        return "btc"

    # Ethereum и EVM-совместимые (0x + 40 hex)
    if re.fullmatch(r"0x[a-fA-F0-9]{40}", a):
        return "eth"

    # Tron (T + 33 base58)
    if re.fullmatch(r"T[a-km-zA-HJ-NP-Z1-9]{33}", a):
        return "tron"

    # Solana (base58, 32-44)
    if re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", a):
        return "sol"

    # Litecoin
    if re.fullmatch(r"[LM3][a-km-zA-HJ-NP-Z1-9]{25,34}", a):
        return "ltc"

    # Dogecoin (D + 33)
    if re.fullmatch(r"D[a-km-zA-HJ-NP-Z1-9]{33}", a):
        return "doge"

    return "unknown"


# ============ TON ============
def check_ton(addr: str) -> dict:
    out = {"found": False, "chain": "TON", "address": addr}
    try:
        # toncenter.com — публичный API без ключа
        r = requests.get(
            "https://toncenter.com/api/v2/getAddressInformation",
            params={"address": addr},
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("ok"):
                res = d.get("result", {})
                balance_nano = int(res.get("balance", 0))
                out.update(
                    {
                        "found": True,
                        "balance_ton": balance_nano / 1e9,
                        "state": res.get("state"),
                        "link": f"https://tonviewer.com/{addr}",
                        "explorer": f"https://tonscan.org/address/{addr}",
                    }
                )
        # Транзакции
        r2 = requests.get(
            "https://toncenter.com/api/v2/getTransactions",
            params={"address": addr, "limit": 10},
            headers=HEADERS,
            timeout=15,
        )
        if r2.status_code == 200:
            t = r2.json()
            if t.get("ok"):
                txs = t.get("result", [])
                out["tx_count_sample"] = len(txs)
                out["last_tx"] = []
                for tx in txs[:5]:
                    out["last_tx"].append(
                        {
                            "hash": tx.get("transaction_id", {}).get("hash", "")[:16]
                            + "...",
                            "lt": tx.get("transaction_id", {}).get("lt"),
                            "utime": tx.get("utime"),
                            "value": int(tx.get("in_msg", {}).get("value", 0) or 0)
                            / 1e9,
                            "from": tx.get("in_msg", {}).get("source", ""),
                        }
                    )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ BITCOIN ============
def check_btc(addr: str) -> dict:
    out = {"found": False, "chain": "Bitcoin", "address": addr}
    try:
        r = requests.get(
            f"https://blockchain.info/rawaddr/{addr}",
            params={"limit": 10},
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            out.update(
                {
                    "found": True,
                    "balance_btc": d.get("final_balance", 0) / 1e8,
                    "total_received_btc": d.get("total_received", 0) / 1e8,
                    "total_sent_btc": d.get("total_sent", 0) / 1e8,
                    "tx_count": d.get("n_tx", 0),
                    "link": f"https://blockchain.info/address/{addr}",
                    "explorer": f"https://www.blockchain.com/explorer/addresses/btc/{addr}",
                }
            )
            txs = d.get("txs", [])
            out["last_tx"] = []
            for tx in txs[:5]:
                out["last_tx"].append(
                    {
                        "hash": tx.get("hash", "")[:16] + "...",
                        "time": tx.get("time"),
                        "result": tx.get("result", 0) / 1e8,
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ ETHEREUM и EVM ============
def check_eth(addr: str) -> dict:
    out = {"found": False, "chain": "Ethereum/EVM", "address": addr}
    try:
        # blockchair public API (no key, up to 1440/day)
        r = requests.get(
            f"https://api.blockchair.com/ethereum/dashboards/address/{addr}",
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("data"):
                info = list(d["data"].values())[0].get("address", {})
                out.update(
                    {
                        "found": True,
                        "balance_eth": info.get("balance", 0) / 1e18,
                        "received_eth": info.get("received", 0) / 1e18,
                        "spent_eth": info.get("spent", 0) / 1e18,
                        "tx_count": info.get("transaction_count", 0),
                        "first_seen": info.get("first_seen_receiving"),
                        "last_seen": info.get("last_seen_spending"),
                        "is_contract": info.get("type") == "contract",
                        "link": f"https://etherscan.io/address/{addr}",
                        "explorer": f"https://blockchair.com/ethereum/address/{addr}",
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ TRON ============
def check_tron(addr: str) -> dict:
    out = {"found": False, "chain": "Tron", "address": addr}
    try:
        r = requests.get(
            f"https://apilist.tronscanapi.com/api/account?address={addr}",
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("address"):
                out.update(
                    {
                        "found": True,
                        "balance_trx": d.get("balance", 0) / 1e6,
                        "tx_count": d.get("transactions", 0),
                        "bandwidth": d.get("bandwidth", {}).get("freeNetUsed", 0),
                        "created": d.get("date_created"),
                        "link": f"https://tronscan.org/#/address/{addr}",
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ SOLANA ============
def check_sol(addr: str) -> dict:
    out = {"found": False, "chain": "Solana", "address": addr}
    try:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]}
        r = requests.post(
            "https://api.mainnet-beta.solana.com",
            json=payload,
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if "result" in d:
                out.update(
                    {
                        "found": True,
                        "balance_sol": d["result"].get("value", 0) / 1e9,
                        "link": f"https://solscan.io/account/{addr}",
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ DOGE ============
def check_doge(addr: str) -> dict:
    out = {"found": False, "chain": "Dogecoin", "address": addr}
    try:
        r = requests.get(
            f"https://dogechain.info/api/v1/address/balance/{addr}",
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("success"):
                out.update(
                    {
                        "found": True,
                        "balance_doge": float(d.get("balance", 0)),
                        "link": f"https://dogechain.info/address/{addr}",
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ LITECOIN ============
def check_ltc(addr: str) -> dict:
    out = {"found": False, "chain": "Litecoin", "address": addr}
    try:
        r = requests.get(
            f"https://api.blockchair.com/litecoin/dashboards/address/{addr}",
            headers=HEADERS,
            timeout=15,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("data"):
                info = list(d["data"].values())[0].get("address", {})
                out.update(
                    {
                        "found": True,
                        "balance_ltc": info.get("balance", 0) / 1e8,
                        "tx_count": info.get("transaction_count", 0),
                        "link": f"https://blockchair.com/litecoin/address/{addr}",
                    }
                )
    except Exception as e:
        out["error"] = str(e)
    return out


# ============ ВЫВОД ============
def _h(text):
    print(f"\n{'─'*60}")
    print(f"  {text}")
    print(f"{'─'*60}")


def fmt_ts(ts):
    if not ts:
        return "?"
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
        return str(ts)[:19]
    except Exception:
        return str(ts)


def print_crypto(info: dict):
    print(f"\n{'='*60}")
    print(f"💰 {info.get('chain', '?').upper()}")
    print(f"{'='*60}")
    print(f"   Адрес:    {info.get('address')}")
    if info.get("error"):
        print(f"   ❌ {info['error']}")
        return
    if not info.get("found"):
        print(f"   ⚪ Адрес не найден в блокчейне")
        return
    for key, label in [
        ("balance_ton", "Баланс TON"),
        ("balance_btc", "Баланс BTC"),
        ("balance_eth", "Баланс ETH"),
        ("balance_trx", "Баланс TRX"),
        ("balance_sol", "Баланс SOL"),
        ("balance_doge", "Баланс DOGE"),
        ("balance_ltc", "Баланс LTC"),
        ("total_received_btc", "Всего получено BTC"),
        ("total_sent_btc", "Всего отправлено BTC"),
        ("received_eth", "Всего получено ETH"),
        ("spent_eth", "Всего отправлено ETH"),
    ]:
        if info.get(key) is not None:
            print(f"   {label}: {info[key]:.8f}".rstrip("0").rstrip("."))
    for key, label in [
        ("tx_count", "Транзакций"),
        ("state", "Состояние"),
        ("is_contract", "Контракт"),
        ("first_seen", "Первый раз"),
        ("last_seen", "Последний раз"),
        ("created", "Создан"),
    ]:
        if info.get(key) is not None:
            v = info[key]
            if isinstance(v, bool):
                v = "да" if v else "нет"
            print(f"   {label}: {v}")
    if info.get("link"):
        print(f"\n   🔗 {info['link']}")
    if info.get("explorer"):
        print(f"   🔗 {info['explorer']}")
    if info.get("last_tx"):
        _h("ПОСЛЕДНИЕ ТРАНЗАКЦИИ")
        for tx in info["last_tx"][:5]:
            h = tx.get("hash", "?")
            print(f"   • {h}")
            if tx.get("utime"):
                print(f"      Время: {fmt_ts(tx['utime'])}")
            if tx.get("time"):
                print(f"      Время: {fmt_ts(tx['time'])}")
            if tx.get("value") is not None:
                print(f"      Сумма: {tx['value']}")
            if tx.get("result") is not None:
                print(f"      Результат: {tx['result']}")
            if tx.get("from"):
                print(f"      От: {tx['from']}")


def check(address: str):
    address = address.strip()
    chain = detect_chain(address)
    print(f"\n{'='*60}")
    print(f"🔎 КРИПТО: {address}")
    print(f"   Определён блокчейн: {chain.upper()}")
    print(f"{'='*60}")
    checkers = {
        "ton": check_ton,
        "btc": check_btc,
        "eth": check_eth,
        "tron": check_tron,
        "sol": check_sol,
        "doge": check_doge,
        "ltc": check_ltc,
    }
    if chain == "unknown":
        print("\n   ⚠️  Не удалось определить блокчейн по формату.")
        print("   Попробую как BTC...")
        info = check_btc(address)
    else:
        info = checkers[chain](address)
    print_crypto(info)


if __name__ == "__main__":
    addr = input("Крипто-адрес: ").strip()
    if addr:
        check(addr)
    else:
        print("❌ Пустой ввод")
