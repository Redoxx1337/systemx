import os

import requests
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

templates = Jinja2Templates(directory="templates")

# Load API credentials from environment (fallback to hard‑coded if not set)
DADATA_TOKEN = os.getenv("DADATA_TOKEN", "cc0b375d3c678a2fcb021a24bd146b4986341bd9")
DADATA_SECRET = os.getenv("DADATA_SECRET", "3ce48f27d73a057f793f2f45ceb4bd27f242e1db")
DEPSEARCH_TOKEN = os.getenv("DEPSEARCH_TOKEN", "mZkvhV9Uj8QKNLlrjrEg60o3gO8Oji94")
NETSPY_TOKEN = os.getenv("NETSPY_TOKEN", "ns-1mnqyWxuKSYgSYfiKn6mxUCrvvaRjIDj")
SEETG_TOKEN = os.getenv("SEETG_TOKEN", "392:_51P9m6rhHnIMJ_t0YKgon2peMUwZmEG")
JITLER_TOKENS = [
    os.getenv("JITLER_1", "vYJ6HySY0cL6mljjXdDRwJlM"),
    os.getenv("JITLER_2", "hAfORhW66liENpfB8TIXG5M8"),
    os.getenv("JITLER_3", "1OEIfDA1OaBzM1CHhdbrFbpw"),
    os.getenv("JITLER_4", "Hnc4kJ5sHGdrCUVVbCOWBnQm"),
]
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "dd1d4b363180aa")

# ---------- Service wrappers ----------


def dadata_search_phone(phone: str):
    url = "https://dadata.ru/api/v2/clean/phone"
    headers = {"Authorization": f"Token {DADATA_TOKEN}"}
    resp = requests.post(url, json=[phone], headers=headers, timeout=10)
    return resp.json()


def depsearch_search(query: str, search_type: str = ""):
    # Simple wrapper – documentation expects POST with JSON payload
    url = "https://depsearch.pro/api/search"
    headers = {
        "Authorization": f"Bearer {DEPSEARCH_TOKEN}",
        "Content-Type": "application/json",
    }
    payload = {"query": query}
    if search_type:
        payload["type"] = search_type
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    return resp.json()


def netspy_search(query: str, search_type: str = "tg"):
    url = "https://netspy.sbs/api/search"
    headers = {
        "X-API-Key": NETSPY_TOKEN,
        "Content-Type": "application/json",
    }
    payload = {"query": query, "search_type": search_type}
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    return resp.json()


def seetg_search(tg: str):
    url = "https://kartoshka.free/"
    headers = {"Authorization": f"Bearer {SEETG_TOKEN}"}
    payload = {"tg": tg}
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    return resp.json()


def jitler_search(query: str, endpoint: str = "phone"):
    # Jitler has several separate APIs – we use the first token for demo
    token = JITLER_TOKENS[0]
    url = f"https://api.jitler.top/{endpoint}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    payload = {"query": query}
    resp = requests.post(url, json=payload, headers=headers, timeout=10)
    return resp.json()


def ipinfo_lookup(ip: str):
    url = f"https://api.ipinfo.io/lite/{ip}?token={IPINFO_TOKEN}"
    resp = requests.get(url, timeout=10)
    return resp.json()


# ---------- UI ----------


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(
        "index.html", {"request": request, "result": None, "error": None}
    )


@app.post("/search", response_class=HTMLResponse)
async def search(request: Request, service: str = Form(...), query: str = Form(...)):
    try:
        if service == "vk":
            # reuse existing vk_search utilities – we will import lazily
            from vk_search import (build_dossier, get_followers, get_friends,
                                   get_groups, get_photos, get_profile,
                                   get_subscriptions, get_wall, parse_vk_input)

            ident = parse_vk_input(query)
            profile = get_profile(ident)
            if profile.get("error"):
                raise ValueError(profile["error"])
            uid = str(profile.get("id"))
            friends = get_friends(uid)
            followers = get_followers(uid)
            subs = get_subscriptions(uid)
            wall = get_wall(uid)
            groups = get_groups(uid)
            photos = get_photos(uid)
            dossier = build_dossier(profile, friends, followers, groups, wall, photos)
            result = {"profile": profile, "dossier": dossier}
        elif service == "dadata":
            result = dadata_search_phone(query)
        elif service == "depsearch":
            result = depsearch_search(query)
        elif service == "netspy":
            result = netspy_search(query)
        elif service == "seetg":
            result = seetg_search(query)
        elif service == "jitler":
            result = jitler_search(query)
        elif service == "ipinfo":
            result = ipinfo_lookup(query)
        else:
            raise ValueError("Unknown service")
        return templates.TemplateResponse(
            "index.html", {"request": request, "result": result, "error": None}
        )
    except Exception as e:
        return templates.TemplateResponse(
            "index.html", {"request": request, "result": None, "error": str(e)}
        )
