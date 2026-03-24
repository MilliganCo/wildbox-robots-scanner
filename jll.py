#!/usr/bin/env python3
"""
silent_robots_finder_async_vpn.py  ·  v4
Поиск robots.txt на wildbox.ru через VPN-канал, без использования прокси.

⮞ Что делает
   • собирает поддомены wildbox.ru из crt.sh (+ Censys, если заданы ключи)
   • HEAD → GET, параллельно max 3 URL-а, random delay 0.5-1.5 с
   • не отправляет User-Agent
   • пишет лог в robots_finder.log (stdout — краткие статусы)

Зависимости:  Python ≥3.9, aiohttp ≥3.9
pip install -U aiohttp
"""

import asyncio
import json
import logging
import os
import random
import sys
import re
import itertools
from typing import Set

import aiohttp
from aiohttp import ClientTimeout

# --------------------------------------------------------------------------
DOMAIN = "wildbox.ru"
LOG_FILE = "robots_finder.log"
CONCURRENT_LIMIT = 3
TIMEOUT = ClientTimeout(total=10)

CRTSH_URL = f"https://crt.sh/?q=%25.{DOMAIN}&output=json"
CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")
CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/certificates/search"
WILDCARD_RE = re.compile(r"^\*\.(.+)$")
BO_URL = "https://dns.bufferover.run/dns?q=.%s"  # FDNS_A + RDNS
RPDNS_URL = "https://rapiddns.io/subdomain/%s?format=json"  # up to 50k lines


# --------------------- CT-лог парсеры ---------------------------------
# --------------------- CT-лог парсер (FIX) ---------------------------
async def fetch_crtsh_hosts(session, base_domain):
    """Возвращает множество хостов, раскрывая wildcard-SAN'ы."""
    seen, queue, out = set(), {base_domain}, set()

    while queue:
        dom = queue.pop()
        if dom in seen:
            continue
        seen.add(dom)

        url = f"https://crt.sh/?q=%25.{dom}&output=json"
        try:
            async with session.get(url, timeout=TIMEOUT, ssl=False) as resp:
                async for raw in resp.content:
                    try:
                        entry = json.loads(raw.decode())
                    except json.JSONDecodeError:
                        continue
                    for n in entry.get("name_value", "").split():
                        n = n.lower().rstrip(".")
                        if n.endswith("." + base_domain) or n == base_domain:
                            if m := WILDCARD_RE.match(n):
                                # '*.telegram.wildbox.ru' → добавить 'telegram.wildbox.ru' в очередь
                                queue.add(m.group(1))
                            else:
                                out.add(n)
        except Exception as e:
            logging.warning("crt.sh fetch %s failed: %s", dom, e)
    return out


# ---------- лёгкие DNS-дампы -----------------------------------------------
async def fetch_bufferover(session):
    hosts = set()
    try:
        async with session.get(BO_URL % DOMAIN, timeout=TIMEOUT) as resp:
            data = await resp.json()
            for line in itertools.chain(data.get("FDNS_A", []), data.get("RDNS", [])):
                host = line.split(",")[1].lower()
                if host.endswith("." + DOMAIN):
                    hosts.add(host)
    except Exception as e:
        logging.warning("bufferover failed: %s", e)
    return hosts


async def fetch_rapiddns(session):
    hosts = set()
    try:
        async with session.get(RPDNS_URL % DOMAIN, timeout=TIMEOUT) as resp:
            for row in await resp.json():  # [{'domain':'sub.wildbox.ru', ...}, …]
                h = row.get("domain", "").lower()
                if h.endswith("." + DOMAIN):
                    hosts.add(h)
    except Exception as e:
        logging.warning("rapiddns failed: %s", e)
    return hosts


async def fetch_censys_hosts(session: aiohttp.ClientSession) -> Set[str]:
    hosts: Set[str] = set()
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return hosts

    payload = {
        "q": DOMAIN,
        "per_page": 100,
        "virtual_hosts": "INCLUDE",
        "fields": ["parsed.names"],
    }
    try:
        async with session.post(
            CENSYS_SEARCH_URL,
            json=payload,
            auth=aiohttp.BasicAuth(CENSYS_API_ID, CENSYS_API_SECRET),
            timeout=TIMEOUT,
        ) as resp:
            if resp.status >= 400:
                logging.warning("Censys HTTP %s", resp.status)
                return hosts
            data = await resp.json()
            for hit in data.get("result", {}).get("hits", []):
                for n in hit.get("parsed.names", []):
                    n = n.lower()
                    if n.endswith("." + DOMAIN) or n == DOMAIN:
                        hosts.add(n)
    except Exception as e:
        logging.warning("Censys fetch failed: %s", e)
    return hosts


# ------------------------ core scan ----------------------------------
async def check_robots(session: aiohttp.ClientSession, sem: asyncio.Semaphore, scheme: str, host: str):
    url = f"{scheme}://{host}/robots.txt"
    async with sem:
        await asyncio.sleep(random.uniform(0.5, 1.5))  # jitter

        try:
            async with session.head(url, timeout=TIMEOUT, allow_redirects=True) as head:
                status = head.status
        except Exception as e:
            logging.debug("%s HEAD err: %s", url, e)
            return

        logging.info("[%s] %s", status, url)
        if status != 200:
            return

        try:
            async with session.get(url, timeout=TIMEOUT) as get_resp:
                text = await get_resp.text()
                snippet = " ".join(text.split())[:180]
                logging.info("      └ snippet: %s", snippet)
        except Exception as e:
            logging.debug("%s GET err: %s", url, e)


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        handlers=[logging.FileHandler(LOG_FILE, "w", "utf-8"), logging.StreamHandler(sys.stdout)],
    )

    logging.info("Fetching hostnames for %s …", DOMAIN)

    async with aiohttp.ClientSession(
        timeout=TIMEOUT,
        headers={},                # пустой dict → UA не отправляется
        skip_auto_headers={"User-Agent"},
    ) as session:
        hosts = {DOMAIN, "www." + DOMAIN}
        hosts |= await fetch_crtsh_hosts(session, DOMAIN)
        hosts |= await fetch_bufferover(session)
        hosts |= await fetch_rapiddns(session)
        hosts |= await fetch_censys_hosts(session)

        hosts = sorted(hosts)
        logging.info("%d hosts collected", len(hosts))

        sem = asyncio.Semaphore(CONCURRENT_LIMIT)
        tasks = [
            check_robots(session, sem, scheme, host)
            for scheme in ("https", "http")
            for host in hosts
        ]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nCancelled by user.")
