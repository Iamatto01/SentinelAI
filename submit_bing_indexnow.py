#!/usr/bin/env python3
"""
SentinelAI - Automatic IndexNow Submission to Bing and IndexNow Search Engines
Pings Microsoft Bing directly to immediately crawl and index https://sentinelai.studio/
"""

import urllib.request
import urllib.error
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

HOST = "sentinelai.studio"
KEY = "7e28b49f3a1d48c291e0a5c7f8b9d3e1"
KEY_LOCATION = f"https://{HOST}/{KEY}.txt"

URL_LIST = [
    f"https://{HOST}/",
    f"https://{HOST}/tools",
    f"https://{HOST}/services",
    f"https://{HOST}/about",
    f"https://{HOST}/pricing",
    f"https://{HOST}/contact",
    f"https://{HOST}/login"
]

ENDPOINTS = [
    "https://api.indexnow.org/indexnow",
    "https://www.bing.com/indexnow"
]

def submit():
    payload = {
        "host": HOST,
        "key": KEY,
        "keyLocation": KEY_LOCATION,
        "urlList": URL_LIST
    }
    data = json.dumps(payload).encode("utf-8")

    print(f"📡 Submitting {len(URL_LIST)} URLs to IndexNow for {HOST}...")
    print(f"   Key Location: {KEY_LOCATION}")

    for endpoint in ENDPOINTS:
        print(f"\n🚀 Sending request to {endpoint} ...")
        req = urllib.request.Request(
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": "SentinelAI-IndexNow/1.0"
            },
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                print(f"   ✓ Success! HTTP Status: {resp.status} ({resp.reason})")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore")
            print(f"   ⚠ HTTP Error {e.code}: {e.reason}")
            if body:
                print(f"     Details: {body}")
        except Exception as e:
            print(f"   ✖ Request failed: {e}")

if __name__ == "__main__":
    submit()
