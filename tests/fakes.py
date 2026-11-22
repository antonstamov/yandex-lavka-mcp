"""Shared fakes for the HTTP-level tests."""

from __future__ import annotations

import httpx
import respx

from yandex_lavka_mcp.config import Config, Location

HOMEPAGE_HTML = (
    '<html><script id="__page_props__-data" type="application/json">'
    '{"csrfToken":"bff-456","authProxyCsrfToken":"tok-123","config":{}}</script>'
    '<script id="storedehydratedstate-data" type="application/json">'
    '{"startup":{"current":{"featureFlags":{"trustedUser":true}}}}</script></html>'
)


def config() -> Config:
    return Config(cookies={"Session_id": "fake"}, location=Location(lat=55.0, lon=37.0))


def mock_homepage():
    return respx.get("https://lavka.yandex.ru/").mock(return_value=httpx.Response(200, text=HOMEPAGE_HTML))
