"""Cookie self-persistence: server rotations are saved back to the file config."""

from __future__ import annotations

import httpx
import pytest
import respx

from yandex_lavka_mcp.client import LavkaClient
from yandex_lavka_mcp.config import Config, Location, load_config, save_config
from fakes import config as _config
from fakes import mock_homepage as _mock_homepage
from yandex_lavka_mcp.errors import LavkaAuthError


def _seeded_config() -> Config:
    cfg = Config(
        cookies={"Session_id": "sess-old", "sessionid2": "sid2-old", "yandexuid": "1"},
        location=Location(lat=55.0, lon=37.0),
    )
    save_config(cfg)
    loaded = load_config()
    assert loaded.from_file is True
    return loaded


@respx.mock
async def test_successful_call_persists_rotated_cookies(tmp_path, monkeypatch):
    monkeypatch.setenv("YANDEX_LAVKA_MCP_CONFIG_DIR", str(tmp_path))
    _mock_homepage()
    respx.post("https://lavka.yandex.ru/api/v1/providers/cart/v1/retrieve").mock(
        return_value=httpx.Response(
            200,
            json={"cartId": "c1", "cartVersion": 1, "items": []},
            headers=[
                ("Set-Cookie", "sessionid2=sid2-new; Path=/"),
                ("Set-Cookie", "brand-new=hello; Path=/"),
            ],
        )
    )
    async with LavkaClient(_seeded_config()) as client:
        await client.get_cart()
    reloaded = load_config()
    assert reloaded.cookies["sessionid2"] == "sid2-new"  # rotated value saved
    assert reloaded.cookies["brand-new"] == "hello"  # new cookie saved
    assert reloaded.cookies["Session_id"] == "sess-old"  # untouched stays
    assert reloaded.cookies["yandexuid"] == "1"


@respx.mock
async def test_in_memory_config_never_touches_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("YANDEX_LAVKA_MCP_CONFIG_DIR", str(tmp_path))
    _mock_homepage()
    respx.post("https://lavka.yandex.ru/api/v1/providers/search/v3/lavka").mock(
        return_value=httpx.Response(
            200,
            json={"cacheProducts": []},
            headers=[("Set-Cookie", "sessionid2=whatever; Path=/")],
        )
    )
    cfg = _config()
    assert cfg.from_file is False
    async with LavkaClient(cfg) as client:
        await client.search("молоко")
    assert list(tmp_path.iterdir()) == []  # no file created anywhere near config


@respx.mock
async def test_auth_error_points_at_cookie_refresh():
    _mock_homepage()
    respx.post("https://lavka.yandex.ru/api/v1/providers/cart/v1/retrieve").mock(
        return_value=httpx.Response(403, text="forbidden")
    )
    async with LavkaClient(_config()) as client:
        with pytest.raises(LavkaAuthError, match="extract_chrome_cookies_win"):
            await client.get_cart()
