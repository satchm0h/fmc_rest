import types
import sys
import importlib
from unittest.mock import MagicMock
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest

from tests.test_fmc_rest_additional import _install_requests_stub, DummyHeaders


def import_mod(monkeypatch):
    _install_requests_stub(monkeypatch)
    import fmc_rest
    import fmc_rest.fmc_rest
    importlib.reload(fmc_rest.fmc_rest)
    importlib.reload(fmc_rest)
    from fmc_rest import FMCRest, cdFMCRest, FMCException
    return FMCRest, cdFMCRest, FMCException


def test_fmcrest_init_calls_auth(monkeypatch):
    FMCRest, _, _ = import_mod(monkeypatch)
    called = {}

    def fake_auth(self, u, p, d):
        called['args'] = (u, p, d)
    monkeypatch.setattr(FMCRest, '_auth', fake_auth)

    fmc = FMCRest('host', 'u', 'p', ssl_verify=True, url='/v/', domain='D')
    assert fmc.base_url == 'https://host/v/'
    assert fmc.session.verify is True
    assert fmc.session.headers == FMCRest.HEADERS
    assert called['args'] == ('u', 'p', 'D')


def test_auth_http_error(monkeypatch):
    FMCRest, _, _ = import_mod(monkeypatch)
    fmc = object.__new__(FMCRest)
    err = Exception('boom')
    resp = types.SimpleNamespace(status_code=500, text='oops', headers={}, raise_for_status=MagicMock(side_effect=err))
    fmc.session = types.SimpleNamespace(post=MagicMock(return_value=resp))
    fmc.base_url = ''
    with pytest.raises(Exception):
        fmc._auth('u', 'p')
    resp.raise_for_status.assert_called_once()


def test_auth_no_refresh(monkeypatch):
    FMCRest, _, _ = import_mod(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    fmc.token_expires = sys.maxsize
    fmc._auth(None, None)
    assert not fmc.session.post.called


def test_auth_missing_refresh(monkeypatch):
    FMCRest, _, FMCException = import_mod(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    headers = DummyHeaders({'DOMAINS':'[{"name":"Global","uuid":"1"}]','X-auth-access-token':'a'})
    resp = types.SimpleNamespace(status_code=200, text='{}', headers=headers, raise_for_status=MagicMock())
    fmc.session.post.return_value = resp
    with pytest.raises(FMCException):
        fmc._auth('u','p','Global')


def test_request_http_error(monkeypatch):
    FMCRest, _, _ = import_mod(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.base_url = ''
    fmc.domain = {'uuid':'id'}
    resp = types.SimpleNamespace(status_code=500, text='oops', raise_for_status=MagicMock(side_effect=Exception('e')))
    fmc.session = types.SimpleNamespace(get=MagicMock(return_value=resp), post=MagicMock(), put=MagicMock(), delete=MagicMock())
    fmc._auth = lambda *a, **k: None
    with pytest.raises(Exception):
        fmc._request('GET','/u')
    resp.raise_for_status.assert_called_once()


def test_cdfmcrest_init(monkeypatch):
    _, cdFMCRest, _ = import_mod(monkeypatch)
    get_ep = MagicMock(return_value='cdo')
    det_ep = MagicMock(return_value='fmc')
    det_dom = MagicMock(return_value={'uuid':'1'})
    monkeypatch.setattr(cdFMCRest, '_get_region_endpoint', get_ep)
    monkeypatch.setattr(cdFMCRest, '_determine_cdFMC_endpoint', det_ep)
    monkeypatch.setattr(cdFMCRest, '_determine_cdFMC_domain', det_dom)

    c = cdFMCRest('tok','us',ssl_verify=False,url='/api/')
    assert c.session.headers['Authorization'] == 'Bearer tok'
    assert c.cdo_base_url == 'https://cdo/'
    assert c.base_url == 'https://fmc/api/'
    get_ep.assert_called_with('us')
    det_ep.assert_called_once()
    det_dom.assert_called_once()


def test_cdfmcrest_auth_noop(monkeypatch):
    _, cdFMCRest, _ = import_mod(monkeypatch)
    c = object.__new__(cdFMCRest)
    assert c._auth() is None

