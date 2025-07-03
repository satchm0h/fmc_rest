import sys
import types
from unittest.mock import MagicMock
import json
import pathlib
import importlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest


def _install_requests_stub(monkeypatch):
    requests = types.ModuleType('requests')
    packages = types.ModuleType('requests.packages')
    urllib3_pkg = types.ModuleType('requests.packages.urllib3')
    exceptions_pkg = types.ModuleType('requests.packages.urllib3.exceptions')
    InsecureRequestWarning = type('InsecureRequestWarning', (), {})
    exceptions_pkg.InsecureRequestWarning = InsecureRequestWarning
    urllib3_pkg.exceptions = exceptions_pkg
    urllib3_pkg.disable_warnings = lambda *a, **k: None
    packages.urllib3 = urllib3_pkg
    requests.packages = packages

    class DummyAuth:
        def __init__(self, u=None, p=None):
            self.u = u
            self.p = p

    requests.Session = lambda: types.SimpleNamespace()
    requests.auth = types.SimpleNamespace(HTTPBasicAuth=DummyAuth)
    requests.exceptions = types.SimpleNamespace(HTTPError=Exception)
    monkeypatch.setitem(sys.modules, 'requests', requests)
    monkeypatch.setitem(sys.modules, 'requests.packages', packages)
    monkeypatch.setitem(sys.modules, 'requests.packages.urllib3', urllib3_pkg)
    monkeypatch.setitem(sys.modules, 'requests.packages.urllib3.exceptions', exceptions_pkg)
    return requests

def import_fmc(monkeypatch):
    stub = _install_requests_stub(monkeypatch)
    import importlib
    import fmc_rest
    import fmc_rest.fmc_rest
    importlib.reload(fmc_rest.fmc_rest)
    importlib.reload(fmc_rest)
    from fmc_rest import FMCRest, cdFMCRest, FMCException
    return FMCRest, cdFMCRest, FMCException, stub


class DummyHeaders(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class DummyResp:
    def __init__(self, status_code=200, text='{}', headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = DummyHeaders(headers or {})

    def raise_for_status(self):
        raise Exception(f"error {self.status_code}")


def make_fmc(FMCRest):
    fmc = object.__new__(FMCRest)
    fmc.base_url = ''
    fmc.domain = {'uuid': 'uid'}
    fmc.session = types.SimpleNamespace(
        get=MagicMock(),
        post=MagicMock(),
        put=MagicMock(),
        delete=MagicMock(),
        headers={}
    )
    fmc._auth = MagicMock()
    return fmc


def test_request_get_success(monkeypatch):
    """Ensure GET requests return parsed JSON on success."""
    FMCRest, _, _, _ = import_fmc(monkeypatch)
    fmc = make_fmc(FMCRest)
    fmc.session.get.return_value = DummyResp(text=json.dumps({'a': 1}))
    assert fmc._request('GET', '/url') == {'a': 1}
    fmc.session.get.assert_called_once_with('/url')


def test_request_handles_rate_limit(monkeypatch):
    """Verify that _request retries once after a 429 response."""
    FMCRest, _, _, _ = import_fmc(monkeypatch)
    fmc = make_fmc(FMCRest)
    fmc.session.get.side_effect = [DummyResp(429), DummyResp(text=json.dumps({'x': 2}))]
    monkeypatch.setattr('fmc_rest.fmc_rest.sleep', lambda *_: None)
    assert fmc._request('GET', '/url') == {'x': 2}
    assert fmc.session.get.call_count == 2


def test_request_post_put_delete(monkeypatch):
    """Check that POST/PUT/DELETE verbs are routed correctly."""
    FMCRest, _, _, _ = import_fmc(monkeypatch)
    fmc = make_fmc(FMCRest)
    fmc.session.post.return_value = DummyResp(text='{}')
    fmc.session.put.return_value = DummyResp(text='{}')
    fmc.session.delete.return_value = DummyResp(text='{}')
    assert fmc._request('POST', '/url', {}) == {}
    assert fmc.session.post.called
    assert fmc._request('PUT', '/url', {}) == {}
    assert fmc.session.put.called
    assert fmc._request('DELETE', '/url') == {}
    assert fmc.session.delete.called


def test_fmcrest_get_helpers(monkeypatch):
    """Confirm higher-level helpers build proper URLs."""
    FMCRest, _, _, _ = import_fmc(monkeypatch)
    fmc = make_fmc(FMCRest)
    fmc._request = MagicMock(return_value=1)
    assert fmc.get('/foo') == 1
    fmc._request.assert_called_with('GET', 'fmc_config/v1/domain/uid/foo')
    assert fmc.post('/foo', 2) == 1
    fmc._request.assert_called_with('POST', 'fmc_config/v1/domain/uid/foo', 2)
    assert fmc.put('/foo', 3) == 1
    fmc._request.assert_called_with('PUT', 'fmc_config/v1/domain/uid/foo', 3)
    assert fmc.delete('/foo') == 1
    fmc._request.assert_called_with('DELETE', 'fmc_config/v1/domain/uid/foo')


def test_auth_login(monkeypatch):
    """Exercise the login flow and token handling."""
    FMCRest, _, _, stub = import_fmc(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    resp = DummyResp(headers={'DOMAINS': '[{"name":"Global","uuid":"123"}]', 'X-auth-access-token': 'at', 'X-auth-refresh-token': 'rt'})
    fmc.session.post.return_value = resp
    fmc.token_expires = 0
    fmc._auth('u', 'p', 'Global')
    assert fmc.domain == {'name': 'Global', 'uuid': '123'}
    assert fmc.session.headers['X-auth-access-token'] == 'at'
    assert fmc.session.headers['X-auth-refresh-token'] == 'rt'
    assert fmc.session.post.call_args[0][0] == fmc.base_url + FMCRest.AUTH_PATH
    assert isinstance(fmc.session.post.call_args.kwargs['auth'], stub.auth.HTTPBasicAuth)


def test_auth_domain_not_found(monkeypatch):
    """Error is raised when selected domain is unavailable."""
    FMCRest, _, FMCException, _ = import_fmc(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    resp = DummyResp(headers={'DOMAINS': '[]', 'X-auth-access-token': 't', 'X-auth-refresh-token': 'r'})
    fmc.domain = None
    fmc.session.post.return_value = resp
    with pytest.raises(FMCException):
        fmc._auth('u', 'p', 'Other')


def test_auth_missing_tokens(monkeypatch):
    """Ensure missing token headers cause an exception."""
    FMCRest, _, FMCException, _ = import_fmc(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    resp = DummyResp(headers={'DOMAINS': '[{"name":"Global","uuid":"1"}]'})
    fmc.session.post.return_value = resp
    with pytest.raises(FMCException):
        fmc._auth('u', 'p', 'Global')


def test_auth_refresh(monkeypatch):
    """Test token refresh when existing credentials expire."""
    FMCRest, _, _, _ = import_fmc(monkeypatch)
    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(post=MagicMock(), headers={})
    fmc.base_url = ''
    resp = DummyResp(headers={'X-auth-access-token': 'a', 'X-auth-refresh-token': 'r'})
    fmc.session.post.return_value = resp
    fmc.token_expires = 0
    fmc._auth(None, None)
    assert fmc.session.post.call_args[0][0] == fmc.base_url + FMCRest.REFRESH_PATH
    assert fmc.session.headers['X-auth-access-token'] == 'a'
    assert fmc.session.headers['X-auth-refresh-token'] == 'r'


def test_get_region_endpoint(monkeypatch):
    """Look up CDO hostnames by region code."""
    _, cdFMCRest, FMCException, _ = import_fmc(monkeypatch)
    c = object.__new__(cdFMCRest)
    assert c._get_region_endpoint('us') == 'www.defenseorchestrator.com'
    assert c._get_region_endpoint('eu') == 'www.defenseorchestrator.eu'
    assert c._get_region_endpoint('apj') == 'apj.cdo.cisco.com'
    with pytest.raises(FMCException):
        c._get_region_endpoint('xx')


def test_raw_get_success(monkeypatch):
    """_raw_get should deserialize response content."""
    _, cdFMCRest, _, _ = import_fmc(monkeypatch)
    c = object.__new__(cdFMCRest)
    c.session = types.SimpleNamespace(get=MagicMock(return_value=DummyResp(text=json.dumps([{'host': 'foo'}]))))
    assert c._raw_get('u') == [{'host': 'foo'}]
    c.session.get.assert_called_with('u')


def test_raw_get_error(monkeypatch):
    """_raw_get propagates HTTP errors."""
    _, cdFMCRest, _, _ = import_fmc(monkeypatch)
    c = object.__new__(cdFMCRest)
    c.session = types.SimpleNamespace(get=MagicMock(return_value=DummyResp(500, text='oops')))
    with pytest.raises(Exception):
        c._raw_get('u')


def test_determine_cdfmc_endpoint(monkeypatch):
    """Confirm endpoint discovery from the host list."""
    _, cdFMCRest, FMCException, _ = import_fmc(monkeypatch)
    c = object.__new__(cdFMCRest)
    c.cdo_base_url = 'b/'
    c._raw_get = MagicMock(return_value=[{'host': 'h'}])
    assert c._determine_cdFMC_endpoint() == 'h'
    c._raw_get.assert_called_with('b/' + cdFMCRest.CDFMC_HOST_ENDPOINT)
    c._raw_get.return_value = [{}]
    with pytest.raises(FMCException):
        c._determine_cdFMC_endpoint()


def test_determine_cdfmc_domain(monkeypatch):
    """Verify domain lookup for cdFMCRest uses _raw_get."""
    _, cdFMCRest, FMCException, _ = import_fmc(monkeypatch)
    c = object.__new__(cdFMCRest)
    c.base_url = 'x/'
    c._raw_get = MagicMock(return_value={'items':[{'name':'Global','uuid':'1'}]})
    assert c._determine_cdFMC_domain() == {'name':'Global','uuid':'1'}
    c._raw_get.assert_called_with('x/' + cdFMCRest.CDFMC_DOMAIN_ENDPOINT)
    c._raw_get.return_value = {}
    with pytest.raises(FMCException):
        c._determine_cdFMC_domain()
