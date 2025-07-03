import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import types
from unittest.mock import MagicMock
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
    requests.Session = lambda: types.SimpleNamespace()
    requests.auth = types.SimpleNamespace(HTTPBasicAuth=object)
    requests.exceptions = types.SimpleNamespace(HTTPError=Exception)
    monkeypatch.setitem(sys.modules, 'requests', requests)
    monkeypatch.setitem(sys.modules, 'requests.packages', packages)
    monkeypatch.setitem(sys.modules, 'requests.packages.urllib3', urllib3_pkg)
    monkeypatch.setitem(sys.modules, 'requests.packages.urllib3.exceptions', exceptions_pkg)


def test_star_import_provides_symbols(monkeypatch):
    _install_requests_stub(monkeypatch)
    namespace = {}
    exec('from fmc_rest import *', namespace)
    assert 'FMCRest' in namespace
    assert 'cdFMCRest' in namespace
    assert 'FMCException' in namespace


def test_request_invalid_verb_raises(monkeypatch):
    _install_requests_stub(monkeypatch)
    from fmc_rest import FMCRest, FMCException

    fmc = object.__new__(FMCRest)
    fmc.session = types.SimpleNamespace(
        get=MagicMock(),
        post=MagicMock(),
        put=MagicMock(),
        delete=MagicMock(),
    )
    fmc.base_url = ''
    fmc._auth = lambda *a, **kw: None

    with pytest.raises(FMCException):
        fmc._request('BAD', '/foo')
