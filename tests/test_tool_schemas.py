"""Deriving Terraform/Ansible support from the live provider + collections, and baking it into the
coverage comparison. All fixture-based — no terraform CLI, no network."""
import io
import tarfile

import pytest

from app.services import coverage_build as cb
from app.services import tool_schemas as ts


# --- the parsers (pure) ---------------------------------------------------------------------------
def test_resources_from_schema_collects_attrs_and_blocks():
    data = {"provider_schemas": {"registry.terraform.io/checkpointsw/checkpoint": {"resource_schemas": {
        "checkpoint_management_host": {"block": {
            "attributes": {"name": {}, "ipv4_address": {}, "ipv6_address": {}},
            "block_types": {"nat_settings": {}, "interfaces": {}}}},
        "checkpoint_management_network": {"block": {"attributes": {"name": {}, "subnet4": {}}}}}}}}
    res = ts._resources_from_schema(data)
    assert res["checkpoint_management_host"] == {"name", "ipv4_address", "ipv6_address", "nat_settings", "interfaces"}
    assert res["checkpoint_management_network"] == {"name", "subnet4"}


def test_doc_options_parses_top_level_options_without_pyyaml():
    doc_src = '''
DOCUMENTATION = """
module: cp_mgmt_host
short_description: manage a host
options:
  name:
    description: x
    type: str
  ip_address:
    type: str
  nat_settings:
    type: dict
    suboptions:
      auto_rule:
        type: bool
  tags:
    type: list
author:
  - someone
"""
'''
    opts = ts._doc_options(doc_src)
    assert opts == {"name", "ip_address", "nat_settings", "tags"}   # top-level only; suboptions excluded


# --- network paths via a fake httpx client --------------------------------------------------------
class _Resp:
    def __init__(self, js=None, content=b""):
        self._js, self.content = js, content
    def json(self):
        if self._js is None:
            raise ValueError("no json")
        return self._js


class _FakeClient:
    def __init__(self, routes):
        self.routes = routes
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def get(self, url):
        for frag, resp in self.routes.items():
            if frag in url:
                return resp
        return _Resp(js={})


def test_latest_versions_reads_registry_and_galaxy(monkeypatch):
    routes = {
        "registry.terraform.io": _Resp(js={"version": "3.2.0"}),
        "/check_point/mgmt/": _Resp(js={"highest_version": {"version": "6.9.0"}}),
        "/check_point/gaia/": _Resp(js={"highest_version": {"version": "7.0.0"}}),
    }
    monkeypatch.setattr(ts, "_client", lambda timeout: _FakeClient(routes))
    assert ts.latest_versions() == {"terraform": "3.2.0", "ansible_mgmt": "6.9.0", "ansible_gaia": "7.0.0"}


def test_latest_versions_is_best_effort_on_failure(monkeypatch):
    def boom(timeout):
        raise RuntimeError("offline")
    monkeypatch.setattr(ts, "_client", boom)
    assert ts.latest_versions() == {"terraform": None, "ansible_mgmt": None, "ansible_gaia": None}


def _fake_collection_tarball():
    mod = (b'DOCUMENTATION = """\noptions:\n  name:\n    type: str\n  groups:\n    type: list\n"""\n')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path, data in [("check_point-mgmt/plugins/modules/cp_mgmt_host.py", mod),
                           ("check_point-mgmt/plugins/modules/__init__.py", b""),     # ignored (not cp_*)
                           ("check_point-mgmt/README.md", b"x")]:                     # ignored (not a module)
            ti = tarfile.TarInfo(path)
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_ansible_modules_downloads_and_parses(monkeypatch):
    routes = {
        "/check_point/mgmt/versions/6.9.0/": _Resp(js={"download_url": "https://x/coll.tar.gz"}),
        "/check_point/mgmt/": _Resp(js={"highest_version": {"version": "6.9.0"}}),
        "coll.tar.gz": _Resp(content=_fake_collection_tarball()),
    }
    monkeypatch.setattr(ts, "_client", lambda timeout: _FakeClient(routes))
    mods, ver = ts.ansible_modules("check_point", "mgmt")
    assert ver == "6.9.0"
    assert mods == {"cp_mgmt_host": {"name", "groups"}}     # only the cp_* module, top-level options


# --- coverage_build derives support from a ToolSchemas --------------------------------------------
_SPEC = {"paths": {"/add-host": {"post": {"requestBody": {"content": {"application/json": {"schema": {
    "type": "object", "required": ["name"], "properties": {
        "name": {"type": "string"}, "ip-address": {"type": "string"}, "groups": {"type": "array"}}}}}}}}}}


def _host_fields(art):
    host = next(o for o in art["objects"] if o["name"] == "host")
    return host, {f["name"]: f for f in host["fields"]}


def test_build_from_spec_derives_support_from_tools():
    tools = ts.ToolSchemas(
        tf_resources={"checkpoint_management_host": {"name", "ipv4_address"}},      # no 'groups' arg
        ans_modules={"cp_mgmt_host": {"name", "groups"}},                            # no ip_address option
        versions={"terraform": "3.2.0", "ansible_mgmt": "6.9.0", "ansible_gaia": "7.0.0"})
    art = cb.build_from_spec("management", "vT", _SPEC, tools=tools)
    assert art["tools_derived"] is True and art["tool_versions"]["terraform"] == "3.2.0"
    host, f = _host_fields(art)
    assert host["terraform"] == "checkpoint_management_host" and host["ansible"] == "cp_mgmt_host"
    assert f["ip-address"]["tf"] is True and f["ip-address"]["tf_name"] == "ipv4_address"   # rename verified
    assert f["ip-address"]["ansible"] is False                # cp_mgmt_host has no ip_address option here
    assert f["groups"]["tf"] is False                         # resource has no 'groups' arg
    assert f["groups"]["ansible"] is True and f["groups"]["ansible_name"] == "groups"


def test_build_from_spec_object_absent_from_tools_is_a_gap():
    tools = ts.ToolSchemas(tf_resources={}, ans_modules={}, versions={"terraform": "9.9.9"})
    art = cb.build_from_spec("management", "vT", _SPEC, tools=tools)
    host, _ = _host_fields(art)
    assert host["terraform"] is None and host["ansible"] is None   # neither provider nor collection has it


def test_build_from_spec_without_tools_uses_curated_fallback():
    art = cb.build_from_spec("management", "vT", _SPEC)            # tools=None
    assert art["tools_derived"] is False
    _, f = _host_fields(art)
    assert f["ip-address"]["tf_name"] == "ipv4_address"           # curated rename
    assert f["groups"]["tf"] is False and f["groups"]["ansible"] is True


def test_tool_version_status_flags_outdated(monkeypatch):
    from app.services import coverage
    monkeypatch.setattr(coverage, "_artifact",
                        lambda api, ver: {"tool_versions": {"terraform": "3.1.0",
                                                            "ansible_mgmt": "6.0.0", "ansible_gaia": "7.0.0"}})
    monkeypatch.setattr(ts, "latest_versions",
                        lambda: {"terraform": "3.2.0", "ansible_mgmt": "6.9.0", "ansible_gaia": "7.0.0"})
    st = cb.tool_version_status("management", "v2.1")
    assert st["outdated"] == {"terraform": True, "ansible_mgmt": True, "ansible_gaia": False}
    assert st["any_outdated"] is True
    assert st["baked"]["terraform"] == "3.1.0" and st["latest"]["terraform"] == "3.2.0"
