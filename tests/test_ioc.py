"""IoC (Custom Intelligence) feed: type/level tokens, per-type value checks, CSV render, quick-entry."""
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.routers import serve, ui
from app.routers.ui import DEFAULT_IOC_INDICATORS_TEXT, parse_indicators_text
from app.schemas.ioc import IOC_LEVELS, IOC_TYPES, IndicatorIn, canonical_type
from app.services.render import normalize_ioc_content, render_ioc

EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


def test_type_tokens_are_the_r8210_set():
    assert set(IOC_TYPES) == {
        "IP", "IP Range", "Domain", "URL", "MD5", "SHA1", "SHA256",
        "Mail-subject", "Mail-from", "Mail-to", "Mail-cc", "Mail-reply-to"}
    assert IOC_LEVELS == ("low", "medium", "high", "critical")


def test_type_canonicalization_is_case_insensitive():
    assert canonical_type("ip") == "IP"
    assert canonical_type("IP RANGE") == "IP Range"
    assert canonical_type("md5") == "MD5"
    assert canonical_type("mail-to") == "Mail-to"
    with pytest.raises(ValueError):
        canonical_type("CIDR")                                  # not a native IoC type in R82.10


def test_indicator_normalizes_type_and_level_and_strips():
    i = IndicatorIn(name="  a ", value=" 203.0.113.5 ", type="ip", confidence="High", severity="")
    assert i.name == "a" and i.value == "203.0.113.5" and i.type == "IP"
    assert i.confidence == "high" and i.severity == ""          # blank level allowed


def test_per_type_value_validation():
    IndicatorIn(name="h", value=EICAR_MD5, type="MD5")          # ok
    with pytest.raises(ValidationError):
        IndicatorIn(name="h", value="abc123", type="MD5")       # wrong hash length
    with pytest.raises(ValidationError):
        IndicatorIn(name="h", value="nope", type="IP")          # not an IP
    IndicatorIn(name="r", value="10.0.0.1-10.0.0.9", type="IP Range")
    with pytest.raises(ValidationError):
        IndicatorIn(name="r", value="10.0.0.9-10.0.0.1", type="IP Range")   # end < start
    with pytest.raises(ValidationError):
        IndicatorIn(name="d", value="x.example.com", type="Domain", severity="urgent")  # bad level
    with pytest.raises(ValidationError):
        IndicatorIn(name="", value="1.1.1.1", type="IP")        # name required
    with pytest.raises(ValidationError):
        IndicatorIn(name="x", value="", type="IP")              # value required


def test_normalize_shape_dedup_and_empty():
    c = normalize_ioc_content([{"name": "a", "value": "203.0.113.5", "type": "IP"}], "desc")
    assert c == {"indicators": [{"name": "a", "value": "203.0.113.5", "type": "IP",
                                 "confidence": "", "severity": "", "product": "", "comment": ""}]}
    with pytest.raises(ValueError):
        normalize_ioc_content([], "")                           # at least one required
    with pytest.raises(ValueError):
        normalize_ioc_content([{"name": "a", "value": "1.1.1.1", "type": "IP"},
                               {"name": "a", "value": "2.2.2.2", "type": "IP"}], "")  # UNIQ-NAME


def test_render_native_checkpoint_csv():
    feed = SimpleNamespace(description="My Feed", name="x", content={"indicators": [
        {"name": "ioc-1", "value": "203.0.113.66", "type": "IP",
         "confidence": "high", "severity": "high", "product": "AB", "comment": "C2, beacon"},
        {"name": "ioc-2", "value": EICAR_MD5, "type": "MD5",
         "confidence": "", "severity": "high", "product": "AV", "comment": ""}]})
    body, media = render_ioc(feed)
    assert media == "text/csv; charset=utf-8"
    lines = body.splitlines()
    assert lines[0] == "#! DESCRIPTION = My Feed"               # metadata line
    assert lines[1] == 'ioc-1,203.0.113.66,IP,high,high,AB,"C2, beacon"'   # comma in comment is quoted
    assert lines[2] == f"ioc-2,{EICAR_MD5},MD5,,high,AV,"       # empty confidence + trailing comment


def test_quick_entry_parser():
    rows = parse_indicators_text(
        "203.0.113.5, IP\n"
        "# a comment line\n"
        "\n"
        "malware.example.com, Domain, high, critical, AB, sinkhole, see ticket 42")
    assert [r["name"] for r in rows] == ["ioc-1", "ioc-2"]      # auto-named, # + blank ignored
    assert rows[0] == {"name": "ioc-1", "value": "203.0.113.5", "type": "IP",
                       "confidence": "", "severity": "", "product": "", "comment": ""}
    assert rows[1]["comment"] == "sinkhole, see ticket 42"      # commas kept in the comment field
    with pytest.raises(ValueError):
        parse_indicators_text("onlyvalue")                      # missing type
    with pytest.raises(ValueError):
        parse_indicators_text("# nothing real\n\n")             # no indicators


def test_default_sample_validates():
    content = normalize_ioc_content(parse_indicators_text(DEFAULT_IOC_INDICATORS_TEXT), "demo")
    assert len(content["indicators"]) == 5
    assert content["indicators"][0]["type"] == "IP"
    assert any(i["type"] == "MD5" for i in content["indicators"])


def test_routes_registered():
    assert "/ioc/{token}.csv" in {r.path for r in serve.router.routes}
    assert "/feeds/new/ioc" in {getattr(r, "path", "") for r in ui.router.routes}
