"""IoC (Custom Intelligence) feed: type/level tokens, per-type value checks, CSV render, quick-entry."""
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.links import public_path
from app.models import FeedType
from app.routers import serve, ui
from app.routers.ui import DEFAULT_IOC_INDICATORS_TEXT, parse_indicators_text
from app.schemas.ioc import IOC_LEVELS, IOC_TYPES, IndicatorIn, canonical_type, validate_snort_rules
from app.services.render import (
    custom_csv_command,
    normalize_ioc_content,
    normalize_snort_content,
    render_ioc,
)

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


def test_product_blade_must_match_type():
    IndicatorIn(name="a", value="203.0.113.5", type="IP", product="AB")            # IP → Anti-Bot ok
    assert IndicatorIn(name="a", value="x.example.com", type="URL", product="Anti-Virus").product == "AV"
    with pytest.raises(ValidationError):
        IndicatorIn(name="a", value="203.0.113.5", type="IP", product="AV")        # IP can't be AV
    with pytest.raises(ValidationError):
        IndicatorIn(name="a", value=EICAR_MD5, type="MD5", product="AB")           # hashes can't be AB
    with pytest.raises(ValidationError):
        IndicatorIn(name="a", value="x.example.com", type="Domain", product="IPS")  # not a valid blade
    assert IndicatorIn(name="a", value="x.example.com", type="Domain", product="").product == ""  # blank ok


def test_normalize_shape_dedup_and_empty():
    c = normalize_ioc_content([{"name": "a", "value": "203.0.113.5", "type": "IP"}], "desc")
    assert c == {"format": "cp_csv", "indicators": [{"name": "a", "value": "203.0.113.5", "type": "IP",
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
    assert lines[1] == "#UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT"   # header line
    assert lines[2] == 'ioc-1,203.0.113.66,IP,high,high,AB,"C2, beacon"'   # comma in comment is quoted
    assert lines[3] == f"ioc-2,{EICAR_MD5},MD5,,high,AV,"       # empty confidence + trailing comment


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


# ── multi-format (M2+): STIX 1.x, Custom CSV, Snort ─────────────────────────────────────────────
def _ind(name, value, type_, **kw):
    base = {"name": name, "value": value, "type": type_,
            "confidence": "", "severity": "", "product": "", "comment": ""}
    base.update(kw)
    return base


def test_normalize_stores_format_and_custom_options():
    assert normalize_ioc_content([_ind("a", "1.1.1.1", "IP")], "d", "stix_1.x")["format"] == "stix_1.x"
    cc = normalize_ioc_content([_ind("a", "1.1.1.1", "IP")], "d", "custom_csv", "|", ";")
    assert cc["format"] == "custom_csv" and cc["delimiter"] == "|" and cc["comment"] == ";"
    with pytest.raises(ValueError):
        normalize_ioc_content([_ind("a", "1.1.1.1", "IP")], "d", "snort")   # snort isn't an indicator format


def test_render_defaults_to_cp_csv_without_format_key():
    feed = SimpleNamespace(token="t", name="F", description="d",
                           content={"indicators": [_ind("a", "1.1.1.1", "IP")]})
    body, media = render_ioc(feed)
    assert media == "text/csv; charset=utf-8" and "#UNIQ-NAME,VALUE,TYPE" in body


def test_stix_render_per_type_objects():
    feed = SimpleNamespace(token="tok", name="F", description="d", content={"format": "stix_1.x", "indicators": [
        _ind("a", "203.0.113.5", "IP"), _ind("b", EICAR_MD5, "MD5"),
        _ind("c", "evil.example.com", "Domain"), _ind("d", "http://x/y", "URL"),
        _ind("e", "10.0.0.1-10.0.0.9", "IP Range")]})
    body, media = render_ioc(feed)
    assert media == "application/xml"
    assert "<stix:STIX_Package" in body and 'cybox_major_version="2"' in body
    assert 'xsi:type="AddressObj:AddressObjectType" category="ipv4-addr"' in body
    assert "<AddressObj:Address_Value>203.0.113.5</AddressObj:Address_Value>" in body
    assert 'xsi:type="FileObj:FileObjectType"' in body and "<cyboxCommon:Type>MD5</cyboxCommon:Type>" in body
    assert EICAR_MD5 in body
    assert 'xsi:type="DomainNameObj:DomainNameObjectType"' in body and 'xsi:type="URIObj:URIObjectType"' in body
    assert 'condition="InclusiveBetween"' in body and "10.0.0.1##comma##10.0.0.9" in body
    import xml.dom.minidom                                       # must be well-formed XML
    xml.dom.minidom.parseString(body)


def test_custom_csv_render_and_command():
    feed = SimpleNamespace(token="tok", name="F", description="d", content={
        "format": "custom_csv", "delimiter": "|", "comment": ";",
        "indicators": [_ind("a", "203.0.113.5", "IP", confidence="high", severity="high",
                            product="AB", comment="c2")]})
    body, media = render_ioc(feed)
    assert media == "text/csv; charset=utf-8"
    lines = body.splitlines()
    assert lines[0] == "; d"                                    # comment-prefixed description
    assert lines[1].startswith(";") and "UNIQ-NAME|VALUE|TYPE" in lines[1]
    assert lines[2] == "a|203.0.113.5|IP|high|high|AB|c2"       # chosen delimiter applied
    cmd = custom_csv_command(feed, "https://p/ioc/tok.csv")
    assert "--feed_file_type custom_csv" in cmd and '--delimiter "|"' in cmd and '--comment ";"' in cmd


def test_snort_validate_and_render():
    rules = validate_snort_rules(
        'alert tcp any any -> any 80 (msg:"x"; sid:1;)\n# c\n\ndrop ip 1.2.3.4 any -> any any (sid:2;)')
    assert len(rules) == 2
    with pytest.raises(ValueError):
        validate_snort_rules("notanaction foo bar")             # bad action keyword
    with pytest.raises(ValueError):
        validate_snort_rules("# only comments\n\n")             # nothing real
    content = normalize_snort_content('alert tcp any any -> any 80 (msg:"x"; sid:1;)')
    assert content["format"] == "snort" and len(content["rules"]) == 1
    body, media = render_ioc(SimpleNamespace(content=content))
    assert media == "text/plain; charset=utf-8" and body.startswith("alert tcp")


def test_public_path_extension_by_format():
    def f(fmt):
        return SimpleNamespace(type=FeedType.ioc, token="tok", content={"format": fmt} if fmt else {})
    assert public_path(f("stix_1.x")) == "/ioc/tok.xml"
    assert public_path(f("snort")) == "/ioc/tok.txt"
    assert public_path(f("cp_csv")) == "/ioc/tok.csv"
    assert public_path(f(None)) == "/ioc/tok.csv"               # default when no format


def test_ioc_serve_extensions_registered():
    paths = {r.path for r in serve.router.routes}
    assert {"/ioc/{token}.csv", "/ioc/{token}.xml", "/ioc/{token}.txt"} <= paths
