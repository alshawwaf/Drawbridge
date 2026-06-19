"""Render IoC indicators as a STIX 1.x / CybOX 2.1 Observables document.

Check Point's IoC parser accepts STIX 1.x (`--feed_file_type stix_1.x`; SmartConsole feed format
"Check Point format/STIX"). We emit an **Observables-only** STIX package — one `cybox:Observable` per
indicator with the per-type CybOX object. CONFIDENCE/SEVERITY are CSV-only concepts and are omitted
here (the gateway applies its profile/defaults). Built to the CybOX 2.1 conventions
(cybox.readthedocs.io); the parser's xsi:type/namespace handling is strict, so validate against a live
gateway — the Mail-* encodings in particular are best-effort.
"""
from xml.sax.saxutils import escape

# Standard STIX 1.x / CybOX 2.1 namespace URIs (+ a local ns for our generated ids).
_NS = {
    "stix": "http://stix.mitre.org/stix-1",
    "cybox": "http://cybox.mitre.org/cybox-2",
    "cyboxCommon": "http://cybox.mitre.org/common-2",
    "AddressObj": "http://cybox.mitre.org/objects#AddressObject-2",
    "DomainNameObj": "http://cybox.mitre.org/objects#DomainNameObject-1",
    "URIObj": "http://cybox.mitre.org/objects#URIObject-2",
    "FileObj": "http://cybox.mitre.org/objects#FileObject-2",
    "EmailMessageObj": "http://cybox.mitre.org/objects#EmailMessageObject-2",
    "dcsim": "https://dcsim.local/ioc",
    "xsi": "http://www.w3.org/2001/XMLSchema-instance",
}


def _properties(type_: str, value: str) -> str:
    """The <cybox:Properties> element for one observable type."""
    v = escape(value)
    if type_ == "IP":
        cat = "ipv6-addr" if ":" in value else "ipv4-addr"
        return (f'<cybox:Properties xsi:type="AddressObj:AddressObjectType" category="{cat}">'
                f'<AddressObj:Address_Value>{v}</AddressObj:Address_Value></cybox:Properties>')
    if type_ == "IP Range":
        lo, _, hi = value.partition("-")
        cat = "ipv6-addr" if ":" in lo else "ipv4-addr"
        rng = escape(f"{lo.strip()}##comma##{hi.strip()}")
        return (f'<cybox:Properties xsi:type="AddressObj:AddressObjectType" category="{cat}">'
                f'<AddressObj:Address_Value condition="InclusiveBetween" apply_condition="ANY">'
                f'{rng}</AddressObj:Address_Value></cybox:Properties>')
    if type_ == "Domain":
        return (f'<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType" type="FQDN">'
                f'<DomainNameObj:Value>{v}</DomainNameObj:Value></cybox:Properties>')
    if type_ == "URL":
        return (f'<cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">'
                f'<URIObj:Value>{v}</URIObj:Value></cybox:Properties>')
    if type_ in ("MD5", "SHA1", "SHA256"):
        return (f'<cybox:Properties xsi:type="FileObj:FileObjectType"><FileObj:Hashes>'
                f'<cyboxCommon:Hash><cyboxCommon:Type>{type_}</cyboxCommon:Type>'
                f'<cyboxCommon:Simple_Hash_Value>{v}</cyboxCommon:Simple_Hash_Value>'
                f'</cyboxCommon:Hash></FileObj:Hashes></cybox:Properties>')
    if type_ == "Mail-subject":
        return ('<cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">'
                f'<EmailMessageObj:Header><EmailMessageObj:Subject>{v}</EmailMessageObj:Subject>'
                '</EmailMessageObj:Header></cybox:Properties>')
    addr = f'<AddressObj:Address_Value>{v}</AddressObj:Address_Value>'
    if type_ in ("Mail-from", "Mail-reply-to"):
        tag = {"Mail-from": "From", "Mail-reply-to": "Reply_To"}[type_]
        inner = (f'<EmailMessageObj:{tag} xsi:type="AddressObj:AddressObjectType" category="e-mail">'
                 f'{addr}</EmailMessageObj:{tag}>')
    else:  # Mail-to / Mail-cc → a Recipient under To/CC
        tag = {"Mail-to": "To", "Mail-cc": "CC"}[type_]
        inner = (f'<EmailMessageObj:{tag}><EmailMessageObj:Recipient '
                 f'xsi:type="AddressObj:AddressObjectType" category="e-mail">{addr}'
                 f'</EmailMessageObj:Recipient></EmailMessageObj:{tag}>')
    return ('<cybox:Properties xsi:type="EmailMessageObj:EmailMessageObjectType">'
            f'<EmailMessageObj:Header>{inner}</EmailMessageObj:Header></cybox:Properties>')


def render_stix(feed) -> tuple[str, str]:
    """Return (xml, media_type) for the feed's indicators as a STIX 1.x Observables package."""
    ns = " ".join(f'xmlns:{prefix}="{uri}"' for prefix, uri in _NS.items())
    observables = []
    for i, ind in enumerate(feed.content.get("indicators", []), 1):
        props = _properties(ind["type"], ind["value"])
        observables.append(
            f'    <cybox:Observable id="dcsim:observable-{i}">'
            f'<cybox:Object id="dcsim:object-{i}">{props}</cybox:Object></cybox:Observable>')
    body = "\n".join(observables)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<stix:STIX_Package {ns} id="dcsim:package-{escape(feed.token)}" version="1.1.1">\n'
        '  <stix:Observables cybox_major_version="2" cybox_minor_version="1">\n'
        f'{body}\n'
        '  </stix:Observables>\n'
        '</stix:STIX_Package>\n'
    )
    return xml, "application/xml"
