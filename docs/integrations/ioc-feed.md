# IoC Feed (Custom Intelligence)

A **threat-intelligence** feed in any of Check Point's IoC formats (native CSV, STIX 1.x, Custom CSV,
or Snort). Unlike the Network Feed (dynamic
network objects) this drives **Threat Prevention** — the **Anti-Bot** and **Anti-Virus** blades fetch
the indicators and block matching traffic, so it unlocks the "feed → enforcement / auto-quarantine"
demo. CloudGuard/the gateway **polls** the URL on its configured interval.

- Public endpoint: [`app/routers/serve.py`](../../app/routers/serve.py) → `GET /ioc/<token>.csv`
- Validation + render: [`app/schemas/ioc.py`](../../app/schemas/ioc.py) · [`app/services/render.py`](../../app/services/render.py)
- Authoring UI: [`app/routers/ui.py`](../../app/routers/ui.py) · [`feed_new_ioc.html`](../../app/templates/feed_new_ioc.html)

## Use it

1. Portal → **New feed → IoC Feed**. Pick a **Feed format** (see below). For the indicator formats,
   enter indicators one per line in quick-entry form: `value, type[, confidence, severity, product,
   comment]` — only **value** and **type** are required, a unique name is auto-assigned (`ioc-N`),
   `#` lines and blanks are ignored, and the trailing comment may contain commas. For **Snort**, paste
   rules instead.
2. (Optional) Add a **username/password** — IoC feeds authenticate with HTTP **Basic** auth
   (`ioc_feeds --user_name`, R81.20+). Leave blank for an open feed — the unguessable token in the
   URL is the guard.
3. Copy the feed URL. **In SmartConsole:** *Security Policies → Threat Prevention → Custom Policy →
   Custom Policy Tools → Indicators → New → New IoC Feed*. Paste the URL, set **Feed Format =
   Check Point format/STIX**, add the username/password if set, then **Install** the Threat Prevention
   policy. Matching traffic is then blocked by Anti-Bot / Anti-Virus.
4. Watch the live **poll log** on the feed page (and the full request/response in the
   [Activity log](../../app/routers/activity.py), kind *Feed poll*).

## Feed formats

The IoC feed serves one of the four formats sk132193 documents (the SmartConsole "Feed Format"
dropdown offers the same set). Pick it on the new-feed form; the served wire format and URL extension
follow:

| Format | What it serves | URL | Media type |
|---|---|---|---|
| **Check Point CSV** (`cp_csv`, default) | native CSV (below) | `…/ioc/<token>.csv` | `text/csv` |
| **STIX 1.x** (`stix_1.x`) | the same indicators as STIX/CybOX 2.1 XML | `…/ioc/<token>.xml` | `application/xml` |
| **Custom CSV** (`custom_csv`) | the indicators in a chosen delimiter/comment layout, + the matching `ioc_feeds add --format …` command on the feed page | `…/ioc/<token>.csv` | `text/csv` |
| **Snort** (`snort`) | Snort/IPS rules served verbatim (needs the **IPS** blade; ≤ 6000 rules) | `…/ioc/<token>.txt` | `text/plain` |

- **STIX 1.x** is emitted as an Observables-only package — one `cybox:Observable` per indicator with
  the per-type CybOX object (AddressObj for IP / IP Range, DomainNameObj, URIObj, FileObj hashes,
  EmailMessageObj for Mail-*). Confidence/severity are CSV concepts and are omitted (the gateway uses
  its profile/defaults). It's built to the CybOX 2.1 schema; **validate against your gateway** once
  connected — the parser is strict about namespaces/`xsi:type`, and the Mail-* encodings are
  best-effort.
- **Custom CSV** demonstrates the gateway's flexible parser: the portal serves the indicators in your
  delimiter (`,` `|` `;` tab) with your comment char, and the feed page shows the exact
  `ioc_feeds add --feed_file_type custom_csv --format [value:#2,type:#3,…] --delimiter … --comment …`
  command to ingest it.
- **Snort** stores rule lines (each must start with an action — `alert`, `drop`, `reject`, …) and
  serves them verbatim. Enforcement is governed by the Threat Prevention profile, not a feed action.

## The native "Check Point format" CSV

Comma-separated, one record per line. The first `#`-prefixed line is a **column header**; the parser
reads columns positionally. Metadata lines begin with `#!` (the portal emits `#! DESCRIPTION = …`);
plain `#` lines are comments. Column order:

```
UNIQ-NAME, VALUE, TYPE, CONFIDENCE, SEVERITY, PRODUCT, COMMENT
```

- **Mandatory:** UNIQ-NAME (unique), VALUE, TYPE. The rest may be empty.
- **TYPE** (exact tokens): `IP`, `IP Range`, `Domain`, `URL`, `MD5`, `SHA1`, `SHA256`,
  `Mail-subject`, `Mail-from`, `Mail-to`, `Mail-cc`, `Mail-reply-to`. (No CIDR/Network type — use a
  Network Feed for CIDR network objects.)
- **CONFIDENCE / SEVERITY:** `low`, `medium`, `high`, `critical` (blank → the gateway's default).
- **PRODUCT** = the Software Blade: `AV` (Anti-Virus) or `AB` (Anti-Bot). **COMMENT** is free text.

**PRODUCT must match the TYPE** (R81.20+) or the indicator silently won't load:

| Observable type | Blade(s) |
|---|---|
| `IP`, `IP Range` | `AB` (Anti-Bot) only |
| `MD5`, `SHA1`, `SHA256` | `AV` (Anti-Virus) only — Anti-Bot can't enforce hashes |
| `URL`, `Domain`, `Mail-*` | `AV` or `AB` |

Example served body:

```
#! DESCRIPTION = Demo threat-intel indicators
#UNIQ-NAME,VALUE,TYPE,CONFIDENCE,SEVERITY,PRODUCT,COMMENT
ioc-1,203.0.113.66,IP,high,high,AB,C2 beacon
ioc-2,198.51.100.10-198.51.100.40,IP Range,medium,high,AB,Known-bad range
ioc-3,malware-c2.example.com,Domain,high,critical,AB,Botnet C2
ioc-4,http://drive-by.example.net/payload,URL,medium,high,AV,Drive-by host
ioc-5,44d88612fea8a8f36de82e1278abb02f,MD5,high,high,AV,EICAR test file
```

(`44d8…b02f` is the EICAR test-file MD5 — a safe, well-known indicator for demos.) Fields containing
a comma (e.g. a COMMENT) are CSV-quoted so the feed round-trips.

## Validation

The portal validates each indicator before saving: the **type** is canonicalized case-insensitively;
**confidence/severity** must be a valid level or blank; **product** must be `AV`/`AB` and must match
the type's allowed blade (per the table above — so an `IP,…,AV` line is rejected at authoring time
rather than silently dropped on the gateway); and values get a light type check — hashes the right hex
length (MD5 32, SHA1 40, SHA256 64), `IP` a single IPv4/IPv6 address, `IP Range` a same-family
`start-end` with start ≤ end. URL/Domain/Mail-* are accepted as entered.

## Enforcement & caveats (from sk132193)

- **IP / IP Range enforcement is destination-only and stateless** (SecureXL deny-list). It is **not** a
  stateful Access-Control replacement: return traffic from a listed IP for an internally-initiated
  connection can also be dropped. For "block new inbound, allow internal-initiated + return", use a
  **Network Feed** object in the Access Control rulebase instead.
- **URL** observables require the **HTTPS Inspection** blade to match inside encrypted traffic.
- **Hashes** (MD5/SHA1/SHA256) require **Anti-Virus**; Anti-Bot can't enforce them.
- Verify on the gateway: `ioc_feeds add --feed_name X --transport https --resource <url> --test true`,
  then `ioc_search ip|hash|url|domain|mail <value>` to confirm an observable loaded.

## Test from a shell

```
curl -s https://<portal>/ioc/<token>.csv
curl -s -u "<user>:<password>" https://<portal>/ioc/<token>.csv   # if Basic auth is set
```
