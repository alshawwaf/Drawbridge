# SIEM receiver (Check Point Log Exporter sink)

A built-in receiver that accepts the logs Check Point's **Log Exporter** sends, so a PoV can prove
"gateway logs reach the SIEM" without standing up a real Splunk/QRadar. It's the one **reverse**
integration in the portal: Check Point connects *out* to us, instead of us serving data it polls.

## What it does

- Listens on **TCP and UDP** on `DCSIM_SYSLOG_PORT` (default `5514`), started in the app lifespan.
- Parses each line best-effort into structured fields — **CEF**, **LEEF**, **JSON**, or plain
  **syslog** (strips the `<PRI>` and RFC3164/5424 header) — and keeps the raw line too.
- Shows everything live at **`/siem`** (nav → **SIEM**): a format filter, a stats strip, and a
  click-through detail with the parsed fields + raw line. Retains the newest ~2000 lines.
- **Send test log** injects a sample Check Point CEF/JSON line so the viewer can be demoed before a
  gateway is pointed at it.

## Point Log Exporter here

On the Management Server (`cp_log_export`):

```
cp_log_export add name dcsim-siem \
  target-server <portal-host> target-port 5514 \
  protocol udp format cef
cp_log_export restart name dcsim-siem
```

`protocol tcp` and `format {syslog|leef|json}` work too. The exact command + host:port are shown on
the `/siem` page.

## Deployment

Syslog is **not HTTP**, so it does **not** go through Caddy. The bundled `docker-compose.yml`
publishes the port straight from the `app` container (host port = container port = `DCSIM_SYSLOG_PORT`):

```yaml
ports:
  - "${DCSIM_SYSLOG_PORT:-5514}:${DCSIM_SYSLOG_PORT:-5514}/udp"
  - "${DCSIM_SYSLOG_PORT:-5514}:${DCSIM_SYSLOG_PORT:-5514}/tcp"
```

On a Dokploy/Traefik host, add a TCP **and** UDP entrypoint for the port (or a `socat` passthrough),
the same way the Nutanix `9440` port is exposed. Set `DCSIM_SYSLOG_PORT=0` to disable the listener.

> A high port (5514) avoids needing root for the privileged 514. Plain syslog is unencrypted; Log
> Exporter's TLS option terminates at a real syslog/TLS endpoint, which this demo receiver doesn't do.
