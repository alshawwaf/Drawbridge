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

Set `DCSIM_SYSLOG_PORT=0` to disable the listener.

> A high port (5514) avoids needing root for the privileged 514. Plain syslog is unencrypted; Log
> Exporter's TLS option terminates at a real syslog/TLS endpoint, which this demo receiver doesn't do.

## Exposing 5514 end-to-end (Dokploy/Traefik + cloud edge)

> ⚠️ **This is *not* the Nutanix `socat 9440→443` trick.** Nutanix is HTTPS, so 9440 could piggyback
> on the already-published 443. Syslog is **raw** (and usually **UDP**) — 443 is the web server and
> can't parse it. The traffic must reach the app's **own 5514 listener**, and you need **both TCP and
> UDP**. Dokploy's Traefik only publishes HTTP/443, so 5514 has to be exposed explicitly — three layers,
> like Nutanix's 9440.

**1. Publish 5514 (TCP *and* UDP) from the app.** The app already listens on 5514 inside the container.
In Dokploy → your app → **Advanced → Ports → Create**, add an entry: **Published Port** `5514`,
**Target Port** `5514`, **Protocol** `TCP`, **Mode** `Host`. Then add a **second** entry, identical but
**Protocol** `UDP` (the dialog is one protocol at a time; Log Exporter commonly uses UDP). Choose
**Host** mode, *not* Ingress: Host publishes the port on the node, works reliably for UDP, and
**preserves the gateway's real source IP** so the SIEM page's *Source* column is meaningful. Ingress
routes through Swarm's mesh, which SNATs the source (every log shows the same mesh IP) and is flaky for
UDP. With this, **no socat is needed**.

_Fallback only if that Ports UI is unavailable_ — a socat sidecar **on the app's Docker network** (find
the names with `docker network ls` / `docker ps`) that publishes to the host and forwards to the **app
container's 5514**, never 443:

```bash
NET=<dokploy-app-network>; APP=<app-container-name>     # from docker network ls / docker ps
docker run -d --name dcsim-siem-tcp --restart unless-stopped --network "$NET" -p 5514:5514/tcp \
  alpine/socat TCP-LISTEN:5514,fork,reuseaddr "TCP:$APP:5514"
docker run -d --name dcsim-siem-udp --restart unless-stopped --network "$NET" -p 5514:5514/udp \
  alpine/socat UDP-LISTEN:5514,fork,reuseaddr "UDP:$APP:5514"
```

**2. The host firewall** (if `ufw` is active):
```bash
sudo ufw allow 5514/tcp
sudo ufw allow 5514/udp
```

**3. The cloud / CloudShare edge.** Open inbound **TCP 5514 *and* UDP 5514** at the same perimeter
where you opened 9440 (security group / NSG / CloudShare networking) — this is the layer that bites:
443 is forwarded there, 5514 stays dropped until you add it.

**Verify** from a host outside the VM's LAN:
```bash
printf '<134>CEF:0|Test|Test|1|1|probe|1|msg=hello\n' | nc -u -w1 <portal-host> 5514   # UDP
printf '<134>CEF:0|Test|Test|1|1|probe|1|msg=hello\n' | nc    -w1 <portal-host> 5514   # TCP
```
The line should appear on the **SIEM** page. No gateway handy? **Send test log** on that page exercises
the parser + viewer without any of the above.
