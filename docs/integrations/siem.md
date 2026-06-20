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

_Fallback only if that Ports UI is unavailable_ — a **host-network** socat that binds the real host 5514
and forwards into the app's `docker_gwbridge` IP. See the exact, proven recipe in
**Troubleshooting → hop 3** below; prefer it over an overlay-attached sidecar, which can't reliably
catch external UDP.

**2. The host firewall** — open 5514 **and verify it actually took.** `ufw` can list a rule in
`ufw status` that was never loaded into the live firewall, so the port reads as "allowed" while every
external packet is silently dropped (this exact trap cost a full PoV — see Troubleshooting):
```bash
sudo ufw allow 5514/tcp
sudo ufw allow 5514/udp
sudo ufw status verbose
```
If `sudo ufw reload` ever reports *"Firewall not enabled"* while `status` says **active**, the rules
aren't live — run `sudo ufw disable && sudo ufw enable` to actually load them (`22/tcp` stays allowed,
so SSH survives).

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

## Troubleshooting — "packets reach the host but nothing shows on /siem"

This cost **hours** in a live PoV, so here is the full ladder and, up front, the cause that actually got
us: **a host firewall silently dropping the inbound UDP.** Not Docker, not ingress, not socat — the OS
firewall. Work the hops in order; each command tells you whether the packet survived that layer.

### The one symptom that points straight at it

**Every local test works, but real external traffic never appears.** If **Send test log**, a
`nc -u 127.0.0.1 5514` from the host, *and* a probe to the host's own public hostname all land on
`/siem` — but the actual gateway/SMS logs don't — then the receiver, parser, and forwarder are all
fine, and something is dropping **external** packets specifically. (Careful: a host sending to its *own*
public IP is routed over loopback internally, so that's still a local test — it does **not** exercise
the external path. Only a packet from another machine does.)

### The diagnostic ladder

**1 — Does the packet reach the host NIC?**
```bash
sudo tcpdump -ni any 'udp and port 5514 and src <gateway-ip>'
```
Packets here mean the network and any cloud/edge firewall are fine. Crucially, `tcpdump` taps **before**
the host firewall, so seeing them proves the packet *arrived*, **not** that it was delivered to a
socket. Nothing here → look upstream: cloud security group / NSG / CloudShare edge, or the gateway
isn't actually sending.

**2 — Is the host firewall dropping it?  ← this was the cause**
```bash
sudo iptables -S INPUT
sudo ufw status verbose
```
The trap: a default `-P INPUT DROP` with an early `-A INPUT -i lo -j ACCEPT`. **Loopback takes that
fast-path and is accepted unconditionally; external traffic skips it and slams into the DROP.** That is
exactly the "local works, external doesn't" split.

And `ufw` can *lie*: `ufw status` reports **active** and lists `5514/udp ALLOW`, while `ufw reload` says
**"Firewall not enabled."** That contradiction means ufw's configured allows were **never loaded into
the live `INPUT` chain** — the port reads as allowed but is silently dropped. Any rule added while ufw
was in this zombie state is config-only — that includes **9440 for the Nutanix mock** and anything else
you opened recently.

**Fix — repair ufw so every configured allow actually loads (and survives reboot):**
```bash
sudo ufw disable && sudo ufw enable
```
`22/tcp` stays allowed, so your SSH session survives the re-enable. Need a quick, non-persistent unblock
without touching ufw:
```bash
sudo iptables -I INPUT -p udp --dport 5514 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 5514 -j ACCEPT
```
While you're here, rule out the rarer culprits (both were *empty* in our case, i.e. **not** the
problem): `sudo iptables -t nat -S | grep 5514` (a stale DNAT to a dead container hijacks external
traffic) and `sudo cat /proc/net/ip_vs` (a Swarm **ingress** IPVS service on the port — empty = good).

**The second firewall on hardened hosts — `DOCKER-USER`.** `INPUT` governs host-local traffic; Docker's
`DOCKER-USER` chain governs traffic **forwarded to containers**, and a locked-down host may carry a
deliberate deny-by-default rule there (often planted in `/etc/ufw/after.rules`):
```bash
sudo iptables -S DOCKER-USER
```
```
-A DOCKER-USER -i vlan.9 -p tcp --dport 443 -j RETURN     (plus a few other allowed ports)
-A DOCKER-USER -i vlan.9 -j DROP                          (everything else to containers: dropped)
```
If 5514 isn't on that allow-list, **every external packet forwarded to a container on 5514 is dropped**
— and that means **host-mode publish cannot work here either**, because a directly-published container
port still sits behind this FORWARD-chain DROP. The host-network socat in hop 3 is the only way past it:
it receives on the *host* (INPUT) and forwards host→container, so it never takes the `vlan.9→container`
path this rule guards — and it leaves the lockdown untouched. One more landmine: if a botched edit left
a stray heredoc delimiter (e.g. a lone `AFTEROF` line) **after** `COMMIT` in `after.rules`,
`iptables-restore` fails and `ufw` silently won't enable (`ufw status` says active, `ufw reload` says
*"not enabled"*). Remove the stray line, then `sudo ufw enable`.

**3 — Does it reach the host's 5514 and get into the container?**

Syslog is **not HTTP**, so it never touches Traefik/Caddy on 443 — it must reach the app's **own** 5514
listener. On Dokploy/Swarm the app sits on an overlay network whose IP the host can't route to, so
something must bridge **host:5514 → the container**. Two ways:

- **Host-mode publish (cleanest).** Dokploy → app → **Ports**: two entries, `5514`→`5514`, one **TCP**
  one **UDP**, **Publish Mode = `host`** (*not* the default **Ingress** — ingress SNATs the source and
  is flaky for UDP). Host mode binds the node's port straight to the task, handles UDP, and **preserves
  the gateway's real source IP**. Check the owner: `sudo ss -lunp | grep 5514` → `docker-proxy` is good,
  `dockerd` means you're still on ingress. **But** if the host has a `DOCKER-USER` lockdown (hop 2), this
  won't work — the published container port is still behind that FORWARD DROP; use the socat below.

- **Host-network socat (the proven fallback).** A `--network host` socat binds the *real* host 5514 (so
  it sees external packets natively, exactly like `tcpdump` does) and forwards to the app's
  **`docker_gwbridge` IP** — the one container address the host *can* reach (the overlay `eth0` IP can't
  be reached from the host; the `172.x` `eth1` can):
  ```bash
  APP=$(docker ps --filter name=dcsim --format '{{.Names}}' | head -1)
  PID=$(docker inspect "$APP" --format '{{.State.Pid}}')
  GW=$(sudo nsenter -t "$PID" -n ip -4 -o addr show | grep -oE '172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+' | head -1)
  echo "forwarding host:5514 to app at $GW"
  docker rm -f siem-host-udp siem-host-tcp 2>/dev/null
  docker run -d --name siem-host-udp --restart unless-stopped --network host alpine/socat UDP-LISTEN:5514,fork,reuseaddr "UDP:$GW:5514"
  docker run -d --name siem-host-tcp --restart unless-stopped --network host alpine/socat TCP-LISTEN:5514,fork,reuseaddr "TCP:$GW:5514"
  ```
  `nsenter … ip addr` runs the *host's* `ip` inside the container's namespace, because the slim app
  image has no `ip` binary. This whole block is packaged as **`tools/siem-host-socat.sh`** — run
  `sudo tools/siem-host-socat.sh` once after each deploy. Two caveats: the gwbridge IP **changes on
  every redeploy** (hence re-running the script), and the app sees the socat host's bridge address as
  the source — so the `/siem` *Source* column won't show the true gateway IP (only host-mode publish
  preserves that).

**4 — Does it reach the app inside the container, and is the app listening?**
```bash
PID=$(docker inspect "$APP" --format '{{.State.Pid}}')
sudo nsenter -t "$PID" -n tcpdump -ni eth0 udp port 5514
docker exec "$APP" sh -c 'grep 158A /proc/net/udp || echo NOT-LISTENING'
```
`158A` is hex for 5514. If the socket line shows but packets never arrive at `eth0`, the problem is
hop 2 or 3 above. If packets arrive but `/siem` stays at 0 *and* it prints `NOT-LISTENING`, set
`DCSIM_SYSLOG_PORT=5514` in the app's environment and redeploy. (The green **Listening** badge only
means the port is *configured*; a bind failure is logged to stderr and the app keeps running without
the receiver.)

> **The lesson, in one line:** when external-only traffic vanishes while every local/loopback test
> works, suspect the **host firewall first** — `sudo iptables -S INPUT` for a `DROP` policy, and the
> `ufw status` (active) vs `ufw reload` ("not enabled") contradiction — *before* you touch Docker
> networking, ingress, or socat. And remember `tcpdump` at the NIC proves arrival, never delivery.
