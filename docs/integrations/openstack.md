# OpenStack (Data Center mock)

Mocks an **OpenStack** cloud (Keystone v3 identity + Nova compute + Neutron networking) so
CloudGuard Controller imports **Instances**, **Security Groups**, and **Subnets**, with security
groups resolving to their member instances' IPs.

- Service: [`app/services/openstack.py`](../../app/services/openstack.py)
- Router: [`app/routers/openstack_mock.py`](../../app/routers/openstack_mock.py)

## Configure in SmartConsole

OpenStack's **Hostname** field accepts a **full URL with a path**, so this mock is **path-based**
(token in the URL) — you can run **many** OpenStack DCs per portal.

1. Portal → **Data Centers → New → OpenStack**. Add Instances (`name = ip | secgroup1, secgroup2`),
   Subnets (`name = cidr`), and any extra Security Groups. Set username / password / project. Save —
   the portal shows the Keystone URL to paste.
2. SmartConsole → **New → More → Server → Data Center → OpenStack**.
   - **Hostname / URL:** `https://<portal>/openstack/<token>/v3`
   - **Username / Password / Project (tenant):** the credentials you set on the portal DC.
3. **Test Connection**, then **Select objects** — Projects → Instances / Security Groups / Subnets.

## Endpoints served

All under `/openstack/{token}` (require `X-Auth-Token` except the version + token endpoints):

- **Keystone:** `GET /v3` (version), `POST /v3/auth/tokens` (validates creds → catalog pointing back
  at this portal's Nova/Neutron), `GET /v3/auth/projects`
- **Nova:** `GET /nova/v2.1/servers` and `…/servers/detail`
- **Neutron:** `GET /neutron/v2.0/{subnets,security-groups,networks,ports,floatingips}` plus a
  catch-all `…/neutron/v2.0/{resource}` → empty shape-correct list (so enumeration never 404-stalls)

## Object model

- **Instances** (`name = ip | sg1, sg2`) → Nova servers with `addresses` keyed by the network name.
- **Subnets** (`name = cidr`) → Neutron subnets.
- **Security Groups** — the union of the explicit list **plus** any group an instance joins (so a
  group an instance references always exists, and explicit groups can be empty).
- **Referential integrity is the whole game:** each instance gets a Neutron **port**
  (`device_id` → the server, `network_id` → the network, `fixed_ips.subnet_id` → the real subnet),
  and the port's `security_groups` carry the **same SG ids** the security-groups endpoint returns —
  so CloudGuard resolves each Security Group to its **member instances' IPs**.

Example with the defaults: `web-sg → web-1, web-2` · `db-sg → db-1` · `prod-sg → all three` ·
`mgmt-sg → (empty)`.

## Gotchas

- **"The Data Center is still initializing" with all 200s = a topology/referential-integrity bug,**
  not a missing endpoint. The controller fetched everything but couldn't assemble the object graph.
  Fixes that mattered: server `addresses` keyed by the **network name**; ports referencing a **real**
  `subnet_id` + `network_id` + `device_id`; `/v3/auth/projects` present; `floatingips` returns an
  empty list (not 404).
- An instance's `| …` list **is** its security-group membership (CloudGuard imports SGs, not Nova
  tags). After changing the model, **recreate** the DC object in SmartConsole.

## Testing

Portal **Activity log** (filter *Data Center*) shows every Keystone/Nova/Neutron call with bodies
(token masked). Confirmed working end-to-end in SmartConsole.
