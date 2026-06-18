"""Live-mutation primitives for a Datacenter's simulated inventory.

CloudGuard **polls** its Data Center objects every ~30s, so to demo dynamic policy we don't push
anything to the gateway — we mutate the portal's stored ``content`` and the next scan re-resolves the
affected objects/rules live (that's the "change a tag → policy updates in ~30s" moment). These are
**pure, provider-aware** helpers over the ``content`` dict: each returns a NEW content dict (deep
copy) plus a human-readable description, so the caller does ``dc.content = new`` (which SQLAlchemy then
persists) and records what changed. ``snapshot``/``restore`` back the one-click "reset to baseline".

Tag model differs by provider — most carry a flat ``tags`` list of strings (NSX-T uses ``scope=value``
strings), while Kubernetes uses a ``labels`` map and Nutanix a ``categories`` map (both ``key=value``).
"""
import copy

# content key holding the workloads (VMs / pods / instances) for each provider
_WORKLOAD_KEY = {
    "openstack": "instances", "vcenter": "vms", "nsxt": "vms", "globalnsxt": "vms",
    "proxmox": "vms", "kubernetes": "pods", "nutanix": "vms",
}
# how each provider stores a workload's tags
_TAG_FIELD = {
    "openstack": "tags", "vcenter": "tags", "nsxt": "tags", "globalnsxt": "tags",
    "proxmox": "tags", "kubernetes": "labels", "nutanix": "categories",
}
# providers whose tags are a key=value map (vs a flat list of strings)
_DICT_TAGS = {"kubernetes", "nutanix"}


def workload_key(provider: str) -> str:
    return _WORKLOAD_KEY.get(provider, "vms")


def _singular(provider: str) -> str:
    return {"instances": "instance", "pods": "pod"}.get(workload_key(provider), "VM")


def supports_tags(provider: str) -> bool:
    """True for providers whose workloads carry tags/labels/categories (i.e. taggable for a flip)."""
    return provider in _TAG_FIELD


def tag_field(provider: str) -> str | None:
    """The content field a provider stores tags in: ``tags`` (list), ``labels`` or ``categories`` (map)."""
    return _TAG_FIELD.get(provider)


def is_map_tags(provider: str) -> bool:
    """True if this provider's tags are a ``key=value`` map (Kubernetes labels, Nutanix categories)."""
    return provider in _DICT_TAGS


def workloads(provider: str, content: dict) -> list[dict]:
    return (content or {}).get(workload_key(provider), []) or []


def workload_names(provider: str, content: dict) -> list[str]:
    return [w.get("name") for w in workloads(provider, content) if w.get("name")]


def _clone(content: dict) -> dict:
    return copy.deepcopy(content or {})


def _find(provider: str, content: dict, name: str) -> dict | None:
    return next((w for w in workloads(provider, content) if w.get("name") == name), None)


def add_tag(provider: str, content: dict, name: str, tag: str) -> tuple[dict, str]:
    """Tag a workload (the headline mutation). ``tag`` is a bare string for list-tag providers, or
    ``key=value`` for Kubernetes/Nutanix. Idempotent."""
    if not supports_tags(provider):
        raise ValueError(f"{provider!r} workloads aren't taggable")
    c = _clone(content)
    w = _find(provider, c, name)
    if w is None:
        raise ValueError(f"no {_singular(provider)} named {name!r}")
    field = _TAG_FIELD[provider]
    if provider in _DICT_TAGS:
        if "=" not in tag:
            raise ValueError(f"{provider} tag must be key=value, got {tag!r}")
        key, _, value = tag.partition("=")
        w.setdefault(field, {})[key.strip()] = value.strip()
    else:
        lst = w.setdefault(field, [])
        if tag not in lst:
            lst.append(tag)
    return c, f"tagged {name} with {tag}"


def remove_tag(provider: str, content: dict, name: str, tag: str) -> tuple[dict, str]:
    """Remove a tag from a workload. For map tags, ``tag`` may be ``key`` or ``key=value`` — the key
    is what's removed. No-op if the tag isn't present."""
    if not supports_tags(provider):
        raise ValueError(f"{provider!r} workloads aren't taggable")
    c = _clone(content)
    w = _find(provider, c, name)
    if w is None:
        raise ValueError(f"no {_singular(provider)} named {name!r}")
    field = _TAG_FIELD[provider]
    if provider in _DICT_TAGS:
        (w.get(field) or {}).pop(tag.partition("=")[0].strip(), None)
    elif tag in (w.get(field) or []):
        w[field].remove(tag)
    return c, f"removed tag {tag} from {name}"


def add_workload(provider: str, content: dict, name: str, ip: str,
                 tags: list[str] | None = None) -> tuple[dict, str]:
    """Add a VM/pod/instance (scale-out). ``tags`` are applied in the provider's tag style."""
    c = _clone(content)
    lst = c.setdefault(workload_key(provider), [])
    if any(w.get("name") == name for w in lst):
        raise ValueError(f"{_singular(provider)} {name!r} already exists")
    w: dict = {"name": name, "ip": ip}
    if provider == "kubernetes":
        w["namespace"] = "default"
    field = _TAG_FIELD.get(provider)
    if tags and field:
        if provider in _DICT_TAGS:
            w[field] = {k.strip(): v.strip() for k, _, v in (t.partition("=") for t in tags) if k.strip()}
        else:
            w[field] = list(tags)
    lst.append(w)
    return c, f"added {_singular(provider)} {name} ({ip})"


def remove_workload(provider: str, content: dict, name: str) -> tuple[dict, str]:
    """Remove a VM/pod/instance (scale-in)."""
    c = _clone(content)
    key = workload_key(provider)
    kept = [w for w in (c.get(key) or []) if w.get("name") != name]
    if len(kept) == len(c.get(key) or []):
        raise ValueError(f"no {_singular(provider)} named {name!r}")
    c[key] = kept
    return c, f"removed {_singular(provider)} {name}"


def apply_action(provider: str, content: dict, action: str, *,
                 name: str = "", value: str = "", ip: str = "") -> tuple[dict, str]:
    """Dispatch one mutation by name — the single entry point shared by the control panel and the
    timed runner. Raises ValueError on an unknown action or an invalid target."""
    name, value, ip = name.strip(), value.strip(), ip.strip()
    if action == "add_tag":
        return add_tag(provider, content, name, value)
    if action == "remove_tag":
        return remove_tag(provider, content, name, value)
    if action == "add_workload":
        return add_workload(provider, content, name, ip, [value] if value else None)
    if action == "remove_workload":
        return remove_workload(provider, content, name)
    raise ValueError(f"unknown action {action!r}")


# ── Named presets ─────────────────────────────────────────────────────────────────────────────────
# A preset expands (against the DC's current inventory) into an ordered list of steps the runner
# applies — one per "tick" so each lands in a separate ~30s scan. Keys are stable; labels are UI text.
_PRESET_LABELS = {
    "quarantine": "Quarantine the first workload",
    "scale_out": "Scale out (+3 workloads)",
    "blocklist": "Blocklist every workload",
}


def _tag_literal(provider: str, word: str) -> str:
    """A tag in the provider's style: bare ``word`` for list tags, ``word=true`` for map tags."""
    return f"{word}=true" if is_map_tags(provider) else word


def _gen_names(provider: str, content: dict, n: int, stem: str) -> list[str]:
    existing = {w.get("name") for w in workloads(provider, content)}
    out: list[str] = []
    i = 1
    while len(out) < n:
        cand = f"{stem}-{i}"
        i += 1
        if cand not in existing and cand not in out:
            out.append(cand)
    return out


def _gen_ips(provider: str, content: dict, n: int) -> list[str]:
    """Pick ``n`` free IPs in the /24 of an existing workload (or 10.99.0.0/24), high in the range."""
    existing = {w.get("ip") for w in workloads(provider, content)}
    prefix = "10.99.0"
    for w in workloads(provider, content):
        parts = (w.get("ip") or "").split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            prefix = ".".join(parts[:3])
            break
    out: list[str] = []
    host = 201
    while len(out) < n and host < 255:
        cand = f"{prefix}.{host}"
        host += 1
        if cand not in existing:
            out.append(cand)
    return out


def plan_preset(key: str, provider: str, content: dict) -> tuple[str, list[dict]]:
    """Expand a named preset into ordered steps for the current inventory. Returns (label, steps);
    each step is ``{action, name, value?, ip?, desc}``. Raises ValueError if it can't apply."""
    if not supports_tags(provider):
        raise ValueError(f"presets aren't available for {provider!r}")
    wls = workloads(provider, content)
    if key == "quarantine":
        if not wls:
            raise ValueError("no workloads to quarantine")
        w = wls[0]
        tag = _tag_literal(provider, "quarantine")
        return _PRESET_LABELS[key], [
            {"action": "add_tag", "name": w["name"], "value": tag, "desc": f"quarantine {w['name']}"}]
    if key == "blocklist":
        if not wls:
            raise ValueError("no workloads to blocklist")
        tag = _tag_literal(provider, "blocklist")
        return _PRESET_LABELS[key], [
            {"action": "add_tag", "name": w["name"], "value": tag, "desc": f"blocklist {w['name']}"}
            for w in wls]
    if key == "scale_out":
        stem = _singular(provider).lower()
        names = _gen_names(provider, content, 3, f"{stem}-scaleout")
        ips = _gen_ips(provider, content, 3)
        tag = _tag_literal(provider, "scaleout")
        return _PRESET_LABELS[key], [
            {"action": "add_workload", "name": nm, "ip": ip, "value": tag, "desc": f"add {stem} {nm} ({ip})"}
            for nm, ip in zip(names, ips)]
    raise ValueError(f"unknown preset {key!r}")


def list_presets(provider: str, content: dict) -> list[dict]:
    """Presets available for this DC, each ``{key, label, count}`` — count 0 means it can't run now
    (e.g. quarantine with no workloads), so the UI can disable it."""
    if not supports_tags(provider):
        return []
    out = []
    for key in ("quarantine", "scale_out", "blocklist"):
        try:
            label, steps = plan_preset(key, provider, content)
            out.append({"key": key, "label": label, "count": len(steps)})
        except ValueError:
            out.append({"key": key, "label": _PRESET_LABELS[key], "count": 0})
    return out


def snapshot(content: dict) -> dict:
    """A deep copy to stash as the baseline before a scenario runs."""
    return copy.deepcopy(content or {})


def restore(baseline: dict) -> dict:
    """The content to write back on 'reset to baseline'."""
    return copy.deepcopy(baseline or {})
