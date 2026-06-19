"""Datacenter edit: the create forms are reused for editing, so content must serialize back to the
quick-entry text format and re-parse to the same inventory. Also covers the edit-mode credential
rules (blank keeps the stored secret, a new value replaces it, 'clear_creds' reverts to open)."""
from app.routers.datacenters import _dc_build_form, _dc_parse_edit, _edit_auth, _quick_set_secret
from app.services import dc_creds


class FakeDC:
    def __init__(self, provider, content, name="DC", description="d"):
        self.id, self.provider, self.content, self.name, self.description = 1, provider, content, name, description


INVENTORY = {
    "openstack": {"instances": [{"name": "web-1", "ip": "10.0.0.11", "tags": ["web-sg", "prod-sg"]}],
                  "subnets": [{"name": "app", "cidr": "10.0.0.0/24"}],
                  "security_groups": [{"name": "db-sg"}]},
    "vcenter": {"vms": [{"name": "vm-a", "ip": "10.0.0.5", "tags": ["web"], "power": "poweredOn", "guest_os": ""}]},
    "nsxt": {"vms": [{"name": "vmx", "ip": "10.10.20.5", "tags": ["tier=web"]}],
             "groups": [{"name": "G1", "member_tag": "tier=web", "tags": ["env=prod"]}]},
    "globalnsxt": {"vms": [{"name": "vmy", "ip": "10.10.20.6", "tags": ["tier=db"]}],
                   "groups": [{"name": "G2", "member_tag": "tier=db", "tags": []}]},
    "proxmox": {"vms": [{"name": "p1", "ip": "10.20.0.11", "tags": ["web"]}], "node": "pve2"},
    "aci": {"tenant": "T1", "app_profile": "AP1",
            "epgs": [{"name": "web-epg", "ips": ["10.30.0.11", "10.30.0.12"]}],
            "esgs": [{"name": "prod-esg", "ips": ["10.30.0.11"]}]},
    "kubernetes": {"nodes": [{"name": "node-1", "ip": "10.40.0.11", "labels": {}}],
                   "pods": [{"namespace": "production", "name": "web", "ip": "10.40.1.11", "labels": {"app": "web"}}],
                   "services": [{"namespace": "production", "name": "web-svc", "cluster_ip": "10.40.10.1", "type": "LoadBalancer"}]},
    "nutanix": {"vms": [{"name": "v1", "ip": "10.50.0.11", "categories": {"Environment": "Production", "AppType": "Web"}}]},
}


def test_every_provider_inventory_round_trips():
    """build_form (content → text) then parse (text → content) preserves the inventory for all types."""
    for provider, content in INVENTORY.items():
        dc = FakeDC(provider, dict(content))
        form = _dc_build_form(dc)                 # serialize to the create-form's text fields
        rebuilt = _dc_parse_edit(dc, form)        # the form dict doubles as the submitted raw form
        for key, original in content.items():
            assert rebuilt.get(key) == original, f"{provider}.{key} did not round-trip: {rebuilt.get(key)!r}"


def test_build_form_carries_name_and_username():
    dc = FakeDC("nutanix", {"vms": [{"name": "v", "ip": "1.1.1.1", "categories": {}}],
                            "auth": {"username": "operator", "password_enc": "v1.x"}}, name="My-NTX")
    form = _dc_build_form(dc)
    assert form["name"] == "My-NTX"
    assert form["nutanix_username"] == "operator"
    assert "nutanix_password" not in form  # the secret is never serialized back into the form


def _ntx(content):
    return FakeDC("nutanix", content)


def test_blank_password_keeps_stored_secret_and_refreshes_username():
    dc = _ntx({"vms": [], "auth": {"username": "old", "password_enc": "v1.KEEPME"}})
    content = {"vms": [{"name": "v", "ip": "1.1.1.1", "categories": {}}]}
    _edit_auth(content, dc, {"nutanix_username": "new", "nutanix_password": ""},
               identity={"nutanix_username": "username"}, secret_form="nutanix_password", secret_key="password")
    assert content["auth"]["password_enc"] == "v1.KEEPME"  # stored secret preserved
    assert content["auth"]["username"] == "new"            # identity refreshed from the form


def test_new_password_replaces_secret():
    dc = _ntx({"auth": {"username": "old", "password_enc": "v1.OLD"}})
    content = {"vms": []}
    _edit_auth(content, dc, {"nutanix_username": "u", "nutanix_password": "fresh"},
               identity={"nutanix_username": "username"}, secret_form="nutanix_password", secret_key="password")
    assert dc_creds.configured(content["auth"], "password")
    assert content["auth"]["username"] == "u"
    assert content["auth"].get("password_enc") != "v1.OLD"  # re-encrypted, not the old token


def test_clear_creds_reverts_to_open_lab():
    dc = _ntx({"auth": {"username": "old", "password_enc": "v1.OLD"}})
    content = {"vms": []}
    _edit_auth(content, dc, {"nutanix_username": "u", "nutanix_password": "", "clear_creds": "1"},
               identity={"nutanix_username": "username"}, secret_form="nutanix_password", secret_key="password")
    assert "auth" not in content  # credentials dropped → open mock


def test_blank_password_on_open_lab_stays_open():
    dc = _ntx({})  # no existing auth
    content = {"vms": []}
    _edit_auth(content, dc, {"nutanix_username": "admin", "nutanix_password": ""},
               identity={"nutanix_username": "username"}, secret_form="nutanix_password", secret_key="password")
    assert "auth" not in content


def test_kubernetes_has_no_credentials():
    dc = FakeDC("kubernetes", dict(INVENTORY["kubernetes"]))
    content = _dc_parse_edit(dc, _dc_build_form(dc))
    assert "auth" not in content  # K8s uses a generated SA token, never a stored secret


# --- inline quick-edit: setting/clearing the password keeps the auth block coherent ---

def test_quick_set_password_on_open_lab_seeds_default_identity():
    content = {"vms": []}  # open nutanix lab, no auth
    _quick_set_secret(content, "nutanix", "newpw", "password")
    assert content["auth"]["username"] == "admin"          # provider default seeded
    assert dc_creds.configured(content["auth"], "password")  # secret stored


def test_quick_set_password_preserves_openstack_project():
    content = {"instances": [], "auth": {"username": "osadmin", "project": "myproj", "password_enc": "v1.OLD"}}
    _quick_set_secret(content, "openstack", "rotated", "password")
    assert content["auth"]["username"] == "osadmin"   # existing identity kept
    assert content["auth"]["project"] == "myproj"     # OpenStack project survives a password change
    assert content["auth"].get("password_enc") != "v1.OLD"


def test_quick_set_password_seeds_proxmox_token_id():
    content = {"vms": []}
    _quick_set_secret(content, "proxmox", "tok", "secret")
    assert content["auth"]["token_id"] == "root@pam!cloudguard"
    assert dc_creds.configured(content["auth"], "secret")


def test_quick_clear_password_reverts_to_open_lab():
    content = {"vms": [], "auth": {"username": "admin", "password_enc": "v1.X"}}
    _quick_set_secret(content, "nutanix", "", "password")
    assert "auth" not in content
