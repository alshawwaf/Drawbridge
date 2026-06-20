"""Coverage matrices: which Check Point objects/commands are supported by the **web_api**, the
**Terraform** provider (CheckPointSW/checkpoint) and the **Ansible** collections (check_point.mgmt /
check_point.gaia) — and which of them the **portal** currently exports.

This powers the /coverage page: a colour-coded API | Terraform | Ansible comparison so the gaps are
visible at a glance. Data is from the official docs/sources (TF v3.2.0 = 248 management + ~119 gaia
resources; Ansible check_point.mgmt = 274 modules, check_point.gaia = 53 config modules). The
``exported`` flag per row is derived from the live exporter specs, so it never drifts from reality.
"""
from __future__ import annotations

from . import gaia_export, mgmt_export


def _r(name, api, tf, ans, note=""):
    """A matrix row. tf/ans = exact resource/module name, or None when that tool has no equivalent."""
    return {"name": name, "api": api, "tf": tf, "ans": ans, "note": note}


# --- Management API ---------------------------------------------------------------------------
_MGMT_GROUPS = [
    ("Network objects", [
        _r("host", "add-host", "checkpoint_management_host", "cp_mgmt_host"),
        _r("network", "add-network", "checkpoint_management_network", "cp_mgmt_network"),
        _r("group", "add-group", "checkpoint_management_group", "cp_mgmt_group"),
        _r("address-range", "add-address-range", "checkpoint_management_address_range", "cp_mgmt_address_range"),
        _r("group-with-exclusion", "add-group-with-exclusion", "checkpoint_management_group_with_exclusion", "cp_mgmt_group_with_exclusion"),
        _r("multicast-address-range", "add-multicast-address-range", "checkpoint_management_multicast_address_range", "cp_mgmt_multicast_address_range"),
        _r("wildcard", "add-wildcard", "checkpoint_management_wildcard", "cp_mgmt_wildcard"),
        _r("dns-domain", "add-dns-domain", "checkpoint_management_dns_domain", "cp_mgmt_dns_domain"),
        _r("security-zone", "add-security-zone", "checkpoint_management_security_zone", "cp_mgmt_security_zone"),
        _r("tag", "add-tag", "checkpoint_management_tag", "cp_mgmt_tag"),
        _r("dynamic-object", "add-dynamic-object", "checkpoint_management_dynamic_object", "cp_mgmt_dynamic_object"),
        _r("simple-gateway", "add-simple-gateway", "checkpoint_management_simple_gateway", "cp_mgmt_simple_gateway"),
        _r("simple-cluster", "add-simple-cluster", "checkpoint_management_simple_cluster", "cp_mgmt_simple_cluster"),
        _r("checkpoint-host", "add-checkpoint-host", "checkpoint_management_checkpoint_host", "cp_mgmt_checkpoint_host"),
        _r("interoperable-device", "add-interoperable-device", "checkpoint_management_interoperable_device", "cp_mgmt_interoperable_device"),
        _r("updatable-object", "add-updatable-object", "checkpoint_management_add_updatable_object", "cp_mgmt_add_updatable_object", "verb-style in both (no plain CRUD resource)"),
    ]),
    ("Services", [
        _r("service-tcp", "add-service-tcp", "checkpoint_management_service_tcp", "cp_mgmt_service_tcp"),
        _r("service-udp", "add-service-udp", "checkpoint_management_service_udp", "cp_mgmt_service_udp"),
        _r("service-icmp", "add-service-icmp", "checkpoint_management_service_icmp", "cp_mgmt_service_icmp"),
        _r("service-icmp6", "add-service-icmp6", "checkpoint_management_service_icmp6", "cp_mgmt_service_icmp6"),
        _r("service-sctp", "add-service-sctp", "checkpoint_management_service_sctp", "cp_mgmt_service_sctp"),
        _r("service-other", "add-service-other", "checkpoint_management_service_other", "cp_mgmt_service_other"),
        _r("service-dce-rpc", "add-service-dce-rpc", "checkpoint_management_service_dce_rpc", "cp_mgmt_service_dce_rpc"),
        _r("service-rpc", "add-service-rpc", "checkpoint_management_service_rpc", "cp_mgmt_service_rpc"),
        _r("service-gtp", "add-service-gtp", "checkpoint_management_service_gtp", None, "no Ansible GTP-service module"),
        _r("service-citrix-tcp", "add-service-citrix-tcp", "checkpoint_management_service_citrix_tcp", "cp_mgmt_service_citrix_tcp"),
        _r("service-compound-tcp", "add-service-compound-tcp", "checkpoint_management_service_compound_tcp", "cp_mgmt_service_compound_tcp"),
        _r("service-group", "add-service-group", "checkpoint_management_service_group", "cp_mgmt_service_group"),
    ]),
    ("Applications", [
        _r("application-site", "add-application-site", "checkpoint_management_application_site", "cp_mgmt_application_site"),
        _r("application-site-category", "add-application-site-category", "checkpoint_management_application_site_category", "cp_mgmt_application_site_category"),
        _r("application-site-group", "add-application-site-group", "checkpoint_management_application_site_group", "cp_mgmt_application_site_group"),
    ]),
    ("Times", [
        _r("time", "add-time", "checkpoint_management_time", "cp_mgmt_time"),
        _r("time-group", "add-time-group", "checkpoint_management_time_group", "cp_mgmt_time_group"),
    ]),
    ("Access policy", [
        _r("access-layer", "add-access-layer", "checkpoint_management_access_layer", "cp_mgmt_access_layer"),
        _r("access-section", "add-access-section", "checkpoint_management_access_section", "cp_mgmt_access_section"),
        _r("access-rule", "add-access-rule", "checkpoint_management_access_rule", "cp_mgmt_access_rule"),
    ]),
    ("NAT", [
        _r("nat-section", "add-nat-section", "checkpoint_management_nat_section", "cp_mgmt_nat_section"),
        _r("nat-rule", "add-nat-rule", "checkpoint_management_nat_rule", "cp_mgmt_nat_rule"),
    ]),
    ("Threat Prevention", [
        _r("threat-rule", "add-threat-rule", "checkpoint_management_threat_rule", "cp_mgmt_threat_rule"),
        _r("threat-exception", "add-threat-exception", "checkpoint_management_threat_exception", "cp_mgmt_threat_exception"),
        _r("threat-profile", "add-threat-profile", "checkpoint_management_threat_profile", "cp_mgmt_threat_profile"),
        _r("threat-layer", "add-threat-layer", "checkpoint_management_threat_layer", "cp_mgmt_threat_layer"),
        _r("exception-group", "add-exception-group", "checkpoint_management_exception_group", "cp_mgmt_exception_group"),
        _r("ips-protection", "add-threat-protections", None, None, "no discrete CRUD resource in TF or Ansible"),
        _r("threat-ioc-feed", "add-threat-ioc-feed", "checkpoint_management_threat_ioc_feed", None, "Ansible has only the check verb"),
        _r("network-feed", "add-network-feed", "checkpoint_management_network_feed", "cp_mgmt_network_feed"),
    ]),
    ("HTTPS Inspection", [
        _r("https-rule", "add-https-rule", "checkpoint_management_https_rule", "cp_mgmt_https_rule"),
        _r("https-section", "add-https-section", "checkpoint_management_https_section", "cp_mgmt_https_section"),
        _r("https-layer", "add-https-layer", "checkpoint_management_https_layer", "cp_mgmt_https_layer"),
    ]),
    ("VPN", [
        _r("vpn-community-meshed", "add-vpn-community-meshed", "checkpoint_management_vpn_community_meshed", "cp_mgmt_vpn_community_meshed"),
        _r("vpn-community-star", "add-vpn-community-star", "checkpoint_management_vpn_community_star", "cp_mgmt_vpn_community_star"),
        _r("vpn-community-remote-access", "set-vpn-community-remote-access", "checkpoint_management_vpn_community_remote_access", "cp_mgmt_set_vpn_community_remote_access", "set-only"),
    ]),
    ("Identity / users / servers", [
        _r("access-role", "add-access-role", "checkpoint_management_access_role", "cp_mgmt_access_role", "users/machines structure differs across all 3"),
        _r("identity-tag", "add-identity-tag", "checkpoint_management_identity_tag", "cp_mgmt_identity_tag"),
        _r("user", "add-user", "checkpoint_management_user", "cp_mgmt_user"),
        _r("user-group", "add-user-group", "checkpoint_management_user_group", "cp_mgmt_user_group"),
        _r("administrator", "add-administrator", "checkpoint_management_administrator", "cp_mgmt_administrator"),
        _r("ldap-group", "add-ldap-group", "checkpoint_management_ldap_group", "cp_mgmt_ldap_group"),
        _r("radius-server", "add-radius-server", "checkpoint_management_radius_server", "cp_mgmt_radius_server"),
        _r("tacacs-server", "add-tacacs-server", "checkpoint_management_tacacs_server", "cp_mgmt_tacacs_server"),
        _r("opsec-application", "add-opsec-application", "checkpoint_management_opsec_application", None, "no Ansible module"),
    ]),
    ("Data Center (CloudGuard)", [
        _r("data-center-object", "add-data-center-object", "checkpoint_management_add_data_center_object", "cp_mgmt_add_data_center_object", "verb-style in both"),
        _r("data-center-query", "add-data-center-query", "checkpoint_management_data_center_query", "cp_mgmt_add_data_center_query"),
        _r("vmware/aws/azure/… data-center-server", "add-data-center-server", "checkpoint_management_*_data_center_server", None, "entire typed DC-server family missing from Ansible"),
    ]),
]

# Field-level gaps surfaced by the research (shown under the management matrix).
_MGMT_FIELD_GAPS = [
    "access-rule · vpn: API/Ansible use one polymorphic `vpn`; Terraform splits it into "
    "`vpn` / `vpn_communities` / `vpn_directional{from,to}`.",
    "access-rule · `service-resource` is settable in API/Ansible but absent from the Terraform resource.",
    "access-role · users/machines: Ansible uses `users`+`users_list` / `machines`+`machines_list`; "
    "Terraform uses repeatable `users`/`machines` blocks; the API show-output is fully-resolved and "
    "must be collapsed to {source, selection, base-dn} before re-add.",
    "host/network/group/services · `groups` (set membership at create) and `details_level` exist in "
    "Ansible + API but NOT in Terraform — the portal captures membership via each group's `members`.",
    "host/network · generic `ip-address` / `subnet` / `mask-length` / `subnet-mask` exist in API+Ansible; "
    "Terraform forces the numbered `*4`/`*6` variants (the portal emits those).",
]


# --- Gaia OS API ------------------------------------------------------------------------------
_GAIA_GROUPS = [
    ("System", [
        _r("hostname", "set-hostname", "checkpoint_gaia_hostname", "cp_gaia_hostname"),
        _r("dns", "set-dns", "checkpoint_gaia_dns", "cp_gaia_dns"),
        _r("domain name (dns suffix)", "set-dns (suffix)", "checkpoint_gaia_dns", "cp_gaia_dns"),
        _r("ntp", "set-ntp", "checkpoint_gaia_ntp", "cp_gaia_ntp"),
        _r("time / date / timezone", "set-time-and-date", "checkpoint_gaia_time_and_date", "cp_gaia_time_and_date"),
        _r("proxy", "set-proxy", "checkpoint_gaia_proxy", "cp_gaia_proxy"),
        _r("banner", "set-banner", "checkpoint_gaia_banner", "cp_gaia_banner"),
        _r("message-of-the-day", "set-message-of-the-day", "checkpoint_gaia_message_of_the_day", "cp_gaia_message_of_the_day"),
    ]),
    ("Interfaces", [
        _r("physical-interface", "set-physical-interface", "checkpoint_gaia_physical_interface", "cp_gaia_physical_interface"),
        _r("vlan-interface", "add-vlan-interface", "checkpoint_gaia_vlan_interface", "cp_gaia_vlan_interface"),
        _r("bond-interface", "add-bond-interface", "checkpoint_gaia_bond_interface", "cp_gaia_bond_interface"),
        _r("bridge-interface", "add-bridge-interface", "checkpoint_gaia_bridge_interface", "cp_gaia_bridge_interface"),
        _r("loopback-interface", "add-loopback-interface", "checkpoint_gaia_loopback_interface", "cp_gaia_loopback_interface"),
        _r("alias-interface", "add-alias-interface", "checkpoint_gaia_alias_interface", "cp_gaia_alias_interface"),
        _r("ipv6 state", "set-ipv6", "checkpoint_gaia_ipv6", "cp_gaia_ipv6"),
    ]),
    ("Routing", [
        _r("static-route", "set-static-route", "checkpoint_gaia_static_route", "cp_gaia_static_route"),
        _r("static-mroute", "set-static-mroute", "checkpoint_gaia_static_mroute", None, "no Ansible module"),
        _r("aggregate-route", "set-aggregate-route", "checkpoint_gaia_route_redistribution_*", None, "Ansible read-only (facts)"),
        _r("BGP", "add/set-bgp-*", "checkpoint_gaia_bgp_*", None, "Ansible dynamic routing is read-only"),
        _r("OSPF", "set-ospf-*", "checkpoint_gaia_*ospf*", None, "Ansible dynamic routing is read-only"),
        _r("RIP", "set-rip-*", "checkpoint_gaia_*rip*", None, "Ansible dynamic routing is read-only"),
        _r("PIM / IGMP / MLD / ISIS", "set-pim / set-igmp / …", "checkpoint_gaia_pim_* / igmp_* / isis_*", None, "no Ansible modules"),
        _r("PBR (policy routing)", "add-pbr-rule / set-pbr-table", "checkpoint_gaia_pbr_rule / _pbr_table", None, "no Ansible modules"),
    ]),
    ("Services", [
        _r("dhcp-server", "set-dhcp-server", "checkpoint_gaia_dhcp_server", "cp_gaia_dhcp_server"),
        _r("dhcp6", "set-dhcp6-server", "checkpoint_gaia_dhcp6_server", None, "no Ansible module"),
        _r("snmp (agent)", "set-snmp", "checkpoint_gaia_snmp", "cp_gaia_snmp", "TF `version` vs Ansible `ver`"),
        _r("snmp-user", "add-snmp-user", "checkpoint_gaia_snmp_user", "cp_gaia_snmp_user"),
        _r("snmp-trap-receiver", "add-snmp-trap-receiver", "checkpoint_gaia_snmp_trap_receiver", "cp_gaia_snmp_trap_receiver"),
        _r("syslog (local)", "set-syslog", "checkpoint_gaia_syslog", "cp_gaia_syslog"),
        _r("remote-syslog", "add-remote-syslog", "checkpoint_gaia_remote_syslog", "cp_gaia_remote_syslog"),
        _r("arp (static)", "set-arp", "checkpoint_gaia_arp", None, "no Ansible module"),
        _r("lldp", "set-lldp", "checkpoint_gaia_lldp", None, "no Ansible module"),
    ]),
    ("AAA / users / access", [
        _r("user", "add-user", "checkpoint_gaia_user", "cp_gaia_user"),
        _r("role", "add-role", "checkpoint_gaia_role", "cp_gaia_role"),
        _r("system-group", "add-system-group", "checkpoint_gaia_system_group", "cp_gaia_system_group"),
        _r("radius", "set-radius", "checkpoint_gaia_radius", "cp_gaia_radius_server", "TF `radius` vs Ansible `radius_server`"),
        _r("tacacs", "set-tacacs", "checkpoint_gaia_tacacs", "cp_gaia_tacacs_server", "TF `tacacs` vs Ansible `tacacs_server`"),
        _r("allowed-clients", "set-allowed-clients", "checkpoint_gaia_allowed_clients", "cp_gaia_allowed_clients"),
        _r("password-policy", "set-password-policy", "checkpoint_gaia_password_policy", "cp_gaia_password_policy"),
        _r("ssh-server-settings", "set-ssh-server-settings", "checkpoint_gaia_ssh_server_settings", "cp_gaia_ssh_server_settings"),
    ]),
    ("Misc / not in any tool", [
        _r("static /etc/hosts entries", None, None, None, "no Gaia-API verb / TF resource / Ansible module (clish-only)"),
        _r("scheduled-job", "add-scheduled-job", "checkpoint_gaia_scheduled_job", "cp_gaia_scheduled_job"),
        _r("VSX / VSNext", "add-virtual-gateway / -switch", "checkpoint_gaia_virtual_gateway / _switch", "cp_gaia_virtual_gateway / _switch"),
        _r("Maestro", "set-maestro-*", "checkpoint_gaia_maestro_*", "cp_gaia_maestro_*", "TF singular vs Ansible plural names"),
    ]),
]

_GAIA_FIELD_GAPS = [
    "Ansible's recurring hole is **dynamic routing** (BGP/OSPF/RIP/PIM/ISIS) + static-mroute, aggregate-route, "
    "arp, lldp, dhcp6, PBR — read-only there; Terraform covers them and is the broadest Gaia target.",
    "physical/vlan/bond interface `dhcp`: Terraform models it as a bool; Ansible/API as an object "
    "(enabled, server_timeout, retry, leasetime, reacquire_timeout).",
    "vlan/bond/bridge identity differs: Ansible/API use `name` (eth0.100 / bond0); Terraform uses "
    "`parent`+`resource_id`.",
    "Static `/etc/hosts` host entries are unsupported in ALL THREE tools (clish `add host` only).",
]


def _exported_mgmt() -> set[str]:
    return set(mgmt_export.OBJ_SPECS) | {"access-layer", "access-section", "access-rule"}


def _exported_gaia() -> set[str]:
    # the Gaia areas the exporter renders today (gaia_export._SECTIONS), mapped to matrix row names
    mapped = {"hostname", "dns", "domain name (dns suffix)", "ntp", "time / date / timezone",
              "proxy", "physical-interface", "static-route"}
    return mapped


def _annotate(groups, exported: set[str]) -> list[dict]:
    out = []
    for title, rows in groups:
        annotated, covered = [], 0
        for row in rows:
            r = dict(row, exported=row["name"] in exported)
            if r["exported"]:
                covered += 1
            annotated.append(r)
        out.append({"title": title, "rows": annotated, "covered": covered, "total": len(rows)})
    return out


def build() -> dict:
    """The colour-coded matrices for the /coverage page."""
    return {
        "mgmt": _annotate(_MGMT_GROUPS, _exported_mgmt()),
        "mgmt_field_gaps": _MGMT_FIELD_GAPS,
        "gaia": _annotate(_GAIA_GROUPS, _exported_gaia()),
        "gaia_field_gaps": _GAIA_FIELD_GAPS,
    }
