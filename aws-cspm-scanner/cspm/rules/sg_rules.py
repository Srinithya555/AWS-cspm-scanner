"""
Security Group checks on normalized data:

    security_groups: [
        {
            "group_id": str,
            "group_name": str,
            "ip_permissions": [
                {
                    "ip_protocol": str,      # "tcp" | "udp" | "-1" (all)
                    "from_port": int|None,   # None when protocol is "-1"
                    "to_port": int|None,
                    "cidr_ranges": [str,...],   # IPv4 CIDRs, e.g. "0.0.0.0/0"
                    "ipv6_cidr_ranges": [str,...],  # e.g. "::/0"
                },
                ...
            ],
        },
        ...
    ]
"""
from cspm.models import Finding, Severity

SENSITIVE_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
DATABASE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
}
OPEN_WORLD_CIDRS = {"0.0.0.0/0"}
OPEN_WORLD_CIDRS_V6 = {"::/0"}


def _port_in_range(port: int, from_port, to_port) -> bool:
    if from_port is None or to_port is None:
        return True  # protocol -1 (all traffic) covers all ports
    return from_port <= port <= to_port


def _has_open_world_cidr(perm: dict) -> bool:
    return bool(set(perm.get("cidr_ranges", [])) & OPEN_WORLD_CIDRS) or \
           bool(set(perm.get("ipv6_cidr_ranges", [])) & OPEN_WORLD_CIDRS_V6)


def check_admin_ports_open_to_world(sgs: list) -> list:
    findings = []
    for sg in sgs:
        for perm in sg.get("ip_permissions", []):
            if not _has_open_world_cidr(perm):
                continue
            for port, name in SENSITIVE_ADMIN_PORTS.items():
                if _port_in_range(port, perm.get("from_port"), perm.get("to_port")):
                    findings.append(Finding(
                        resource_type="security_group", resource_id=sg["group_id"], rule_id="SG-001",
                        severity=Severity.CRITICAL,
                        title=f"{name} (port {port}) open to the entire internet",
                        description=f"Security group '{sg['group_id']}' ({sg.get('group_name', '')}) "
                                     f"allows {name} from 0.0.0.0/0 or ::/0. This is one of the most "
                                     "common initial-access vectors in real breaches — automated "
                                     "scanners find and brute-force these within minutes of exposure.",
                        remediation=f"Restrict {name} access to specific known IP ranges (office VPN, "
                                     "bastion host) or remove direct exposure entirely in favor of "
                                     "Session Manager / a VPN.",
                        cis_reference="CIS AWS Foundations Benchmark 5.2/5.3-equivalent (verify version)",
                    ))
    return findings


def check_database_ports_open_to_world(sgs: list) -> list:
    findings = []
    for sg in sgs:
        for perm in sg.get("ip_permissions", []):
            if not _has_open_world_cidr(perm):
                continue
            for port, name in DATABASE_PORTS.items():
                if _port_in_range(port, perm.get("from_port"), perm.get("to_port")):
                    findings.append(Finding(
                        resource_type="security_group", resource_id=sg["group_id"], rule_id="SG-002",
                        severity=Severity.HIGH,
                        title=f"{name} (port {port}) open to the entire internet",
                        description=f"Security group '{sg['group_id']}' allows direct internet "
                                     f"access to a {name} port. Databases should never be directly "
                                     "internet-reachable — access should go through an application "
                                     "layer or a bastion/VPN.",
                        remediation="Restrict to the application tier's security group only; remove public CIDR ranges.",
                        cis_reference="General AWS security best practice (not a specific CIS numbered control)",
                    ))
    return findings


def check_all_ports_open_to_world(sgs: list) -> list:
    findings = []
    for sg in sgs:
        for perm in sg.get("ip_permissions", []):
            if not _has_open_world_cidr(perm):
                continue
            protocol = str(perm.get("ip_protocol", ""))
            from_port, to_port = perm.get("from_port"), perm.get("to_port")
            is_all_protocols = protocol == "-1"
            is_full_port_range = from_port == 0 and to_port == 65535
            if is_all_protocols or is_full_port_range:
                findings.append(Finding(
                    resource_type="security_group", resource_id=sg["group_id"], rule_id="SG-003",
                    severity=Severity.CRITICAL,
                    title="All ports/protocols open to the entire internet",
                    description=f"Security group '{sg['group_id']}' allows ALL traffic "
                                 "(any port, any protocol) from 0.0.0.0/0 or ::/0 — every "
                                 "service on any instance using this group is directly exposed.",
                    remediation="Replace with specific rules for only the ports/protocols actually needed.",
                    cis_reference="CIS AWS Foundations Benchmark 5.1-equivalent (verify version)",
                ))
    return findings


ALL_SG_RULES = [
    check_admin_ports_open_to_world,
    check_database_ports_open_to_world,
    check_all_ports_open_to_world,
]


def run_sg_rules(security_groups: list) -> list:
    findings = []
    for rule in ALL_SG_RULES:
        findings.extend(rule(security_groups))
    return findings
