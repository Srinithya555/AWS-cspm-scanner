import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspm.rules.sg_rules import (
    check_admin_ports_open_to_world, check_database_ports_open_to_world,
    check_all_ports_open_to_world,
)
from cspm.models import Severity


def _sg(perms):
    return {"group_id": "sg-test", "group_name": "test", "ip_permissions": perms}


class TestAdminPorts:
    def test_flags_ssh_open_to_world(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_admin_ports_open_to_world([sg])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "SSH" in findings[0].title

    def test_flags_rdp_open_to_world(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_admin_ports_open_to_world([sg])
        assert len(findings) == 1
        assert "RDP" in findings[0].title

    def test_ssh_restricted_to_specific_cidr_not_flagged(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": ["10.0.0.0/24"], "ipv6_cidr_ranges": []}])
        assert check_admin_ports_open_to_world([sg]) == []

    def test_flags_via_ipv6_open_world(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_ranges": [], "ipv6_cidr_ranges": ["::/0"]}])
        findings = check_admin_ports_open_to_world([sg])
        assert len(findings) == 1

    def test_port_range_covering_ssh_flagged(self):
        """A wide port range (e.g. 0-1024) that happens to include port 22 should
        still trigger — RDP (3389) is outside this range so only SSH is flagged."""
        sg = _sg([{"ip_protocol": "tcp", "from_port": 0, "to_port": 1024, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_admin_ports_open_to_world([sg])
        assert len(findings) == 1
        assert "SSH" in findings[0].title


class TestDatabasePorts:
    def test_flags_postgres_open_to_world(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_database_ports_open_to_world([sg])
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_postgres_restricted_not_flagged(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_ranges": ["10.0.5.0/24"], "ipv6_cidr_ranges": []}])
        assert check_database_ports_open_to_world([sg]) == []


class TestAllPortsOpen:
    def test_flags_protocol_negative_one(self):
        sg = _sg([{"ip_protocol": "-1", "from_port": None, "to_port": None, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_all_ports_open_to_world([sg])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_flags_full_port_range(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 0, "to_port": 65535, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        findings = check_all_ports_open_to_world([sg])
        assert len(findings) == 1

    def test_specific_port_not_flagged(self):
        sg = _sg([{"ip_protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_ranges": ["0.0.0.0/0"], "ipv6_cidr_ranges": []}])
        assert check_all_ports_open_to_world([sg]) == []
