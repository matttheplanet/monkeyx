"""CIDR-aware fleet sizing: a /16 in -t must size a bigger opening fleet than a
single IP (it used to count the whole range as ONE target, so multiple /16s only
booted ~3 nodes). count_ip_workload sums capped host-equivalents per range, and
compute_initial_nodes + the between-step scaler both use it so the fleet doesn't
inflate at init then shrink on step 1.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core import fleet


def test_count_cidr_vs_bare_ip():
    assert fleet.count_ip_workload(["1.2.3.4"]) == 1
    assert fleet.count_ip_workload(["10.0.0.0/24"]) == 256
    # /16 (65,536 hosts) is capped at the default CIDR_HOST_CAP, not counted whole
    assert fleet.count_ip_workload(["10.0.0.0/16"]) == fleet.CIDR_HOST_CAP
    assert fleet.count_ip_workload(["10.0.0.0/16", "1.2.3.4"]) == fleet.CIDR_HOST_CAP + 1


def test_count_cap_override_and_legacy():
    assert fleet.count_ip_workload(["10.0.0.0/16"], cidr_host_cap=256) == 256
    # cap<=0 -> legacy: every entry counts 1 (a CIDR == a single target)
    assert fleet.count_ip_workload(["10.0.0.0/16", "10.1.0.0/16"], cidr_host_cap=0) == 2


def test_count_unparseable_entry_counts_one():
    assert fleet.count_ip_workload(["garbage/99"]) == 1


def test_cidr_sizes_a_real_fleet(tmp_path):
    """A /16 scope should open far more than the 1 node a single IP would."""
    one_ip = tmp_path / "one.txt"
    one_ip.write_text("1.2.3.4\n")
    slash16 = tmp_path / "big.txt"
    slash16.write_text("10.0.0.0/16\n")

    n_one = fleet.compute_initial_nodes(target_file=str(one_ip), max_nodes=50)
    n_big = fleet.compute_initial_nodes(target_file=str(slash16), max_nodes=50)

    assert n_one == 1
    assert n_big > 1
    # ceil(1024 / 60) = 18 with the default cap + per-node ratio
    assert n_big == fleet.compute_optimal_nodes(fleet.CIDR_HOST_CAP)


def test_cidr_sizing_respects_max_nodes(tmp_path):
    many = tmp_path / "many.txt"
    many.write_text("10.1.0.0/16\n10.2.0.0/16\n10.3.0.0/16\n10.4.0.0/16\n")
    assert fleet.compute_initial_nodes(target_file=str(many), max_nodes=10) == 10
