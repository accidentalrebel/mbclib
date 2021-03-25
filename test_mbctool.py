from mbctool import *
import pytest
import subprocess
import json

bid = 'attack-pattern--295a3b88-2a7e-4bae-9c50-014fce6d5739'
eid = 'B0007'
mid = 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'

def test_main():
    src = setup_src()

    b = subprocess.check_output('./mbctool.py -i ' + bid, shell=True)
    b = json.loads(b)
    assert b['type'] == 'attack-pattern' and b['id'] == bid

    b = subprocess.check_output('./mbctool.py -e ' + eid, shell=True)
    b = json.loads(b)
    assert b['type'] == 'attack-pattern' and b['id'] == bid


def test_lib():
    src = setup_src()

    b = get_behavior_by_id(src, bid)
    assert b.type == 'attack-pattern' and b.id == bid

    m = get_malware_by_id(src, mid)
    assert m.type == 'malware' and m.id == mid
