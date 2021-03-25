from mbctool import *
import pytest

def test_main():
    src = setup_src()
    
    b = get_behavior_by_id(src, 'attack-pattern--5a3611aa-4253-4302-b09e-02fe53a1af9d')
    assert b.type == 'attack-pattern' and b.id == 'attack-pattern--5a3611aa-4253-4302-b09e-02fe53a1af9d'

    m = get_malware_by_id(src, 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
    assert m.type == 'malware' and m.id == 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'
