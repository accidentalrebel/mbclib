from mbclib import *
import pytest
import subprocess
import json

bid = 'attack-pattern--295a3b88-2a7e-4bae-9c50-014fce6d5739'
eid = 'B0009.029'
mid = 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'

def test_lib():
    src = setup_src('./mbc-stix2/')

    b = get_behavior_by_id(src, bid)
    assert b.type == 'attack-pattern' and b.id == bid

    m = get_malware_by_id(src, mid)
    assert m.type == 'malware' and m.id == mid

    b = get_behavior_by_external_id(src, eid)
    assert b.type == 'attack-pattern' and b.id == 'attack-pattern--dd40dbb6-6220-4b7b-93e1-20fe081eb219'
        
    b = get_parent_behavior(src, b.id)
    assert b.type == 'attack-pattern' and b.id == 'attack-pattern--61eb90ad-4b2a-4d85-b264-7f248a05507d'
    
