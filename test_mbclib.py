from mbclib import *
import pytest
import subprocess
import json

oid = 'x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0'
bid = 'attack-pattern--295a3b88-2a7e-4bae-9c50-014fce6d5739'
eid = 'B0009.029'
mid = 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'

def test_lib():
    src = setup_src('./mbc-stix2/')

    assert len(get_all_objectives(src)) > 0
    assert len(get_all_behaviors(src)) > 0
    assert len(get_all_malwares(src)) > 0

    o = get_objective_by_id(src, oid)
    assert o.type == 'x-mitre-tactic' and o.id == oid

    o = get_objective_by_external_id(src, 'OC0001')
    assert o.type == 'x-mitre-tactic' and o.id == 'x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0'

    o = get_objective_by_external_id(src, 'OC0001')
    assert o.type == 'x-mitre-tactic' and o.id == 'x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0'

    o = get_objective_by_external_id(src, 'Oc0001')
    assert o.type == 'x-mitre-tactic' and o.id == 'x-mitre-tactic--0735bfd3-bffa-4476-9e3b-e33cc5c553e0'

    o = get_objective_by_shortname(src, 'anti-behavioral-analysis')
    assert o.type == 'x-mitre-tactic' and o.id == 'x-mitre-tactic--eb6166b0-f3c9-4124-aeb9-662941baa19e'
    
    b = get_behavior_by_id(src, bid)
    assert b.type == 'attack-pattern' and b.id == bid

    b = get_behavior_by_external_id(src, eid)
    assert b.type == 'attack-pattern' and b.id == 'attack-pattern--dd40dbb6-6220-4b7b-93e1-20fe081eb219'
        
    b = get_parent_behavior(src, b.id)
    assert b.type == 'attack-pattern' and b.id == 'attack-pattern--61eb90ad-4b2a-4d85-b264-7f248a05507d'

    assert get_mbc_external_id(b) == 'B0009'
    assert get_mbc_external_id(None) == None

    mals = get_malwares_using_behavior(src, 'attack-pattern--7981f82d-ff58-4d38-a420-69d73a67bbc9')
    for m in mals:
        assert m.type == 'malware' and m.id == 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa'

    behaviors = get_behaviors_under_objective(src, 'exfiltration')
    assert len(behaviors) > 0
    for b in behaviors:
        assert b.type == 'attack-pattern'

    hit_count = 0
    behaviors = get_children_of_behavior(src, 'attack-pattern--5146900f-415f-4817-9153-a9a3f857b3cd')
    assert len(behaviors) > 0
    for b in behaviors:
        assert b.type == 'attack-pattern'
        if b.id == 'attack-pattern--da7d23d7-ead0-4926-a7ee-be9ea77bb2cd':
            hit_count+=1
    assert hit_count == 1

    hit_count = 0
    for b in behaviors:
        assert b.type == 'attack-pattern' and b.x_mitre_is_subtechnique == True
        if b.id == 'attack-pattern--772c8a08-0dbb-4059-8459-7ac1193840bc':
            hit_count+=1
    assert hit_count == 1

    m = get_malware_by_id(src, mid)
    assert m.type == 'malware' and m.id == mid

    m = get_malware_by_external_id(src, 'X0014')
    assert m.type == 'malware' and m.id == 'malware--49b9796a-27fd-414e-a87d-b071aaff295b'

    


