#!/usr/bin/env python3
from stix2 import Filter, FileSystemSource

g_src = None

def get_all_objectives():
    return g_src.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

def get_behaviors_by_external_id(external_id):
    return g_src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', external_id)
    ])

def get_behaviors_by_id(id):
    return g_src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', '=', id)
    ])

def get_malwares_by_id(id):
    return g_src.query([
        Filter('type', '=', 'malware'),
        Filter('id', '=', id)
    ])

def get_relationships_by(id, src_type, rel_type, target_type, is_reversed=False):
    relationship_lists = []
    relationships = g_src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type)
    ])
    for r in relationships:
        if not is_reversed and r.source_ref == id:
            relationship_lists.append(r)
        elif is_reversed and r.target_ref == id:
            relationship_lists.append(r)

    return relationship_lists

def get_behavior_relationships(id):
    return get_relationships_by(id, 'attack-pattern', 'subtechnique-of', 'attack-pattern')

def get_behaviors_used_by_malware(id):
    return get_relationships_by(id, 'malware', 'uses', 'attack-pattern')

def get_malwares_using_behavior(id):
    return get_relationships_by(id, 'malware', 'uses', 'attack-pattern', True)

def setup_src():
    global g_src
    g_src = FileSystemSource('./mbc-stix2/')

if __name__ == '__main__':
    setup_src()
    
    # objectives = get_all_objectives()
    # for o in objectives:
    #     print(str(o))

    # behaviors = get_behaviors_by_external_id('B0007')

    behaviors = get_behaviors_by_id('attack-pattern--55040e64-313d-4656-8e1c-1146ff2f47d7')    
    # related = get_behavior_relationships(behaviors[0])
    # for r in related:
    #     print(str(r))

    # malwares = get_malwares_by_id('malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
    # related = get_behaviors_used_by_malware(malwares[0].id)
    # for r in related:
    #     print(str(r))

    # print('=======')
    related = get_malwares_using_behavior('attack-pattern--5a3611aa-4253-4302-b09e-02fe53a1af9d')
    for r in related:
        print(str(r))

        

    
    
