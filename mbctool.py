#!/usr/bin/env python3
from stix2 import Filter, FileSystemSource

g_src = None

def get_all_objectives():
    return g_src.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

def get_behavior_by_external_id(external_id):
    q = g_src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', external_id)
    ])
    return q[0] if len(q) > 0 else None

def get_behavior_by_id(id):
    q = g_src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

def get_malware_by_id(id):
    q =  g_src.query([
        Filter('type', '=', 'malware'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

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
    rels =  get_relationships_by(id, 'malware', 'uses', 'attack-pattern')

    l = []
    for rel in rels:
        l.append(get_behavior_by_id(rel.target_ref))

    return l

def get_malwares_using_behavior(id):
    rels = get_relationships_by(id, 'malware', 'uses', 'attack-pattern', True)

    l = []
    for rel in rels:
        l.append(get_malware_by_id(rel.source_ref))
        
    return l

def setup_src():
    global g_src
    g_src = FileSystemSource('./mbc-stix2/')

if __name__ == '__main__':
    setup_src()

    malware = get_malware_by_id('malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
    malwares = get_behaviors_used_by_malware(malware.id)
    for m in malwares:
        print(str(m))

    print('=======')
    behavior = get_behavior_by_external_id('B0031')
    behaviors = get_malwares_using_behavior(behavior.id)
    for b in behaviors:
        print(str(b))
