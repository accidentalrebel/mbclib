#!/usr/bin/env python3
from stix2 import Filter, FileSystemSource

g_src = None

def get_all_objectives():
    return g_src.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

def get_behaviours_by_external_id(external_id):
    return g_src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', external_id)
    ])

def get_related(src_type, rel_type, target_type):
    relationships = g_src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type)
    ])
    return relationships

def get_behavior_relationships(behavior):
    return get_related(None, 'subtechnique-of', None)
    

def setup_src():
    global g_src
    g_src = FileSystemSource('./mbc-stix2/')

if __name__ == '__main__':
    setup_src()

    behaviors = get_behaviours_by_external_id('B0007')
    for b in behaviors:
        print(str(b))
    
    # objectives = get_all_objectives()
    # for o in objectives:
    #     print(str(o))

    # related = get_behavior_relationships(None)
    # for r in related:
    #     print(str(r))
    
