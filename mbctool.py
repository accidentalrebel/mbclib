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

def get_relationships(src_type, rel_type, target_type):
    relationships = g_src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type)
    ])

    return relationships

def get_behavior_relationships(behavior):
    behavior_relationships = []
    relationships = get_relationships('attack-pattern', 'subtechnique-of', 'attack-pattern')
    for r in relationships:
        if r.source_ref == behavior.id:
            behavior_relationships.append(r)

    return behavior_relationships

def setup_src():
    global g_src
    g_src = FileSystemSource('./mbc-stix2/')

if __name__ == '__main__':
    setup_src()

    # behaviors = get_behaviors_by_external_id('B0007')

    behaviors = get_behaviors_by_id('attack-pattern--55040e64-313d-4656-8e1c-1146ff2f47d7')
    
    # objectives = get_all_objectives()
    # for o in objectives:
    #     print(str(o))

    related = get_behavior_relationships(behaviors[0])
    for r in related:
        print(str(r))