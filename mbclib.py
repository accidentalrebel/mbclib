#!/usr/bin/env python3
from stix2 import Filter, FileSystemSource, properties
from stix2.v21 import CustomObject, Bundle

@CustomObject('x-mitre-tactic', [ ('x_mitre_shortname', properties.StringProperty(required=True)) ])
class Tactic(object):
    pass

import json

def get_all_objectives(src):
    return src.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

def get_all_behaviors(src):
    return src.query([
        Filter('type', '=', 'attack-pattern')
    ])

def get_all_malwares(src):
    return src.query([
        Filter('type', '=', 'malware')
    ])

def get_objective_by_id(src, id):
    q = src.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

def get_objective_by_external_id(src, external_id):
    q = src.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('external_references.external_id', '=', external_id.upper())
    ])
    return q[0] if len(q) > 0 else None

def get_objective_by_shortname(src, shortname):
    q = src.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('x_mitre_shortname', '=', shortname)
    ])
    return q[0] if len(q) > 0 else None

def get_behavior_by_external_id(src, external_id):
    q = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', external_id.upper())
    ])
    return q[0] if len(q) > 0 else None

def get_behavior_by_id(src, id):
    q = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

def get_malware_by_external_id(src, external_id):
    q = src.query([
        Filter('type', '=', 'malware'),
        Filter('external_references.external_id', '=', external_id.upper())
    ])
    return q[0] if len(q) > 0 else None

def get_malware_by_id(src, id):
    q =  src.query([
        Filter('type', '=', 'malware'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

def get_mbc_external_id(obj):
    if obj and obj.external_references:
        for ref in obj.external_references:
            if ref.source_name == 'mitre-mbc' \
               and ref.external_id:
                return ref.external_id

    return None

def get_relationships_by(src, id, src_type, rel_type, target_type, is_reversed=False):
    relationship_lists = []
    relationships = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type)
    ])
    for r in relationships:
        if not is_reversed and r.source_ref == id:
            relationship_lists.append(r)
        elif is_reversed and r.target_ref == id:
            relationship_lists.append(r)

    return relationship_lists

def get_parent_behavior(src, id):
    rels = get_relationships_by(src, id, 'attack-pattern', 'subtechnique-of', 'attack-pattern')
    if len(rels) <= 0:
        return None
    
    return get_behavior_by_id(src, rels[0].target_ref)

def get_behaviors_under_objective(src, phase_name):
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', phase_name)
    ])

def get_children_of_behavior(src, id):
    rels = get_relationships_by(src, id, 'attack-pattern', 'subtechnique-of', 'attack-pattern', True)
    l = []
    for rel in rels:
        l.append(get_behavior_by_id(src, rel.source_ref))

    return l

def get_behaviors_used_by_malware(src, id):
    rels = get_relationships_by(src, id, 'malware', 'uses', 'attack-pattern')

    l = []
    for rel in rels:
        l.append(get_behavior_by_id(src, rel.target_ref))

    return l

def get_malwares_using_behavior(src, id):
    if not type(id) is str:
        print('[ERROR] ID should be a string!')
        raise SystemExit(1)
        
    rels = get_relationships_by(src, id, 'malware', 'uses', 'attack-pattern', True)

    l = []
    for rel in rels:
        l.append(get_malware_by_id(src, rel.source_ref))
        
    return l

def setup_src(path):
    return FileSystemSource(path)
