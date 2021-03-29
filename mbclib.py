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

def get_behavior_by_external_id(src, external_id):
    q = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', external_id)
    ])
    return q[0] if len(q) > 0 else None

def get_objective_by_external_id(src, external_id):
    q = src.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('external_references.external_id', '=', external_id)
    ])
    return q[0] if len(q) > 0 else None

def get_objective_by_shortname(src, shortname):
    q = src.query([
        Filter('type', '=', 'x-mitre-tactic'),
        Filter('x_mitre_shortname', '=', shortname)
    ])
    return q[0] if len(q) > 0 else None

def get_mbc_external_id(behavior):
    if behavior and behavior.external_references:
        for ref in behavior.external_references:
            if ref.source_name == 'mitre-mbc' \
               and ref.external_id:
                return ref.external_id

    return None

def get_behavior_by_id(src, id):
    q = src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

def get_malware_by_id(src, id):
    q =  src.query([
        Filter('type', '=', 'malware'),
        Filter('id', '=', id)
    ])
    return q[0] if len(q) > 0 else None

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

def get_behaviors_used_by_malware(src, id):
    rels = get_relationships_by(src, id, 'malware', 'uses', 'attack-pattern')

    l = []
    for rel in rels:
        l.append(get_behavior_by_id(src, rel.target_ref))

    return l

def get_malwares_using_behavior(src, id):
    rels = get_relationships_by(src, id, 'malware', 'uses', 'attack-pattern', True)

    l = []
    for rel in rels:
        l.append(get_malware_by_id(src, rel.source_ref))
        
    return l

def setup_src(path):
    return FileSystemSource(path)

# if __name__ == '__main__':
#     parser = ArgumentParser(description='MBC Tool')
#     parser.add_argument('-i',
#                         '--id',
#                         help='The ID to search for.')
#     parser.add_argument('-e',
#                         '--externalid',
#                         help='The external ID to search for.')
#     parser.add_argument('-bb',
#                         '--externalid',
#                         help='The external ID to search for.')
    
#     args = parser.parse_args()

#     src = setup_src()

#     if args.id:
#         if 'malware--' in args.id:
#             malware = get_malware_by_id(src, args.id)
#             print(str(malware))
#         elif 'attack-pattern--' in args.id:
#             behavior = get_behavior_by_id(src, args.id)
#             print(str(behavior))
#         else:
#             print('[ERROR] ID ' + args.id + ' is not valid.')
#             raise SystemExit(1)
#     elif args.externalid:
#         behavior = get_behavior_by_external_id(src, args.externalid)
#         if behavior:
#             print(str(behavior))
#         else:
#             print('[ERROR] ExternalID ' + args.externalId + ' is not valid.')
#             raise SystemExit(1)

#     sys.exit()

#     # malware = get_malware_by_id(src, 'malware--36e75009-8fd6-467a-aa8c-c6a4d3511dfa')
#     # malwares = get_behaviors_used_by_malware(src ,malware.id)
#     # for m in malwares:
#     #     print(str(m))

#     # print('=======')
#     # behavior = get_behavior_by_external_id(src, 'B0031')
#     # behaviors = get_malwares_using_behavior(src, behavior.id)
#     # for b in behaviors:
#     #     print(str(b))
