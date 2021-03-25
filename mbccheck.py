#!/usr/bin/env python3

import os
import sys
import json
import requests
import stix2
from stix2 import Filter

fs_source = stix2.FileSystemSource('./mbc-stix2/')
attacks = fs_source.query([
    Filter('type', '=', 'attack-pattern'),
])
for att in attacks:
    for attack in response_json['mitre_attcks']:
        attack_id = attack['attck_id']
        print('checking '+ attack_id)
        if att.external_references[0].source_name == 'mitre-attack':
            print(str(att))
        # if att.external_references[0].external_id == attack_id:
        #     print('Found it: ' + str(att))
        #     print('\n\n =================== \n\n')


sys.exit()
attacks = fs_source.query([
    Filter('type', '=', 'attack-pattern'),
    Filter('external_references.external_id', '=', 'C0057')
])
 
for att in attacks:
    print(att)

sys.exit()
relationships = fs_source.query([
    Filter('type', '=', 'relationship'),
    Filter('relationship_type', '=', 'subtechnique-of')
])

for rel in relationships:
    print(rel)

