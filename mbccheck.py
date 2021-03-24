#!/usr/bin/env python3

import os
import sys
import json

import requests

headers = {
    'accept': 'application/json',
    'user-agent': 'Falcon Sandbox',
    'api-key': '839lo9gs2da0cb7fdhgvyrvtb67138c068z573b075e1a9d5zq7wzxw2b40d6c44',
    'Content-Type': 'application/x-www-form-urlencoded',
}

data = {
  'hash': 'f143151e08f11f44b3dae80374d316b800514967e192ddc6460fc426280cfd81'
}

response = requests.post('https://www.hybrid-analysis.com/api/v2/search/hash', headers=headers, data=data)
response_json = response.json()[0]

for attack in response_json['mitre_attcks']:
    print(attack['attck_id'])
