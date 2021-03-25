#!/usr/bin/env python3
from stix2 import Filter, FileSystemSource

g_src = None

def get_all_objectives():
    return g_src.query([
        Filter('type', '=', 'x-mitre-tactic')
    ])

def setup_src():
    global g_src
    g_src = FileSystemSource('./mbc-stix2/')

if __name__ == '__main__':
    setup_src()

    objectives = get_all_objectives()
    for o in objectives:
        print(str(o))
