#!/usr/bin/env python3

import json
import sys
import pprint

assert(len(sys.argv) == 2)
with open(sys.argv[1], 'r') as data_json_fd:
    data = json.load(data_json_fd)[0]

parsed = {}
for mode, mode_data in data["results_benchs"].items():
    parsed[mode] = {}
    for bench in mode_data.keys():
        parsed[mode][bench] = {"dynamic": {}, "static": {}}
        parsed[mode][bench]["dynamic"]["time"] = data["results_benchs"][mode][bench]["total-time"]
        parsed[mode][bench]["static"]["time"]  = data["results_benchs_static"][mode][bench]["total-time"]

pprint.pprint(parsed)
