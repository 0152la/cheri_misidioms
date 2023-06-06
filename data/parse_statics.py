#!/usr/bin/env python3

import json
import sys
import pprint

# From https://stackoverflow.com/a/45846841
def human_format(num):
    num = float('{:.3g}'.format(num))
    magnitude = 0
    while abs(num) >= 1000:
        magnitude += 1
        num /= 1000.0
    return '{}{}'.format('{:f}'.format(num).rstrip('0').rstrip('.'), ['', 'K', 'M', 'B', 'T'][magnitude])

def get_both(data, bench, key):
    dynamic = data["results_benchs"][mode][bench][key]
    static  = data["results_benchs_static"][mode][bench][key]
    margin  = static * 100.00 / dynamic
    return { "dynamic" : human_format(dynamic), "static" : human_format(static), "margin" : margin }

assert(len(sys.argv) == 2)
with open(sys.argv[1], 'r') as data_json_fd:
    data = json.load(data_json_fd)[0]

margin = 7.00
parsed = {}
for mode, mode_data in data["results_benchs"].items():
    parsed[mode] = {}
    for bench in mode_data.keys():
        dyn_time = data["results_benchs"][mode][bench]["total-time"]
        sta_time = data["results_benchs_static"][mode][bench]["total-time"]

        time_improvement = sta_time * 100.00 / dyn_time
        if all([sta_time, dyn_time]) and time_improvement < 100 - margin:
            parsed[mode][bench] = {}
            parsed[mode][bench]["time"] = {"dynamic" : dyn_time, "static" : sta_time, "margin" : time_improvement}
            parsed[mode][bench]["pmc_cpu_cycles"] = get_both(data, bench, "CPU_CYCLES")
            parsed[mode][bench]["pmc_instr_retired"] = get_both(data, bench, "INST_RETIRED")

pprint.pprint(parsed)
