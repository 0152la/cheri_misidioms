#!/usr/bin/env python3

import argparse
import json
import pprint
import shutil
import sys

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("input", type=str, action='store',
    help="""Path to input json file containing `get_all` output""")
arg_parser.add_argument("--margin", type=float, action='store', default=7.00,
    help="""The difference in runtime percent for which to print out
         benchmarks. A value of 0.0 means always print.""")
args = arg_parser.parse_args()

def get_both(data, bench, key):
    dynamic = data["results_benchs"][mode][bench][key]
    static  = data["results_benchs_static"][mode][bench][key]
    margin  = 100.00 - static * 100.00 / dynamic
    return { "dynamic" : f'{dynamic:,}', "static" : f'{static:,}', "margin" : margin }

with open(args.input, 'r') as data_json_fd:
    data = json.load(data_json_fd)[0]

parsed = {}
for mode, mode_data in data["results_benchs"].items():
    parsed[mode] = {}
    for bench in mode_data.keys():
        dyn_time = data["results_benchs"][mode][bench]["total-time"]
        sta_time = data["results_benchs_static"][mode][bench]["total-time"]

        margin = 100.00 - sta_time * 100.00 / dyn_time
        if all([sta_time, dyn_time]) and abs(margin) >= args.margin:
            parsed[mode][bench] = {}
            parsed[mode][bench]["time"] = {"dynamic" : dyn_time, "static" : sta_time, "margin" : margin}
            parsed[mode][bench]["pmc_cpu_cycles"] = get_both(data, bench, "CPU_CYCLES")
            parsed[mode][bench]["pmc_instr_retired"] = get_both(data, bench, "INST_RETIRED")

pprint.pprint(parsed, width = shutil.get_terminal_size().columns, sort_dicts = False)
