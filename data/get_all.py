#!/usr/bin/env python3

import argparse
import git
import json
import os
import glob
import subprocess
import shlex
import re
import tempfile
import time
import sys
import enum

from operator import itemgetter

from fabric import Connection

################################################################################
# Constants
################################################################################

cheri_lines_pattern = "Total CHERI lines: (\d+)"

cheri_fn_pattern = "cheri_[a-zA-Z0-9_]+"
cheri_fn_grep_pattern = "\\bcheri_[[:alnum:]_]\+("

cheri_builtin_fn_pattern = "__builtin_cheri[a-zA-Z0-9_]+"
cheri_builtin_fn_grep_pattern = "BUILTIN(__builtin_cheri[[:alnum:]_]\+"
cheri_builtin_fn_call_grep_pattern = "__builtin_cheri[[:alnum:]_]\+"

################################################################################
# Arguments
################################################################################

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("--alloc", type=str, action='store', required=False,
        help="""Optional path to allocator. If not given, runs over all
        allocators given in `config.json`.""")
arg_parser.add_argument("--local-dir", type=str, action='store', default=None,
        required=False, metavar="path",
        help="Where to store local data, instead of generating a folder.")
arg_parser.add_argument("--log-file", type=str, action='store',
        default='cheri_alloc.log', metavar="path",
        help="File to store log data to")
arg_parser.add_argument("--no-build-cheri", action="store_true",
        help="""Whether to build CheriBSD and the QEMU image from scratch. Only
        set if `local-dir` is set with a pre-existing build within.""")
arg_parser.add_argument("--no-wait-qemu", action="store_true",
        help="If set, assumes the QEMU instance is running, and skip waiting.")
arg_parser.add_argument("--parse-data-only", action='store', default="",
        type=str, metavar="path",
        help="Parse given results file to generate LaTeX tables.")
arg_parser.add_argument("--target-machine", action='store', default="",
        type=str, metavar="IP",
        help="""Address of a CHERI-enabled machine on the network to run
        experiments on instead of using a QEMU instance. Expected format is
        `user@host:port`. NOTE: This requires appropriate keys being set-up
        between the machines to communicate without further user input""")
arg_parser.add_argument("--table-context", action='store_true',
        help="""If set, will emit Latex tables with prologue and epilogue.
        Otherwise, simply generates the table content""")
args = arg_parser.parse_args()

################################################################################
# Helper Functions
################################################################################

def make_scp_cmd(path_from, path_to):
    if args.target_machine:
        target = args.target_machine
        port = ""
    else:
        target = "root@localhost"
        port = f'-P{config["cheri_qemu_port"]}'
    return shlex.split(f'scp -o "StrictHostKeyChecking=no" -o "UserKnownHostsFile=/dev/null" {port} {path_from} {target}:{path_to}')

def make_cheribuild_cmd(target, flags = ""):
    cmd = shlex.split(f'./cheribuild.py -d -f --skip-update --source-root {work_dir_local}/cheribuild {flags} {target}')
    print(f"MADE {cmd}")
    return cmd

def make_grep_pattern_cmd(pattern, target):
    return shlex.split(f"grep -oIrhe '{pattern}' {target}")

def make_cloc_cmd(path):
    return shlex.split(f"cloc --json {path}")

def make_replace(path):
    path = path.replace('$HOME', os.getenv('HOME'))
    return path

def prepare_tests(tests_path, dest_path):
    test_sources = glob.glob(os.path.join(tests_path, "*.c"))
    for to_ignore in config["tests_to_ignore"]:
        test_sources = [x for x in test_sources if not to_ignore in x]
    log_message(f"Found tests in {tests_path}: {test_sources}")
    assert(test_sources)
    tests = []
    compile_cmd = f"{os.path.join(work_dir_local, 'cheribuild', 'output', 'morello-sdk', 'bin', 'clang')} --std=c11 -Wall --config cheribsd-morello-purecap.cfg"
    for source in test_sources:
        test = os.path.join(work_dir_local, os.path.splitext(os.path.basename(source))[0])
        subprocess.run(shlex.split(compile_cmd) + ['-o', test, source], check = True)
        tests.append(test)
    subprocess.run(make_scp_cmd(" ".join(tests), f"{dest_path}"), check = True)
    return tests

def get_config(to_get):
    return parse_path(config[to_get])

def parse_path(to_parse):
    if to_parse.startswith("$HOME"):
        to_parse = to_parse.replace("$HOME", os.getenv("HOME"))
    elif to_parse.startswith("$WORK"):
        to_parse = to_parse.replace("$WORK", work_dir_local)
    elif to_parse.startswith("$CWD"):
        to_parse = to_parse.replace("$CWD", base_cwd)
    elif to_parse.startswith("$RHOME"):
        to_parse = to_parse.replace("$RHOME", remote_homedir)
    else:
        print(f"Did not parse anything for path {to_parse}.")
    return to_parse

#TODO check intersection
def read_apis(apis_path):
    api_fns = {}
    with open(f"{apis_path}", 'r') as api_info_json:
        api_info = json.load(api_info_json)
        for api in api_info:
            api_fns[api] = set()
            if api == "builtin":
                pattern = cheri_builtin_fn_grep_pattern
            else:
                pattern = cheri_fn_grep_pattern
            for api_file in api_info[api]['path']:
                api_file = parse_path(api_file)
                if not os.path.exists(api_file):
                    print(f"Could not find file {api_file}; exiting...")
                    sys.exit(1)
                log_message(f"Checking API file {api_file} for API {api}.")
                fns = subprocess.check_output(make_grep_pattern_cmd(pattern, api_file), encoding = "UTF-8")
                fns = fns.strip().split(os.linesep)
                if api == "builtin":
                    fns = [x.removeprefix("BUILTIN(") for x in fns]
                else:
                    fns = [x.removesuffix("(") for x in fns]
                api_fns[api].update(fns)
    return api_fns

def log_message(msg):
    print(msg)
    log_fd.write(msg + '\n')

################################################################################
# Objects
################################################################################

class InstallMode(enum.Enum):
    REPO = enum.auto()
    PKG = enum.auto()
    CHERIBUILD = enum.auto()

    def parse_version(self, install_data):
        if self == InstallMode.PKG:
            return install_data['version']
        return install_data['commit']

    @classmethod
    def parse_mode(cls, mode):
        if mode == "repo":
            return InstallMode.REPO
        elif mode == "pkg64c":
            return InstallMode.PKG
        elif mode == "cheribuild":
            return InstallMode.CHERIBUILD
        else:
            print(f"Wrong mode parsed: {mode}")
            assert(False)

class Allocator:
    def __init__(self, folder, json_data):
        self.name = os.path.basename(folder.removesuffix('/')).replace('_', '-')
        self.info_folder = os.path.abspath(folder)
        self.install_mode = InstallMode.parse_mode(json_data['install']['mode'])
        self.install_target = json_data['install']['target']
        self.lib_file = parse_path(json_data['install']['lib_file'])
        if self.install_mode == InstallMode.PKG:
            # self.source_path =
            self.remote_lib_path = json_data['install']['lib_file']
            self.cheribsd_ports_path = json_data['cheribsd_ports_path']
            self.cheribsd_ports_commit = json_data['commit']
        elif self.install_mode == InstallMode.CHERIBUILD:
            self.source_path = parse_path(json_data['install']['source'])
            self.remote_lib_path = os.path.join(work_dir_remote, os.path.basename(self.lib_file))
        elif self.install_mode == InstallMode.REPO:
            self.source_path = os.path.join(base_cwd, self.name)
            self.remote_lib_path = os.path.join(work_dir_remote, os.path.basename(self.lib_file))
        if not os.path.isabs(self.lib_file):
            self.lib_file = os.path.join(self.source_path, self.lib_file)
        self.version = self.install_mode.parse_version(json_data['install'])
        self.no_attacks = False if not "no_attacks" in json_data else json_data['no_attacks']
        self.raw_data = json_data

    def get_build_file_path(self):
        print(self.info_folder)
        return os.path.join(self.info_folder, self.raw_data['install']['build_file'])

class ExecEnvironment:
    def __init__(self, addr):
        addr_regex = "(\w+)@([\w\.]+):(\d+)"
        self.user, self.host, self.port = re.match(addr_regex, addr).groups()
        self.conn = Connection(host = self.host, user = self.user, port = self.port)

    def __del__(self):
        self.conn.close()

    def install_alloc(self, alloc, version):
        return self.run_cmd(f"pkg64c install -y {alloc}-{version}", check = True)

    def run_cmd(self, cmd, env = {}, check = False):
        return self.conn.run(cmd, env = env, warn = not check)

    def put_file(self, src, dest):
        return self.conn.put(src, remote = dest)

################################################################################
# Preparation
################################################################################

def prepare_cheri():
    if args.no_build_cheri:
        assert(args.local_dir)
        assert(os.path.exists(args.local_dir))
    else:
        log_message(f"Building new QEMU instance in {work_dir_local}")
        cmd = shlex.split(f"./cheribuild.py -d -f --source-root {work_dir_local}/cheribuild qemu disk-image-morello-purecap")
        subprocess.run(cmd, cwd = get_config('cheribuild_folder'))
    artifact_path = os.path.join(work_dir_local, "cheribuild")
    assert(os.path.exists(os.path.join(artifact_path, "output", "sdk", "bin", "qemu-system-morello")))
    port = config['cheri_qemu_port']
    qemu_cmd = f"""
        {artifact_path}/output/sdk/bin/qemu-system-morello
        -M virt,gic-version=3 -cpu morello -bios edk2-aarch64-code.fd -m 2048
        -nographic
        -drive if=none,file={artifact_path}/output/cheribsd-morello-purecap.img,id=drv,format=raw
        -device virtio-blk-pci,drive=drv -device virtio-net-pci,netdev=net0
        -netdev 'user,id=net0,smb={artifact_path}<<<source_root@ro:{artifact_path}/build<<<build_root:{artifact_path}/output<<<output_root@ro:{artifact_path}/output/rootfs-morello-purecap<<<rootfs,hostfwd=tcp::{port}-:22'
        -device virtio-rng-pci
    """
    log_message(re.compile(r'\s+').sub(' ', qemu_cmd))
    with open(os.path.join(work_dir_local, "qemu_child.log"), 'w') as qemu_child_log:
        qemu_child = subprocess.Popen(shlex.split(qemu_cmd), stdin = subprocess.PIPE, stdout = qemu_child_log, stderr = qemu_child_log)
    print("Waiting for emulator...")
    if not args.no_wait_qemu:
        time.sleep(2 * 60) # wait for instance to boot
    attempts = 0
    attempts_max = 5
    attempts_cd = 10
    while attempts < attempts_max:
        print(f"-- checking if QEMU running; try {attempts}...")
        with Connection(f"root@localhost:{port}") as qemu_conn:
            check_proc = qemu_conn.run("echo hi", warn = False)
        print(f"-- saw return code {check_proc.returncode}")
        if check_proc.returncode == 0:
            return qemu_child
        attempts += 1
        time.sleep(attempts_cd)
    return None

def prepare_cheribsd_ports():
    to_path = os.path.join(work_dir_local, 'cheribsd-ports')
    if not os.path.exists(to_path):
        repo = git.Repo.clone_from(url = get_config('cheribsd_ports_url'),
                                   to_path = to_path,
                                   multi_options = ["--depth 1", "--single-branch"])
    else:
        repo = git.Repo(to_path)
    return repo

################################################################################
# Application
################################################################################

def do_source(alloca):
    if alloca.install_mode == InstallMode.CHERIBUILD:
        os.chdir(get_config('cheribuild_folder'))
        subprocess.run(make_cheribuild_cmd(alloca.install_target, "--configure-only"), stdout = None)
        repo = git.Repo(path = subprocess.check_output(shlex.split("git rev-parse --show-toplevel"), cwd = alloca.source_path, encoding = 'UTF-8').strip())
        repo.git.fetch("origin", alloca.version)
        repo.git.checkout(alloca.version)
        os.chdir(base_cwd)
    elif alloca.install_mode == InstallMode.REPO:
        if not os.path.exists(alloca.source_path):
            repo = git.Repo.clone_from(url = alloca.install_target, to_path = alloca.source_path)
        else:
            repo = git.Repo(alloca.source_path)
        repo.git.fetch("origin", alloca.version)
        repo.git.checkout(alloca.version)
    elif alloca.install_mode == InstallMode.PKG:
        # TODO
        pass

def do_install(alloca, compile_env):
    if alloca.install_mode == InstallMode.CHERIBUILD:
        os.chdir(get_config('cheribuild_folder'))
        subprocess.run(make_cheribuild_cmd(alloca.install_target, "-c"), stdout = None)
        os.chdir(base_cwd)
        subprocess.run(make_scp_cmd(alloca.lib_file, work_dir_remote), check = True)
    elif alloca.install_mode == InstallMode.REPO:
        subprocess.run([alloca.get_build_file_path(), work_dir_local], env = compile_env, cwd = alloca.source_path)
        subprocess.run(make_scp_cmd(alloca.lib_file, work_dir_remote), check = True)
    elif alloca.install_mode == InstallMode.PKG:
        if args.target_machine:
            check_cmd = exec_env.run_cmd(f"pkg64c info {alloca.install_target}")
            return check_cmd.returncode == 0
        else:
            exec_env.install_alloc(alloca.install_target, alloca.version)

def do_line_count(source_path):
    cloc_data = json.loads(subprocess.check_output(make_cloc_cmd(source_path), encoding = 'UTF-8'))
    return cloc_data['SUM']['code']

def do_cheri_line_count(alloc_path):
    data = subprocess.check_output([get_config('data_get_script_path'), "cheri-line-count", alloc_path], encoding = 'UTF-8')
    return int(re.search(cheri_lines_pattern, data).group(1))

def do_attacks(alloca, tests):
    if alloca.no_attacks:
        return {}, False
    results = {}
    for test in tests:
        cmd = os.path.join(work_dir_remote, os.path.basename(test))
        print(f"- Running test {cmd}")
        remote_env = {}
        print(f"-- with `LD_PRELOAD` at {alloca.remote_lib_path}")
        remote_env = { 'LD_PRELOAD' : alloca.remote_lib_path }
        log_message(f"RUN {cmd} WITH ENV {remote_env}")
        start_time = time.perf_counter_ns()
        test_res = exec_env.run_cmd(cmd, env = remote_env, check = False)
        runtime = time.perf_counter_ns() - start_time
        if "validate" in test:
            validated = test_res.exited == 0
        results[test] = {}
        results[test]['exit_code'] = test_res.exited
        results[test]['stdout'] = test_res.stdout
        results[test]['stderr'] = test_res.stderr
        results[test]['time'] = runtime
    return results, validated

def get_source_data(alloca):
    source_data = {}
    if alloca.install_mode == InstallMode.PKG:
        cheribsd_ports_repo.git.fetch("origin", alloca.cheribsd_ports_commit)
        cheribsd_ports_repo.git.checkout(alloca.cheribsd_ports_commit)
        alloc_path = os.path.join(cheribsd_ports_repo.working_dir, alloca.cheribsd_ports_path)
        assert(os.path.exists(alloc_path))
        source_data['api'] = do_cheri_api(alloc_path, api_fns)
        source_data['cheri_loc'] = do_cheri_line_count(alloc_path)
    else:
        source_data['api'] = do_cheri_api(alloca.source_path, api_fns)
        source_data['sloc'] = do_line_count(alloca.source_path)
        source_data['cheri_loc'] = do_cheri_line_count(alloca.source_path)
    return source_data

def do_cheri_api(source_dir, apis_info):
    api_fns = set()
    get_funcs = lambda x : set(x.strip().split(os.linesep))
    try:
        api_fns.update(get_funcs(subprocess.check_output(make_grep_pattern_cmd(cheri_fn_grep_pattern, source_dir), encoding = 'UTF-8')))
        api_fns = set([x.removesuffix("(") for x in api_fns])
    except subprocess.CalledProcessError:
        pass
    try:
        api_fns.update(get_funcs(subprocess.check_output(make_grep_pattern_cmd(cheri_builtin_fn_call_grep_pattern, source_dir), encoding="UTF-8")))
    except subprocess.CalledProcessError:
        pass
    found_apis = dict.fromkeys(apis_info.keys(), 0)
    not_found_funcs = []
    for api_fn in api_fns:
        found = False
        for api in apis_info:
            if api_fn in apis_info[api]:
                found_apis[api] += 1
                found= True
                break
        if not found:
            not_found_funcs.append(api_fn)
    return found_apis, not_found_funcs

################################################################################
# Latex Tables
################################################################################

def do_table_cheri_api(results):
    preamble = []
    epilogue = []
    if args.table_context:
        preamble = [r'\begin{table}[t]', r'\begin{center}', r'\begin{tabular}{lcrr}']
        preamble += [r'\toprule', r'allocator & API & \# API calls & \# builtin calls \\']
        preamble += [r'\midrule']

        epilogue = [r'\\ \bottomrule', r'\end{tabular}']
        epilogue += [r'\caption{\label{tab:rq1}Coverage of CHERI API calls by various allocators}']
        epilogue += [r'\label{tab:atks}', r'\end{center}', r'\end{table}']
    entries = []
    for result in results:
        if not 'api' in result:
            continue
        api_key = max(result['api'][0], key = result['api'][0].get)
        entry = [result['name']]
        entry.append(api_key)
        entry.append(result['api'][0][api_key])
        entry.append(result['api'][0]['builtin'])
        entries.append(' & '.join(map(str, entry)))
    table = '\n'.join(['\n'.join(preamble), '\\\\\n'.join(entries), '\n'.join(epilogue)])
    return table

def do_table_tests_parse_result(result, test):
    if result["results"][test]["exit_code"] == 0:
        result_stdout = result["results"][test]["stdout"]
        if "Attack unsuccessful" in result_stdout:
            return r'$\checkmark$'
        elif "Attack successful" in result_stdout:
            return r'$\times$'
        else:
            return 'P'
    else:
        return r'$\oslash$'

def do_table_tests_entries(result, test_names):
    new_entry = []
    test_sources = tests if not args.parse_data_only else sorted(result["results"].keys())
    for test in test_sources:
        if os.path.basename(test) in config["table_tests_to_ignore"]:
            continue
        new_entry.append(do_table_tests_parse_result(result, test))
    return new_entry

def do_table_tests(results):
    test_names = [os.path.splitext(x)[0] for x in map(os.path.basename, sorted(tests)) if not os.path.splitext(x)[0] in (config["table_tests_to_ignore"] + config["tests_to_ignore"])]
    preamble = f'% {" & ".join(test_names)}'
    epilogue = []
    if args.table_context:
        latexify = lambda x : r'\tbl' + x.replace('_', '').replace('2', "two").replace('3', "three")
        header_fields = len(test_names) * 'c'
        preamble += [r'\begin{table}[t]', r'\begin{center}', r'\begin{tabular}{l' + header_fields + r'}']
        preamble += [r'\toprule', r'Allocator & ' + ' & '.join(map(latexify, test_names)) + r'\\']
        preamble += [r'\midrule']

        epilogue = [r'\input{./data/results/tests_extra.tex}']
        epilogue += [r'\\ \bottomrule', r'\end{tabular}']
        epilogue += [r'''\caption{Attacks which succeed on a given allocator
        are marked with a $\times$, while unsuccessful attacks are marked with
        a $\checkmark$; attack executions which fail due to other reasons
        (e.g., segmentation faults) are marked with $\oslash$.}''']
        epilogue += [r'\label{tab:atks}', r'\end{center}', r'\end{table}']
    entries = []
    for result in results:
        if not result['results'] or not result['validated']:
            continue
        entry = [result['name']]
        entry.extend(do_table_tests_entries(result, test_names))
        entries.append(' & '.join(entry))
    table = '\n'.join(['\n'.join(preamble), '\\\\\n'.join(entries), '\n'.join(epilogue)])
    return table

def do_table_slocs(results):
    preamble = []
    epilogue = []
    if args.table_context:
        preamble += [r'\begin{table}[tb]', r'\begin{center}', r'\begin{tabular}{lcrrr}']
        preamble += [r'\toprule', ' & '.join(['Allocator', 'Version', 'SLoC', r'\multicolumn{2}{c}{Changed}']) + r'\\']
        preamble += [r'\cmidrule(lr){4-5}', ' & '.join([' ', ' ', ' ', 'LoC', r'\multicolumn{1}{c}{\%}']) + r'\\']
        preamble += [r'\midrule']

        epilogue += [r'\\ \bottomrule', r'\end{tabular}', r'\end{center}']
        epilogue += [r'''\caption{The allocators we examined, their size in
                Source Lines of Code (SLoC), and the number of lines changed to
                adapt them for pure capability CheriBSD.}''']
        epilogue += [r'\label{tab:allocator_summary}', r'\end{table}']
    entries = []
    for result in results:
        entry = [result['name']]
        entry.append(result['version'][:10].replace('_', r"\_"))
        if 'sloc' in result:
            entry.append(r'\numprint{' + str(result['sloc']) + r'}')
            entry.append(r'\numprint{' + str(result['cheri_loc']) + r'}')
            entry.append("{:.2f}".format(result['cheri_loc'] * 100 / result['sloc']))
        else:
            entry.extend(['-', '-', '-'])
        entries.append(' & '.join(map(str, entry)))
    table = '\n'.join(['\n'.join(preamble), '\\\\\n'.join(entries), '\n'.join(epilogue)])
    return table

def do_all_tables(results):
    results = sorted(results, key = itemgetter("name"))
    with open(os.path.join(work_dir_local, "cheri_api.tex"), 'w') as cheri_api_fd:
        cheri_api_fd.write(do_table_cheri_api(results))
    with open(os.path.join(work_dir_local, "tests.tex"), 'w') as tests_fd:
        tests_fd.write(do_table_tests(results))
    with open(os.path.join(work_dir_local, "slocs.tex"), 'w') as slocs_fd:
        slocs_fd.write(do_table_slocs(results))

################################################################################
# Main
################################################################################

# Initial setup
config_path = "./config.json"
with open(config_path, 'r') as json_config:
    config = json.load(json_config)
base_cwd = os.getcwd()

# Gather allocator folders
allocators = []
if args.alloc:
    allocators = [args.alloc]
else:
    allocators = [alloc_dir.path for alloc_dir in os.scandir(get_config('allocators_folder')) if alloc_dir.is_dir()]

# Prepare local work directories
work_dir_prefix = "cheri_alloc_"
if args.local_dir:
    work_dir_local = os.path.abspath(args.local_dir)
else:
    work_dir_local = tempfile.mkdtemp(prefix = work_dir_prefix, dir = os.getcwd())

# Local files
results_tmp_path = os.path.join(work_dir_local, "results_tmp.json")
results_path = os.path.join(work_dir_local, "results.json")
log_fd = open(os.path.join(work_dir_local, args.log_file), 'w')
log_message(f"Set local work directory to {work_dir_local}")

if args.parse_data_only:
    log_message(f"Parsing results file at {args.parse_data_only}.")
    with open(args.parse_data_only, 'r') as results_fd:
        results = json.load(results_fd)
    tests = sorted([x for x in glob.glob(os.path.join(get_config('tests_folder'), "*.c"))])
    api_fns = read_apis(get_config('cheri_api_path'))
    do_all_tables(results)
    log_message(f"DONE in {work_dir_local}")
    log_fd.close()
    sys.exit(0)

# Symlink last execution work directory
symlink_name = f"{work_dir_prefix}last"
if os.path.exists(symlink_name):
    os.remove(symlink_name)
os.symlink(work_dir_local, symlink_name)

# Build and run new CHERI QEMU instance
exec_env = None
if args.target_machine:
    exec_env = ExecEnvironment(args.target_machine)
else:
    qemu_child = prepare_cheri()
    if not qemu_child:
        log_message("Unable to build or run QEMU instance; exiting...")
        sys.exit(1)
    exec_env = ExecEnvironment("root@localhost:10086")

# Prepare remote work directories
remote_homedir = exec_env.run_cmd("printf '$HOME'", check = True)
exec_env.run_cmd(f"mkdir -p {get_config('cheri_qemu_test_folder')}", check = True)
work_dir_remote = exec_env.run_cmd(f"mktemp -d {get_config('cheri_qemu_test_folder')}/{work_dir_prefix}XXX", check = True).stdout.strip()
# remote_homedir = subprocess.check_output(make_ssh_cmd("printf '$HOME'"), encoding = "UTF-8")
# subprocess.run(make_ssh_cmd(f"mkdir -p {get_config('cheri_qemu_test_folder')}"), check = True)
# work_dir_remote = subprocess.check_output(make_ssh_cmd(f"mktemp -d {get_config('cheri_qemu_test_folder')}/{work_dir_prefix}XXX"), encoding = "UTF-8")
# work_dir_remote = work_dir_remote.strip()
log_message(f"Set remote work directory to {work_dir_remote}")

# Prepare tests and read API data
tests = sorted(prepare_tests(get_config('tests_folder'), work_dir_remote))
api_fns = read_apis(get_config('cheri_api_path'))
cheribsd_ports_repo = prepare_cheribsd_ports()

# Environment for cross-compiling
compile_env = {
        "CC": get_config('cheribsd_cc'),
        "CFLAGS": config['cheribsd_cflags'],
        "CXX": get_config('cheribsd_cxx'),
        "CXXFLAGS": config['cheribsd_cxxflags'],
        "LD": get_config('cheribsd_ld'),
        "PATH": os.getenv('PATH'),
        }

results = []
for alloc_folder in allocators:
    log_message(f"=== PARSING {alloc_folder}")
    if not os.path.exists(f"{alloc_folder}/info.json"):
        log_message("No `info.json` found; skipping...")
        continue
    with open(f"{alloc_folder}/info.json", 'r') as alloc_info_json:
        alloca = Allocator(alloc_folder, json.load(alloc_info_json))
    alloc_data = {"name": alloca.name}

    # Get source
    do_source(alloca)

    # Install
    if not alloca.no_attacks:
        do_install(alloca, compile_env)

    # Attacks and validation
    alloc_data['results'], alloc_data['validated'] = do_attacks(alloca, tests)

    # SLoCs, CHERI API calls count
    alloc_data.update(get_source_data(alloca))

    # Version info
    alloc_data['version'] = alloca.version

    print(alloc_data)
    results.append(alloc_data)
    with open(os.path.join(work_dir_local, "results_tmp.json"), 'w') as results_file:
        json.dump(results, results_file)
    log_message(f"=== DONE {alloc_folder}")

# Terminate QEMU instance
if not args.target_machine:
    qemu_child.kill()

os.rename(results_tmp_path, results_path)
do_all_tables(results)

log_message(f"DONE in {work_dir_local}")

log_fd.close()
