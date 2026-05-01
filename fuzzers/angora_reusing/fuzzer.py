# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Integration code for Angora fuzzer."""

import os
import shutil
import subprocess
from pathlib import Path
from fuzzers import utils

ANGORA_BIN = '/angora/bin'
ANGORA_TOOLS = '/angora/tools'
ABILIST_PATH = '/tmp/angora_extra_abilist.txt'

# Libraries already covered by Angora's built-in abilists — skip them.
_ABILIST_SKIP = {
    'libgcc_s.so', 'libstdc++.so', 'libc.so',
    'libm.so', 'libpthread.so', 'libdl.so',
}

def _get_dry_run_paths():
    """runner.py와 동일한 규칙으로 dry run 마커/sentinel 경로를 반환한다.

    형식: {EXPERIMENT_FILESTORE}/{EXPERIMENT}/dryrun/dry_run_{opt_in|done}_{TRIAL_ID}
    """
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    trial_id = os.environ.get('TRIAL_ID', 'unknown')
    dryrun_dir = os.path.join(filestore, experiment, 'dryrun')
    os.makedirs(dryrun_dir, exist_ok=True)
    opt_in = os.path.join(dryrun_dir, f'dry_run_opt_in_{trial_id}')
    sentinel = os.path.join(dryrun_dir, f'dry_run_done_{trial_id}')
    return opt_in, sentinel

def _watch_angora_dry_run(output_corpus, sentinel_path, stop_event):
    """Angora의 dry run 완료를 감지하는 백그라운드 스레드.

    Angora는 dry run 완료 후 output_corpus/queue/signal/dryrun_finish 를 생성한다.
    파일이 감지되면 sentinel을 생성해 runner.py에 알린다.
    """
    dryrun_finish = Path(output_corpus) / 'queue' / 'signal' / 'dryrun_finish'
    print(f'[DRY_RUN] Angora dry run watcher started. '
          f'Watching: {dryrun_finish}')
    while not stop_event.is_set():
        if dryrun_finish.exists():
            Path(sentinel_path).touch()
            print(f'[DRY_RUN] Angora dry run complete (dryrun_finish found). '
                  f'Sentinel created: {sentinel_path}')
            return
        stop_event.wait(2)
    print('[DRY_RUN] Angora dry run watcher stopped (fuzzer exited).')


def generate_abilist():
    """Generate a DFSan abilist (discard) for all system shared libraries.

    Scanning all .so files rather than using ldd on the fast binary — ldd only
    shows direct dynamic dependencies and misses libraries used by statically
    compiled components (e.g. zlib called from libarchive built from source).
    Running after the fast build also captures any libs installed during it.
    """
    gen_script = os.path.join(ANGORA_TOOLS, 'gen_library_abilist.sh')
    lib_dirs = ['/usr/lib', '/lib', '/usr/local/lib']

    libs = set()
    for lib_dir in lib_dirs:
        if not os.path.isdir(lib_dir):
            continue
        for dirpath, _, filenames in os.walk(lib_dir):
            for fname in filenames:
                if '.so' not in fname:
                    continue
                full = os.path.join(dirpath, fname)
                if not os.path.isfile(full):
                    continue
                base = fname.split('.so')[0] + '.so'
                if base not in _ABILIST_SKIP:
                    libs.add(full)

    with open(ABILIST_PATH, 'w') as out_f:
        for lib in sorted(libs):
            try:
                result = subprocess.run(
                    [gen_script, lib, 'discard'],
                    capture_output=True, text=True, timeout=30,
                )
                if result.stdout:
                    out_f.write(result.stdout)
            except Exception:  # pylint: disable=broad-except
                pass

    print(f'[build] Generated abilist for {len(libs)} libs at {ABILIST_PATH}')
    return ABILIST_PATH


def build():
    """Build benchmark twice with Angora instrumentation: fast then taint."""
    fuzz_target = utils.get_config_value('fuzz_target')
    out = os.environ['OUT']

    base_env = os.environ.copy()
    base_env['CC'] = f'{ANGORA_BIN}/angora-clang'
    base_env['CXX'] = f'{ANGORA_BIN}/angora-clang++'
    base_env['LD'] = f'{ANGORA_BIN}/angora-clang'
    # Let angora-clang manage its own flags; clear FuzzBench defaults.
    base_env['CFLAGS'] = ''
    base_env['CXXFLAGS'] = ''

    # --- fast binary ---
    fast_env = base_env.copy()
    fast_env['USE_FAST'] = '1'
    fast_env['FUZZER_LIB'] = '/libfuzzer-harness-fast.a'
    fast_env["ANGORA_PASS_LOG_DIR"] = str(Path(fast_env["OUT"]))
    print('[build] Building fast binary')
    # Snapshot $OUT before build so we can clean up between the two builds.
    out_before = set(os.listdir(out))
    with utils.restore_directory(os.environ['SRC']):
        utils.build_benchmark(fast_env)
    shutil.move(
        os.path.join(out, fuzz_target),
        os.path.join(out, fuzz_target + '.fast'),
    )

    # Remove files/dirs that the first build added to $OUT so the second
    # build.sh does not trip on already-existing paths (e.g. mkdir /out/seeds/).
    for item in os.listdir(out):
        if item == fuzz_target + '.fast':
            continue
        if item not in out_before:
            item_path = os.path.join(out, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)

    # --- taint binary ---
    # Generate abilist from the fast binary's shared-lib dependencies so that
    # DFSan does not rename external symbols to dfs$* (causing link errors).
    abilist = generate_abilist()

    taint_env = base_env.copy()
    taint_env['USE_TRACK'] = '1'
    taint_env['FUZZER_LIB'] = '/libfuzzer-harness-taint.a'
    taint_env['ANGORA_TAINT_RULE_LIST'] = abilist
    print('[build] Building taint binary')
    taint_env["ANGORA_PASS_LOG_DIR"] = str(Path(taint_env["OUT"]))
    # The FuzzBench builder image ships /usr/local/lib/libc++.a which conflicts
    # with Angora's DFSan-instrumented libc++abitrack.a. Temporarily hide the
    # system libc++ so the linker uses only Angora's track version.
    _CONFLICTING_LIBS = [
        '/usr/local/lib/libc++.a',
        '/usr/local/lib/libc++abi.a',
    ]
    renamed = []
    for lib in _CONFLICTING_LIBS:
        if os.path.exists(lib):
            os.rename(lib, lib + '.bak')
            renamed.append(lib)
    try:
        utils.build_benchmark(taint_env)
    finally:
        for lib in renamed:
            os.rename(lib + '.bak', lib)
    shutil.move(
        os.path.join(out, fuzz_target),
        os.path.join(out, fuzz_target + '.taint'),
    )

    # Make the Angora fuzzer binary available inside $OUT.
    shutil.copy(f'{ANGORA_BIN}/fuzzer', os.path.join(out, 'angora_fuzzer'))

    # FuzzBench's runner locates the target via get_fuzz_target_binary(), which
    # looks for the canonical name. Copy .fast as the placeholder so it's found,
    # then fuzz() derives .fast/.taint from the returned path.
    shutil.copy(
        os.path.join(out, fuzz_target + '.fast'),
        os.path.join(out, fuzz_target),
    )


def fuzz(input_corpus, output_corpus, target_binary):
    """Run Angora fuzzer on target."""
    utils.create_seed_file_for_empty_corpus(input_corpus)

    # Angora refuses to start if the output directory already exists.
    # FuzzBench pre-creates /out/corpus in the runner image (empty); remove it
    # so Angora can create its own structure (angora/queue/, etc.) there.
    if os.path.exists(output_corpus):
        shutil.rmtree(output_corpus)

    fast_binary = target_binary + '.fast'
    taint_binary = target_binary + '.taint'
    angora_fuzzer = os.path.join(os.environ['OUT'], 'angora_fuzzer')
    # logs_dir = os.path.join(os.environ['EXPERIMENT_FILESTORE'], os.environ['EXPERIMENT'], 'logs')
    filestore = os.environ.get('EXPERIMENT_FILESTORE', '/tmp')
    experiment = os.environ.get('EXPERIMENT', 'unknown')
    fuzzer_name = os.environ.get('FUZZER', 'unknown')
    logs_dir = Path(filestore) / experiment / 'logs'

    os.makedirs(logs_dir, exist_ok=True)

    shutil.copy(str(out_path / "cmpid_log_fast.json"), str(logs_dir / f"{fuzz_target_name}_{fuzzer_name}_cmpid_log_fast.json"))
    shutil.copy(str(out_path / "cmpid_log_track.json"), str(logs_dir / f"{fuzz_target_name}_{fuzzer_name}_cmpid_log_track.json"))

    # config.yaml 옵션 읽기
    only_dryrun = os.environ.get('ONLY_DRYRUN', 'false').lower() == 'true'
    analysis_mode = os.environ.get('ANALYSIS_MODE', 'false').lower() == 'true'
    print(f"[DEBUG] Config: ONLY_DRYRUN={only_dryrun}, ANALYSIS_MODE={analysis_mode}")

    # Dry run opt-in: runner.py에 dry run이 있음을 알림
    dry_run_opt_in_path, dry_run_sentinel_path = _get_dry_run_paths()
    Path(dry_run_opt_in_path).touch()
    print(f'[DRY_RUN] Angora dry run opt-in marker created: {dry_run_opt_in_path}')

    # Dry run 완료 감지 watcher 시작 (dryrun_finish 파일 감시)
    watcher_stop = threading.Event()
    watcher = threading.Thread(
        target=_watch_angora_dry_run,
        args=(str(output_corpus), dry_run_sentinel_path, watcher_stop),
        daemon=True,
    )
    watcher.start()
    
    fuzzer_cmd = [
        "fuzzer",
        f"-i={input_corpus}",
        f"-o={output_corpus}",
        f"-t={angora_track_path}",
    ]
    if only_dryrun:
        fuzzer_cmd.append("--only-dryrun")
    if analysis_mode:
        fuzzer_cmd.append("--analysis-mode")
    fuzzer_cmd += ["--", str(fast_binary), "@@"]
    # Disable CPU binding — Docker containers do not support affinity syscalls.
    env = os.environ.copy()
    env['ANGORA_DISABLE_CPU_BINDING'] = '1'

    print(f'[fuzz] Running: {" ".join(fuzzer_cmd)}')
    angora_proc = subprocess.Popen(fuzzer_cmd)
    try:
        angora_proc.wait()
    except KeyboardInterrupt:
        angora_proc.wait()
    finally:
        watcher_stop.set()
        watcher.join(timeout=5)
