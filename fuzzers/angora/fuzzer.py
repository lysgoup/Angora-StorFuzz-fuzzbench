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

from fuzzers import utils

ANGORA_BIN = '/angora/bin'
ANGORA_TOOLS = '/angora/tools'
ABILIST_PATH = '/tmp/angora_extra_abilist.txt'

# Libraries already covered by Angora's built-in abilists — skip them.
_ABILIST_SKIP = {
    'libgcc_s.so', 'libstdc++.so', 'libc.so',
    'libm.so', 'libpthread.so', 'libdl.so',
}


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

    # Disable CPU binding — Docker containers do not support affinity syscalls.
    env = os.environ.copy()
    env['ANGORA_DISABLE_CPU_BINDING'] = '1'

    cmd = [
        angora_fuzzer,
        '-i', input_corpus,
        '-o', output_corpus,
        '-t', taint_binary,
        '--',
        fast_binary,
        '@@',
    ]
    print(f'[fuzz] Running: {" ".join(cmd)}')
    subprocess.check_call(cmd, env=env)
