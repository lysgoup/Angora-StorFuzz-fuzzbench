#!/bin/bash

set -euo pipefail
CONFIG_FILE="${1:-Angora-StorFuzz-fuzzbench/config.yaml}"

# ── config.yaml 존재 확인 ──
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[ERROR] config.yaml not found: $CONFIG_FILE"
    echo "Usage: $0 [config.yaml path]"
    exit 1
fi
 
# ── config.yaml 파싱 ──
parse_yaml_value() {
    local key="$1"
    grep "^${key}:" "$CONFIG_FILE" | sed "s/^${key}:[[:space:]]*//" | tr -d "'\""
}
 
EXPERIMENT_FILESTORE=$(parse_yaml_value "experiment_filestore")
REPORT_FILESTORE=$(parse_yaml_value "report_filestore")

if [[ -z "$EXPERIMENT_FILESTORE" ]]; then
    echo "[ERROR] experiment_filestore not found in $CONFIG_FILE"
    exit 1
fi
 
if [[ -z "$REPORT_FILESTORE" ]]; then
    echo "[ERROR] report_filestore not found in $CONFIG_FILE"
    exit 1
fi

parse_comment() {
    local key="$1"
    local val
    val=$(grep "^#[[:space:]]*${key}[[:space:]]*:" "$CONFIG_FILE" | head -1 | sed "s/^#[[:space:]]*${key}[[:space:]]*:[[:space:]]*//" | xargs)
    echo "$val"
}

FUZZERS=$(parse_comment "fuzzers")
TARGETS=$(parse_comment "targets")
RC=$(parse_comment "runners-cpus")
MC=$(parse_comment "measurers-cpus")
CUSTOM_CORPUS=$(parse_comment "custom_corpus")
EXP_NAME=$(parse_comment "experiment-name")
RCO=$(parse_comment "runners-cpus-offset")
# CB=$(parse_comment "concurrent-builds")

# ── 기본값 ──
RC="${RC:-1}"
MC="${MC:-1}"
EXP_NAME="${EXP_NAME:-storfuzz-fuzzbench}"
RCO="${RCO:-0}"
# CB="${CB:-2}"

# ── 필수값 확인 ──
if [[ -z "$FUZZERS" ]]; then
    echo "[ERROR] 'fuzzers' not found in $CONFIG_FILE"
    exit 1
fi
if [[ -z "$TARGETS" ]]; then
    echo "[ERROR] 'targets' not found in $CONFIG_FILE"
    exit 1
fi
 
# ── 공백 정리 ──
FUZZERS=$(echo "$FUZZERS" | xargs)
TARGETS=$(echo "$TARGETS" | xargs)

# ── 커맨드 조립 ──
CMD="PYTHONPATH=. python3.10 experiment/run_experiment.py"
CMD+=" --experiment-config config.yaml"
CMD+=" --experiment-name $EXP_NAME"
CMD+=" --runners-cpus $RC"
CMD+=" --measurers-cpus $MC"
CMD+=" --runners-cpus-offset $RCO"
# CMD+=" --concurrent-builds $CB"
CMD+=" --fuzzers $FUZZERS"
CMD+=" --benchmarks $TARGETS"

if [[ -n "$CUSTOM_CORPUS" ]]; then
    CMD+=" -cs $CUSTOM_CORPUS"
fi

INFO="--------------------------------------------------------------\n"
INFO+="[INFO] experiment-name : $EXP_NAME\n"
INFO+="[INFO] experiment_filestore : $EXPERIMENT_FILESTORE\n"
INFO+="[INFO] report_filestore : $REPORT_FILESTORE\n"
INFO+="[INFO] FUZZERS     : $FUZZERS\n"
INFO+="[INFO] TARGETS     : $TARGETS\n"
INFO+="[INFO] CUSTOM_CORPUS     : $CUSTOM_CORPUS\n"
INFO+="[INFO] Command to run : $CMD\n"
INFO+="--------------------------------------------------------------"

exec screen -S "myeonggyu-$EXP_NAME" bash -c "echo -e \"$INFO\" && source .venv/bin/activate && $CMD"