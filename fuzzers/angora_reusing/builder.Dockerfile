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

ARG parent_image

# Stage 1: Build Angora tools with LLVM 11.1.0
FROM ubuntu:20.04 AS angora_builder

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    git build-essential wget cmake curl \
    zlib1g-dev libstdc++-9-dev \
    python-is-python3

# Install LLVM 11.1.0 (ubuntu-16.04 build runs on ubuntu-20.04 via glibc compat)
RUN wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    tar -C / -xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    mv /clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04 /clang+llvm && \
    rm clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz

ENV PATH="/clang+llvm/bin:$PATH"
ENV LD_LIBRARY_PATH="/clang+llvm/lib:$LD_LIBRARY_PATH"
ENV CC=clang
ENV CXX=clang++

# Install Rust (stable)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable --no-modify-path
ENV PATH="/root/.cargo/bin:$PATH"

# Build Angora — installs tools to /angora/bin/
RUN git clone --depth 1 https://github.com/lysgoup/Reusing_mut.git /angora_src
RUN cd /angora_src && PREFIX=/angora/bin ./build/build.sh


# Stage 2: FuzzBench builder image
FROM $parent_image

ENV DEBIAN_FRONTEND=noninteractive

# Copy LLVM 11.1.0 — angora-clang invokes this clang at benchmark compile time
COPY --from=angora_builder /clang+llvm/ /clang+llvm/

# Copy Angora compiler wrapper, LLVM passes, runtime libs, and fuzzer binary
COPY --from=angora_builder /angora/bin/ /angora/bin/

# Copy tools (gen_library_abilist.sh is used at benchmark build time)
COPY --from=angora_builder /angora_src/tools/ /angora/tools/

ENV PATH="/clang+llvm/bin:/angora/bin:$PATH"
ENV LD_LIBRARY_PATH="/clang+llvm/lib:$LD_LIBRARY_PATH"

# Compile the libFuzzer harness proxy in two modes.
# Each .a provides main() that reads argv[1] and calls LLVMFuzzerTestOneInput.
# The Angora runtime is linked separately by angora-clang during benchmark build.
COPY libfuzz-harness-proxy.c /

RUN USE_FAST=1 /angora/bin/angora-clang \
        -c /libfuzz-harness-proxy.c -o /libfuzzer-harness-fast.o && \
    ar r /libfuzzer-harness-fast.a /libfuzzer-harness-fast.o

RUN USE_TRACK=1 /angora/bin/angora-clang \
        -c /libfuzz-harness-proxy.c -o /libfuzzer-harness-taint.o && \
    ar r /libfuzzer-harness-taint.a /libfuzzer-harness-taint.o
