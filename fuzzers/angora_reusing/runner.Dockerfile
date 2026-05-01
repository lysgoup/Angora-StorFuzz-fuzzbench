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

FROM gcr.io/fuzzbench/base-image

# Angora's fuzzer binary calls `llvm-config --libdir` at runtime to locate the
# DFSan runtime library before executing the taint binary.
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
RUN wget -q https://github.com/llvm/llvm-project/releases/download/llvmorg-11.1.0/clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    tar -C / -xf clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz && \
    mv /clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04 /clang+llvm && \
    rm clang+llvm-11.1.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz

ENV PATH="/clang+llvm/bin:$PATH"
ENV LD_LIBRARY_PATH="/clang+llvm/lib:$LD_LIBRARY_PATH"
