# StorFuzz

This repository contains the FuzzBench source code including all fuzzer configurations used for the ICSE 2026 paper "StorFuzz: Using Data Diversity to Overcome Fuzzing Plateaus". It is based on FuzzBench revision ([2a2ca6a](https://github.com/google/fuzzbench/commit/2a2ca6ae4c5d171a52b3e20d9b7a72da306fe5b8)).

The complete artifacts can be found at [rub-softsec/StorFuzz](https://github.com/rub-softsec/StorFuzz).

The original README can be found at the bottom.

## FuzzBench Quick-Start

### Setup

To setup FuzzBench, you just need to clone this repository and create a Python 3.10 virtual environment at `.venv`. In the environment install all required Python modules by running `source .venv/bin/activate ; python -m pip install -r requirements.txt`. You also need a working docker installation.

You may also need to update `config.yaml` to suit your needs. It should be self explanatory. Keep in mind that docker build cache and longer experiments can use up a lot of disk space.

If you want to use custom seed corpora, make sure the extracted corpora are located in folders named exactly like the benchmarks:

```
custom_seed_corpora
├── bloaty_fuzz_target
├── curl_curl_fuzzer_http
├── freetype2_ftfuzzer
├── ...
└── zlib_zlib_uncompress_fuzzer
```

### Starting Experiments

It is advisable to run this inside a `screen` or `tmux` session.
You can omit the custom seed corpus option `-cs` if you want to simply use the default seeds shipped with FuzzBench.

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e <experiment_name> \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs <custom_seed_corpus_location> \
  -b <benchmark_name> <benchmark_name> ... \
  -f <fuzzer_name> <fuzzer_name> ...
```

Note 1: In case you encounter build failures, it might help to reduce the number of concurrent builds (`-cb`).

## Paper Experiments

To replicate experiments from the paper we provide the configurations below.
Beware that the concrete results may depend on the concrete hardware, the load and other factors.

We assume that the provided corpora are located in `/corpora` please adjust the commands accordingly.

### 4.3 Getting to the Plateau

Adjust config settings:
```yaml
trials: 5
max_total_time: 432000 # (5 days)
```

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e getting-to-the-plateau \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs /corpora/oss-fuzz_corpora \
  -b bloaty_fuzz_target curl_curl_fuzzer_http freetype2_ftfuzzer \
     harfbuzz_hb-shape-fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer \
     libjpeg-turbo_libjpeg_turbo_fuzzer libpcap_fuzz_both libpng_libpng_read_fuzzer \
     libxml2_xml libxslt_xpath mbedtls_fuzz_dtlsclient openh264_decoder_fuzzer \
     openssl_x509 openthread_ot-ip6-send-fuzzer proj4_proj_crs_to_crs_fuzzer \
     re2_fuzzer sqlite3_ossfuzz stb_stbi_read_fuzzer systemd_fuzz-link-parser \
     vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer zlib_zlib_uncompress_fuzzer \
  -f libafl_stats
```

For the saturated corpora (`/corpora/saturated_with_libafl`) extract all corpus entries from the snapshots of all trials. Merge per benchmark and deduplicate with `sha256sum`.

### 4.4 Escaping the Plateau

Adjust config settings:
```yaml
trials: 10
max_total_time: 86400 # (1 day)
```

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e  escaping-the-plateau \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs /corpora/saturated_with_libafl \
  -b bloaty_fuzz_target curl_curl_fuzzer_http freetype2_ftfuzzer \
     harfbuzz_hb-shape-fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer \
     libjpeg-turbo_libjpeg_turbo_fuzzer libpcap_fuzz_both libpng_libpng_read_fuzzer \
     libxml2_xml libxslt_xpath mbedtls_fuzz_dtlsclient openh264_decoder_fuzzer \
     openssl_x509 openthread_ot-ip6-send-fuzzer proj4_proj_crs_to_crs_fuzzer \
     re2_fuzzer sqlite3_ossfuzz stb_stbi_read_fuzzer systemd_fuzz-link-parser \
     vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer zlib_zlib_uncompress_fuzzer \
  -f storfuzz libafl_stats ddfuzz_libafl
```

### 4.6 Transferring the Diversity: LibAFL

Adjust config settings:
```yaml
trials: 10
max_total_time: 345600 # (4 days)
```

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e transferring-diversity-libafl \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs /corpora/saturated_with_libafl \
  -b bloaty_fuzz_target curl_curl_fuzzer_http freetype2_ftfuzzer \
     harfbuzz_hb-shape-fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer \
     libjpeg-turbo_libjpeg_turbo_fuzzer libpcap_fuzz_both libpng_libpng_read_fuzzer \
     libxml2_xml libxslt_xpath mbedtls_fuzz_dtlsclient openh264_decoder_fuzzer \
     openssl_x509 openthread_ot-ip6-send-fuzzer proj4_proj_crs_to_crs_fuzzer \
     re2_fuzzer sqlite3_ossfuzz stb_stbi_read_fuzzer systemd_fuzz-link-parser \
     vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer zlib_zlib_uncompress_fuzzer \
  -f storfuzz_24_libafl_24_switch libafl_24_libafl_24_switch ddfuzz_24_libafl_24_switch
```


### 4.7 Transferring the Diversity: WingFuzz

To saturate with libFuzzer use the instructions from 4.3 Getting to the Plateau, replace `libafl_stats` with `libfuzzer` and choose a different experiment name.


Adjust config settings:
```yaml
trials: 10
max_total_time: 345600 # (4 days)
```

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e transferring-diversity-wingfuzz \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs /corpora/saturated_with_libfuzzer_and_libafl \
  -b bloaty_fuzz_target curl_curl_fuzzer_http freetype2_ftfuzzer \
     harfbuzz_hb-shape-fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer \
     libjpeg-turbo_libjpeg_turbo_fuzzer libpcap_fuzz_both libpng_libpng_read_fuzzer \
     libxml2_xml libxslt_xpath mbedtls_fuzz_dtlsclient openh264_decoder_fuzzer \
     openssl_x509 openthread_ot-ip6-send-fuzzer proj4_proj_crs_to_crs_fuzzer \
     re2_fuzzer sqlite3_ossfuzz stb_stbi_read_fuzzer systemd_fuzz-link-parser \
     vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer zlib_zlib_uncompress_fuzzer \
  -f storfuzz_24_libafl_24_switch wingfuzz_24_libfuzzer_24_switch
```


### 4.9 Ablation Study

Adjust config settings:
```yaml
trials: 10
max_total_time: 86400 # (1 day)
```

```bash
source .venv/bin/activate
PYTHONPATH=. python experiment/run_experiment.py \
  -c config.yaml \
  -e transferring-diversity-wingfuzz \
  -cb <number_of_concurrent_builds> \
  -rc <number_of_cores_used_for_fuzzing> \
  -mc <number_of_cores_used_for_measuring_coverage> \
  -cs /corpora/saturated_with_libafl \
  -b bloaty_fuzz_target curl_curl_fuzzer_http freetype2_ftfuzzer \
     harfbuzz_hb-shape-fuzzer jsoncpp_jsoncpp_fuzzer lcms_cms_transform_fuzzer \
     libjpeg-turbo_libjpeg_turbo_fuzzer libpcap_fuzz_both libpng_libpng_read_fuzzer \
     libxml2_xml libxslt_xpath mbedtls_fuzz_dtlsclient openh264_decoder_fuzzer \
     openssl_x509 openthread_ot-ip6-send-fuzzer proj4_proj_crs_to_crs_fuzzer \
     re2_fuzzer sqlite3_ossfuzz stb_stbi_read_fuzzer systemd_fuzz-link-parser \
     vorbis_decode_fuzzer woff2_convert_woff2ttf_fuzzer zlib_zlib_uncompress_fuzzer \
  -f storfuzz_reduction_width_12 storfuzz_reduction_width_16 \
     storfuzz_reduction_width_4 storfuzz_stores_per_bb_1 \
     storfuzz_stores_per_bb_20 storfuzz_stores_per_bb_5 \
     storfuzz_stores_per_bb_65536 storfuzz_with_mem2mem
```

---

# FuzzBench: Fuzzer Benchmarking As a Service

FuzzBench is a free service that evaluates fuzzers on a wide variety of
real-world benchmarks, at Google scale. The goal of FuzzBench is to make it
painless to rigorously evaluate fuzzing research and make fuzzing research
easier for the community to adopt. We invite members of the research community
to contribute their fuzzers and give us feedback on improving our evaluation
techniques.

FuzzBench provides:

* An easy API for integrating fuzzers.
* Benchmarks from real-world projects. FuzzBench can use any
  [OSS-Fuzz](https://github.com/google/oss-fuzz) project as a benchmark.
* A reporting library that produces reports with graphs and statistical tests
  to help you understand the significance of results.

To participate, submit your fuzzer to run on the FuzzBench platform by following
[our simple guide](
https://google.github.io/fuzzbench/getting-started/).
After your integration is accepted, we will run a large-scale experiment using
your fuzzer and generate a report comparing your fuzzer to others.
See [a sample report](https://www.fuzzbench.com/reports/sample/index.html).

## Overview
<kbd>
  
![FuzzBench Service diagram](docs/images/FuzzBench-service.png)
  
</kbd>


## Sample Report

You can view our sample report
[here](https://www.fuzzbench.com/reports/sample/index.html) and
our periodically generated reports
[here](https://www.fuzzbench.com/reports/index.html).
The sample report is generated using 10 fuzzers against 24 real-world
benchmarks, with 20 trials each and over a duration of 24 hours.
The raw data in compressed CSV format can be found at the end of the report.

When analyzing reports, we recommend:
* Checking the strengths and weaknesses of a fuzzer against various benchmarks.
* Looking at aggregate results to understand the overall significance of the
  result.

Please provide feedback on any inaccuracies and potential improvements (such as
integration changes, new benchmarks, etc.) by opening a GitHub issue
[here](https://github.com/google/fuzzbench/issues/new).

## Documentation

Read our [detailed documentation](https://google.github.io/fuzzbench/) to learn
how to use FuzzBench.

## Contacts

Join our [mailing list](https://groups.google.com/forum/#!forum/fuzzbench-users)
for discussions and announcements, or send us a private email at
[fuzzbench@google.com](mailto:fuzzbench@google.com).
