#!/usr/bin/env bash
# Fetches the official UNSW-NB15 training/testing partition (not redistributed here; see the dataset's terms).
# Mirror used: github.com/emirhanaydin60/UNSW-NB15-ML (data/UNSW_NB15_{training,testing}-set.csv)
set -e
mkdir -p data && cd data
git clone --depth 1 --filter=blob:none --sparse https://github.com/emirhanaydin60/UNSW-NB15-ML.git _tmp
(cd _tmp && git sparse-checkout set data)
cp _tmp/data/UNSW_NB15_training-set.csv _tmp/data/UNSW_NB15_testing-set.csv . && rm -rf _tmp
