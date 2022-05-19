#! /bin/bash

# for DPU
./dma_test --is_server=0 --ops=1000000 --benchmarks=write --random=true --block_size=64 --threads=8 --depth=32

# for server
sudo ./dma_test --is_server=1 --use_pmem=true --pmem_path=/dev/dax0.3 --threads=8