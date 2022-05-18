#include <iostream>
#include <doca_buf.h>
#include <libpmem.h>
#include <gflags/gflags.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <doca_dev.h>
#include <chrono>

#include "receiver.h"
#include "sender.h"
#include "histogram.h"

DEFINE_bool(is_server, true, "True means Sender (Host), False means Receiver (DPU)");

// Server / Host
DEFINE_bool(use_pmem, true, "Use PMEM or DRAM");
DEFINE_string(pmem_path, "/dev/dax0.3", "The path of the pmem device");
DEFINE_uint64(buf_size, 32UL * 1024 * 1024 * 1024, "The size of pmem device");
DEFINE_string(receiver_ip, "192.168.100.2", "The ip of the receiver");
DEFINE_int32(receiver_port, 45678, "The port of the receiver");

// DPU
DEFINE_int64(block_size, 64, "The size of each IO");
DEFINE_int64(ops, 100, "Total number of operations");
DEFINE_bool(random, true, "Perform random IO or not");
DEFINE_string(benchmarks, "read", "The type of benchmarks");
DEFINE_int32(depth, 32, "The size of DMA queue");

int main(int argc, char** argv) {
    google::ParseCommandLineFlags(&argc, &argv, false);
    if (FLAGS_is_server) {
        // Server
        size_t mapped_len;
        int is_pmem;
        char* buf;
        size_t buf_size = FLAGS_buf_size;
        if (FLAGS_use_pmem) {
            buf = (char*)pmem_map_file(FLAGS_pmem_path.c_str(), 0, PMEM_FILE_CREATE, 0666, &mapped_len, &is_pmem);
            if (buf == nullptr) {
                fprintf(stderr, "map pmem file failed : %s\n", strerror(errno));
            }
        } else {
            char* buf = new char[buf_size];
        }

        struct doca_pci_bdf pci_bdf;
        pci_bdf.bus = 0xaf;
        pci_bdf.device = 0x00;
        pci_bdf.function = 0x0;

        char* ip = new char[FLAGS_receiver_ip.size() + 1];
        memcpy(ip, FLAGS_receiver_ip.c_str(), FLAGS_receiver_ip.size());
        ip[FLAGS_receiver_ip.size()] = 0;
        auto sender = new Sender(&pci_bdf, buf, buf_size, ip, FLAGS_receiver_port);
        sender->WaitingForExit();

        printf("Server shutdown\n");
        delete[] ip;
        delete sender;
        if (FLAGS_use_pmem) {
            pmem_unmap(buf, mapped_len);
        } else {
            delete[] buf;
        }
    } else {
        // DPU
        struct doca_pci_bdf pci_bdf;
        pci_bdf.bus = 0x03;
        pci_bdf.device = 0x00;
        pci_bdf.function = 0x0;
        auto receiver = new Receiver(&pci_bdf, "45678", FLAGS_block_size, FLAGS_depth);
        auto hist = leveldb::Histogram();
        if (FLAGS_benchmarks == "read") {
            auto start = std::chrono::high_resolution_clock::now();
            for (int i = 0; i < FLAGS_ops; i = i + FLAGS_depth) {
                receiver->ExecuteDMAJobsReadMulti(i, FLAGS_random, FLAGS_depth);
                //printf("%lf\n", dma_read_lat.count());
                //hist.Add(dma_read_lat.count());
            }
            auto end1 = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double, std::micro> dma_read_lat = end1 - start;
            printf("Finish %d ops with %d B blocks in %lf s\n", FLAGS_ops, FLAGS_block_size, dma_read_lat.count() / 1000000);
            printf("DMA %s read throughput: %lf KOPS\n", FLAGS_random ? "random" : "sequential", FLAGS_ops / dma_read_lat.count() * 1000000 / 1000);
            printf("DMA %s read bandwidth: %lf MB/s\n", FLAGS_random ? "random" : "sequential", FLAGS_ops * FLAGS_block_size / 1024.0 / 1024.0 / dma_read_lat.count() * 1000000 / 1000);
        } else if (FLAGS_benchmarks == "write") {
            for (int i = 0; i < FLAGS_ops; ++i) {
                auto end1 = std::chrono::high_resolution_clock::now();
                receiver->ExecuteDMAJobsWrite(i, FLAGS_random);
                auto end2 = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double, std::micro> dma_write_lat = end2 - end1;
                hist.Add(dma_write_lat.count());
            }
            printf("DMA random write lat: %s\n", hist.ToString().c_str());
        }
        delete receiver;
    }
    return 0;
}
