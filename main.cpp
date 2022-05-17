#include <iostream>
#include <doca_buf.h>
#include <libpmem.h>
#include <gflags/gflags.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <doca_dev.h>

#include "receiver.h"
#include "sender.h"

DEFINE_bool(is_server, true, "True means Sender (Host), False means Receiver (DPU)");

// Server / Host
DEFINE_string(pmem_path, "/dev/dax0.0", "The path of the pmem device");
DEFINE_uint64(pmem_size, 64UL * 1024 * 1024 * 1024, "The size of pmem device");
DEFINE_string(receiver_ip, "192.168.100.2", "The ip of the receiver");
DEFINE_int32(receiver_port, 45678, "The port of the receiver");

int main(int argc, char** argv) {
    google::ParseCommandLineFlags(&argc, &argv, false);
    if (FLAGS_is_server) {
        size_t mapped_len;
        int is_pmem;
        char* buf = new char[1024];
        size_t buf_size = 1024;
        /*char* pmem_buf = (char*)pmem_map_file(FLAGS_pmem_path.c_str(), 0, PMEM_FILE_CREATE, 0666, &mapped_len, &is_pmem);
        if (pmem_buf == nullptr) {
            fprintf(stderr, "map pmem file failed : %s\n", strerror(errno));
        }*/
        for (int i = 0; i < 1024; ++i) {
            buf[i] = 'a' + i % 25;
        }
        //memset(buf, 'a', buf_size);
        buf[1023] = 0;
        struct doca_pci_bdf pci_bdf;
        pci_bdf.bus = 0xaf;
        pci_bdf.device = 0x00;
        pci_bdf.function = 0x0;

        char* ip = new char[FLAGS_receiver_ip.size() + 1];
        memcpy(ip, FLAGS_receiver_ip.c_str(), FLAGS_receiver_ip.size());
        ip[FLAGS_receiver_ip.size()] = 0;
        auto sender = new Sender(&pci_bdf, buf, buf_size, ip, FLAGS_receiver_port);
        sender->WaitingForExit();
        printf("Server buffer %s\n", buf);
        delete[] ip;
        delete sender;
        delete[] buf;
    } else {
        struct doca_pci_bdf pci_bdf;
        pci_bdf.bus = 0x03;
        pci_bdf.device = 0x00;
        pci_bdf.function = 0x0;
        auto receiver = new Receiver(&pci_bdf, "45678");
        receiver->ExecuteDMAJobsRead();
        receiver->ExecuteDMAJobsWrite();
        delete receiver;
    }
    return 0;
}
