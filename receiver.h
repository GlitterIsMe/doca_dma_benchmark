//
// Created by YiwenZhang on 2022/5/17.
//

#ifndef DOCA_DMA_RECEIVER_H
#define DOCA_DMA_RECEIVER_H

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include "dma_common.h"

class Receiver {
public:
    explicit Receiver (struct doca_pci_bdf *pcie_addr,
            const char *port, size_t blk_size, int depth,
            int core_num, int id) : block_size(blk_size) {
        dst_buffer = new char[block_size];
        dst_buffer_len = block_size;
        total_core_num = core_num;
        core_id = id;
        dma_jobs = new struct doca_dma_job_memcpy[depth];
        init_receiver(pcie_addr, port, depth + 1);
        total_blocks = remote_addr_len / total_core_num / block_size;
        local_remote_addr = remote_addr + (remote_addr_len / total_core_num * core_id);
    }

    ~Receiver();

    bool ExecuteDMAJobsRead();

    bool ExecuteDMAJobsRead(int blk_num, bool random);

    bool ExecuteDMAJobsReadMulti(int blk_num, bool random, int nums);

    bool ExecuteDMAJobsWrite();

    bool ExecuteDMAJobsWrite(int blk_num, bool random);

    bool ExecuteDMAJobsWriteMulti(int blk_num, bool random, int nums);

private:
    doca_error_t init_receiver(struct doca_pci_bdf *pcie_addr, const char *port, int buf_nums);
    bool receive_json_from_sender (const char *port, char *export_buffer, size_t export_buffer_len);
    void send_ack_to_sender() const;

    char* get_random_remote_block();
    char* get_remote_block(int blk_num, bool random);

    app_state state;
    int receiver_fd;
    int sender_fd;

    struct doca_event event = {0};
    struct doca_dma_job_memcpy* dma_jobs = nullptr;
    struct doca_dma_job_memcpy dma_job = {0};
    struct doca_mmap *remote_mmap;

    struct doca_buf *dst_doca_buf;

    static char export_json[1024];
    static char* remote_addr;
    static size_t remote_addr_len;
    char* local_remote_addr;

    char* dst_buffer;
    size_t dst_buffer_len;

    const size_t block_size {64};
    size_t total_blocks;

    int total_core_num;
    int core_id;

    static int exit_count;
};

#endif //DOCA_DMA_RECEIVER_H
