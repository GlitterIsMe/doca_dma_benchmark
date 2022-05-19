//
// Created by YiwenZhang on 2022/5/17.
//

#ifndef DOCA_DMA_DMA_COMMON_H
#define DOCA_DMA_DMA_COMMON_H

#include <stdint.h>
#include <doca_error.h>
#include <stddef.h>

struct app_state {
    struct doca_dev *dev;
    struct doca_mmap *mmap;
    struct doca_buf_inventory *buf_inv;
    struct doca_ctx *ctx;
    struct doca_dma *dma_ctx;
    struct doca_workq *workq;
};

doca_error_t open_local_device(struct doca_pci_bdf *pcie_addr, struct app_state *state);

doca_error_t create_core_objects(struct app_state *state, int buf_inv_num_elems);

doca_error_t init_core_objects(struct app_state *state, uint32_t max_chunks);

doca_error_t init_core_objects_sender(struct app_state *state);

doca_error_t populate_mmap(struct doca_mmap *mmap, char *buffer, size_t length, size_t pg_sz);

void cleanup_core_objects(struct app_state *state);

void destroy_core_objects(struct app_state *state);

void destroy_core_objects_sender(struct app_state *state);

#endif //DOCA_DMA_DMA_COMMON_H
