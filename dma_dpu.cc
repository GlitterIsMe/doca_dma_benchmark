/*
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <vector>
#include <thread>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <cassert>

#include "utils.h"
#include "dma_common.h"
#include "hash.h"

DOCA_LOG_REGISTER(DMA_COPY_DPU::MAIN);

//DOCA_LOG_REGISTER(DMA_COPY_DPU);

#define SLEEP_IN_NANOS (10 * 1000)	/* Sample the job every 10 microseconds  */
#define MAX_DMA_BUF_SIZE (1024 * 1024)	/* DMA buffer maximum size */
#define RECV_BUF_SIZE 256		/* Buffer which contains config information */

#define BENCHMARK_TYPE_READ false /* true: read, false: write */
#define BENCHMARK_THREAD_NUM 4
#define BENCHMARK_DEPTH 64

const uint64_t BENCHMARK_OP_NUM = 1000000;
const uint64_t BENCHMARK_BLOCK_SIZE = 16;

#define f_seed 0xc70697UL
#define randomIO false

struct doca_dma_context {
    struct program_core_objects state = {0};
    struct doca_dma *dma_ctx;
    struct doca_mmap *remote_mmap;
    char* dpu_buffer;
    struct doca_buf* dst_doca_buf;
} thread_ctxs[BENCHMARK_THREAD_NUM];

/*struct program_core_objects state = {0};
struct doca_dma *dma_ctx;
struct doca_buf **dst_doca_buf;
struct doca_mmap *remote_mmap;
char** dpu_buffers;*/
char *remote_addr = NULL;
char export_desc[1024] = {0};
size_t remote_addr_len = 0, export_desc_len = 0;

/*
 * Saves export descriptor and buffer information content into memory buffers
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @export_desc [in]: Export descriptor buffer
 * @export_desc_len [in]: Export descriptor buffer length
 * @remote_addr [in]: Remote buffer address
 * @remote_addr_len [in]: Remote buffer total length
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
save_config_info_to_buffers(const char *export_desc_file_path, const char *buffer_info_file_path, char *export_desc,
                            size_t *export_desc_len, char **remote_addr, size_t *remote_addr_len)
{
    FILE *fp;
    long file_size;
    char buffer[RECV_BUF_SIZE];

    fp = fopen(export_desc_file_path, "r");
    if (fp == NULL) {
        DOCA_LOG_ERR("Failed to open %s", export_desc_file_path);
        return DOCA_ERROR_IO_FAILED;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        DOCA_LOG_ERR("Failed to calculate file size");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }

    file_size = ftell(fp);
    if (file_size == -1) {
        DOCA_LOG_ERR("Failed to calculate file size");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }

    if (file_size > MAX_DMA_BUF_SIZE)
        file_size = MAX_DMA_BUF_SIZE;

    *export_desc_len = file_size;

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        DOCA_LOG_ERR("Failed to calculate file size");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }

    if (fread(export_desc, 1, file_size, fp) != file_size) {
        DOCA_LOG_ERR("Failed to allocate memory for source buffer");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }

    fclose(fp);

    /* Read source buffer information from file */
    fp = fopen(buffer_info_file_path, "r");
    if (fp == NULL) {
        DOCA_LOG_ERR("Failed to open %s", buffer_info_file_path);
        return DOCA_ERROR_IO_FAILED;
    }

    /* Get source buffer address */
    if (fgets(buffer, RECV_BUF_SIZE, fp) == NULL) {
        DOCA_LOG_ERR("Failed to read the source (host) buffer address");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }
    *remote_addr = (char *)strtoull(buffer, NULL, 0);

    memset(buffer, 0, RECV_BUF_SIZE);

    /* Get source buffer length */
    if (fgets(buffer, RECV_BUF_SIZE, fp) == NULL) {
        DOCA_LOG_ERR("Failed to read the source (host) buffer length");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }
    *remote_addr_len = strtoull(buffer, NULL, 0);

    fclose(fp);

    return DOCA_SUCCESS;
}

doca_error_t init_doca_dma_and_host_mmap (doca_dma_context* ctx, char *export_desc_file_path, char *buffer_info_file_path, struct doca_pci_bdf *pcie_addr) {
    doca_error_t result;
    result = doca_dma_create(&ctx->dma_ctx);
    uint32_t max_chunks = 1024;
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
        return result;
    }

    ctx->state.ctx = doca_dma_as_ctx(ctx->dma_ctx);

    result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &ctx->state.dev);
    if (result != DOCA_SUCCESS) {
        doca_dma_destroy(ctx->dma_ctx);
        return result;
    }
// what's max_chunks
    result = init_core_objects(&ctx->state, DOCA_BUF_EXTENSION_NONE, WORKQ_DEPTH, max_chunks);
    if (result != DOCA_SUCCESS) {
        dma_cleanup(&ctx->state, ctx->dma_ctx);
        return result;
    }

    /* Create a local DOCA mmap from exported data */
    result = doca_mmap_create_from_export(NULL, (const void *)export_desc, export_desc_len, ctx->state.dev,
                                          &ctx->remote_mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Creating mmap from remote export failed: %s",
                     doca_get_error_string(result));
        dma_cleanup(&ctx->state, ctx->dma_ctx);
        return result;
    }

    return result;
};

doca_error_t create_dpu_buffer_and_mmap(doca_dma_context* ctx) {
    doca_error_t result;
    size_t dst_buffer_size = BENCHMARK_BLOCK_SIZE;
    ctx->dpu_buffer = (char *)malloc(dst_buffer_size);
    if (ctx->dpu_buffer == NULL) {
        DOCA_LOG_ERR("Failed to allocate buffer memory");
        dma_cleanup(&ctx->state, ctx->dma_ctx);
        return DOCA_ERROR_NO_MEMORY;
    }
    result = doca_mmap_populate(ctx->state.mmap, ctx->dpu_buffer, dst_buffer_size, PAGE_SIZE, NULL, NULL);
    if (result != DOCA_SUCCESS) {
        free(ctx->dpu_buffer);
        dma_cleanup(&ctx->state, ctx->dma_ctx);
        return result;
    }

    /* Construct DOCA buffer for each address range */
    result = doca_buf_inventory_buf_by_addr(ctx->state.buf_inv, ctx->state.mmap, ctx->dpu_buffer, dst_buffer_size, &ctx->dst_doca_buf);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
                     doca_get_error_string(result));
        doca_mmap_destroy(ctx->remote_mmap);
        free(ctx->dpu_buffer);
        dma_cleanup(&ctx->state, ctx->dma_ctx);
        return result;
    }
    return result;
}

/*
 * Run DOCA DMA DPU copy sample
 *
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer info file path
 * @pcie_addr [in]: Device PCI address
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
dma_copy_dpu(doca_dma_context* ctx, int thread_ID)
{
    doca_error_t result;
    struct timespec ts = {0};
    struct doca_event event = {0};

    //struct doca_buf **src_doca_bufs = new struct doca_buf*[BENCHMARK_DEPTH];
    struct doca_buf *src_doca_bufs;
    struct doca_dma_job_memcpy* dma_jobs = new struct doca_dma_job_memcpy[BENCHMARK_DEPTH];
    char* local_remote_addr = remote_addr + (remote_addr_len / BENCHMARK_THREAD_NUM * thread_ID);
    size_t total_blocks = remote_addr_len / BENCHMARK_THREAD_NUM / BENCHMARK_BLOCK_SIZE;

    int pending_request = 0;
    int finished = 0;
    bool last = false;

    for(int blk_num = 0; blk_num < BENCHMARK_OP_NUM; blk_num++){
        // init buffer
        if (blk_num == BENCHMARK_OP_NUM - 1) last = true;
        struct doca_buf *src_doca_bufs;
        unsigned int blk_no = blk_num;
        if (randomIO) {
            blk_no = hash::hash_funcs[0](&blk_no, sizeof(int), f_seed);
        }
        blk_no = blk_no % total_blocks;
        char* target_remote_buffer = local_remote_addr + blk_no * BENCHMARK_BLOCK_SIZE;
        assert(target_remote_buffer < remote_addr + remote_addr_len);
        /* Construct DOCA buffer for each address range */
        //result = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, target_remote_buffer, BENCHMARK_BLOCK_SIZE, &src_doca_bufs[i]);
        result = doca_buf_inventory_buf_by_addr(ctx->state.buf_inv, ctx->remote_mmap, local_remote_addr, remote_addr_len / BENCHMARK_THREAD_NUM, &src_doca_bufs);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s",
                         doca_get_error_string(result));
            doca_mmap_destroy(ctx->remote_mmap);
            free(ctx->dpu_buffer);
            dma_cleanup(&ctx->state, ctx->dma_ctx);
            return result;
        }
        /* Construct DMA job */
        struct doca_dma_job_memcpy dma_jobs;
        dma_jobs.base.type = DOCA_DMA_JOB_MEMCPY;
        dma_jobs.base.flags = DOCA_JOB_FLAGS_NONE;
        dma_jobs.base.ctx = ctx->state.ctx;
        dma_jobs.base.user_data.ptr = (void*) src_doca_bufs;
        if(BENCHMARK_TYPE_READ == true){
            // local dram buffer
            dma_jobs.dst_buff = ctx->dst_doca_buf;
            // host pm buffer
            dma_jobs.src_buff = src_doca_bufs;
            /* Set data position in src_buff */
            result = doca_buf_set_data(src_doca_bufs, target_remote_buffer, BENCHMARK_BLOCK_SIZE);
        }else{
            dma_jobs.dst_buff = src_doca_bufs;
            dma_jobs.src_buff = ctx->dst_doca_buf;
            /* Set data position in src_buff */
            result = doca_buf_set_data(ctx->dst_doca_buf, ctx->dpu_buffer, BENCHMARK_BLOCK_SIZE);
        }

        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
            return result;
        }

        // submit
        result = doca_workq_submit(ctx->state.workq, &dma_jobs.base);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
            doca_buf_refcount_rm(ctx->dst_doca_buf, NULL);
            doca_buf_refcount_rm(src_doca_bufs, NULL);
            doca_mmap_destroy(ctx->remote_mmap);
            free(ctx->dpu_buffer);
            dma_cleanup(&ctx->state, ctx->dma_ctx);
            return result;
        }
        pending_request++;

        // poll
        do {
            result = doca_workq_progress_retrieve(ctx->state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE);
            if (result == DOCA_SUCCESS) {
                pending_request--;
                finished++;
                result = (doca_error_t)event.result.u64;
                if (result != DOCA_SUCCESS) {
                    DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
                    // return result;
                }
                struct doca_buf *old_src_buf = (struct doca_buf*)event.user_data.ptr;
                if (doca_buf_refcount_rm(old_src_buf, NULL) != DOCA_SUCCESS)
                    DOCA_LOG_ERR("Failed to remove DOCA source buffer reference count");

            } else if (result == DOCA_ERROR_AGAIN) {
                // nothing
            } else {
                DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
                break;
            }
        } while ((!last && pending_request >= BENCHMARK_DEPTH) | (last && finished < BENCHMARK_OP_NUM));

    }
    if (doca_buf_refcount_rm(ctx->dst_doca_buf, NULL) != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to remove DOCA destination buffer reference count");

    delete[] src_doca_bufs;
    delete[] dma_jobs;
    return DOCA_SUCCESS;

}

/*
 * Sample main function
 *
 * @argc [in]: command line arguments size
 * @argv [in]: array of command line arguments
 * @return: EXIT_SUCCESS on success and EXIT_FAILURE otherwise
 */
int
main(int argc, char **argv)
{
    struct dma_config dma_conf = {0};
    struct doca_pci_bdf pcie_dev;
    doca_error_t result;

    strcpy(dma_conf.pci_address, "03:00.0");
    strcpy(dma_conf.export_desc_path, "/tmp/export_desc.txt");
    strcpy(dma_conf.buf_info_path, "/tmp/buffer_info.txt");

    result = doca_argp_init("dma_copy_dpu", &dma_conf);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_get_error_string(result));
        return EXIT_FAILURE;
    }
    result = register_dma_params();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register DMA sample parameters: %s", doca_get_error_string(result));
        return EXIT_FAILURE;
    }

    result = doca_argp_start(argc, argv);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse sample input: %s", doca_get_error_string(result));
        return EXIT_FAILURE;
    }
#ifndef DOCA_ARCH_DPU
    DOCA_LOG_ERR("Sample can run only on the DPU");
    doca_argp_destroy();
    return EXIT_FAILURE;
#endif
    result = parse_pci_addr(dma_conf.pci_address, &pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
        return EXIT_FAILURE;
    }

    /* Copy all relevant information into local buffers */
    save_config_info_to_buffers(dma_conf.export_desc_path, dma_conf.buf_info_path, export_desc, &export_desc_len,
                                &remote_addr, &remote_addr_len);

    for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
        result = init_doca_dma_and_host_mmap(&thread_ctxs[i], dma_conf.export_desc_path, dma_conf.buf_info_path, &pcie_dev);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Init DPU buffer failed:%s\n", doca_get_error_string(result));
            return EXIT_FAILURE;
        }
        result = create_dpu_buffer_and_mmap(&thread_ctxs[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Create DPU buffer and mmap failed:%s\n", doca_get_error_string(result));
            return EXIT_FAILURE;
        }
    }
    std::vector<std::thread> threads;
    threads.reserve(BENCHMARK_THREAD_NUM);

    auto start = std::chrono::high_resolution_clock::now();
    for(int i=0;i<BENCHMARK_THREAD_NUM;i++){
        threads.emplace_back(dma_copy_dpu, &thread_ctxs[i], i);
    }
    for(int i=0;i<BENCHMARK_THREAD_NUM;i++){
        threads[i].join();
    }
    auto end1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::micro> dma_lat = end1 - start;
    const char* type = BENCHMARK_TYPE_READ ? "read" : "write";
    printf("Finish %d ops with %d B blocks in %lf s\n", BENCHMARK_OP_NUM, BENCHMARK_BLOCK_SIZE, dma_lat.count() / 1000000);
    printf("DMA %s %s throughput: %lf KOPS\n", randomIO ? "random" : "sequential", type, BENCHMARK_OP_NUM / dma_lat.count() * 1000000 / 1000);
    printf("DMA %s %s bandwidth: %lf MB/s\n", randomIO ? "random" : "sequential", type, BENCHMARK_OP_NUM * BENCHMARK_BLOCK_SIZE / 1024.0 / 1024.0 / dma_lat.count() * 1000000);

    // if (result != DOCA_SUCCESS) {
    //     DOCA_LOG_ERR("Sample function has failed: %s", doca_get_error_string(result));
    //     doca_argp_destroy();
    //     return EXIT_FAILURE;
    // }

    /* Destroy remote memory map */
    for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
        if (doca_mmap_destroy(thread_ctxs[i].remote_mmap) != DOCA_SUCCESS)
            DOCA_LOG_ERR("Failed to destroy remote memory map");
        /* Clean and destroy all relevant objects */
        dma_cleanup(&thread_ctxs[i].state, thread_ctxs[i].dma_ctx);
        free(thread_ctxs[i].dpu_buffer);
    }
    /* Inform host that DMA operation is done */
    DOCA_LOG_INFO("Host sample can be closed, DMA copy ended");
    doca_argp_destroy();

    return EXIT_SUCCESS;
}
