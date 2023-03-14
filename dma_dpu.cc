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
#define BENCHMARK_THREAD_NUM 1
#define BENCHMARK_DEPTH 64

const uint64_t BENCHMARK_OP_NUM = 1000000;
const uint64_t BENCHMARK_BLOCK_SIZE = 16;

#define f_seed 0xc70697UL
#define randomIO false

struct program_core_objects state = {0};
struct doca_dma *dma_ctx;
struct doca_buf **dst_doca_buf;
struct doca_mmap *remote_mmap;
struct doca_buf_inventory *remote_buf_inv;
struct doca_buf *remote_doca_buf;
char *remote_addr = NULL;
char** dpu_buffers;
size_t dst_buffer_size, remote_addr_len = 0, export_desc_len = 0;

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

doca_error_t init_dpu_side_buffer (char *export_desc_file_path, char *buffer_info_file_path, struct doca_pci_bdf *pcie_addr) {
    doca_error_t result;
    result = doca_dma_create(&dma_ctx);
    uint32_t max_chunks = 2048;
    char export_desc[1024] = {0};
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create DMA engine: %s", doca_get_error_string(result));
        return result;
    }

    state.ctx = doca_dma_as_ctx(dma_ctx);

    result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
    if (result != DOCA_SUCCESS) {
        doca_dma_destroy(dma_ctx);
        return result;
    }
// what's max_chunks
    result = init_core_objects(&state, DOCA_BUF_EXTENSION_NONE, WORKQ_DEPTH, max_chunks);
    if (result != DOCA_SUCCESS) {
        dma_cleanup(&state, dma_ctx);
        return result;
    }

    /* Copy all relevant information into local buffers */
    save_config_info_to_buffers(export_desc_file_path, buffer_info_file_path, export_desc, &export_desc_len,
                                &remote_addr, &remote_addr_len);

    /* Create a local DOCA mmap from exported data */
    result = doca_mmap_create_from_export(NULL, (const void *)export_desc, export_desc_len, state.dev,
                                          &remote_mmap);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Creating mmap from remote export failed: %s",
                     doca_get_error_string(result));
        dma_cleanup(&state, dma_ctx);
        return result;
    }

    return result;
};

doca_error_t create_dpu_buffer_and_mmap() {
    doca_error_t result;
    dpu_buffers = new char*[BENCHMARK_THREAD_NUM];
    dst_doca_buf = new struct doca_buf*[BENCHMARK_THREAD_NUM];
    for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
        // create local dpu buffer
        /* Copy the entire host buffer */
        size_t dst_buffer_size = BENCHMARK_BLOCK_SIZE;
        dpu_buffers[i] = (char *)malloc(dst_buffer_size);
        if (dpu_buffers[i] == NULL) {
            DOCA_LOG_ERR("Failed to allocate buffer memory");
            dma_cleanup(&state, dma_ctx);
            return DOCA_ERROR_NO_MEMORY;
        }

        result = doca_mmap_populate(state.mmap, dpu_buffers[i], dst_buffer_size, PAGE_SIZE, NULL, NULL);
        if (result != DOCA_SUCCESS) {
            free(dpu_buffers[i]);
            dma_cleanup(&state, dma_ctx);
            return result;
        }

        /* Construct DOCA buffer for each address range */
        result = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, dpu_buffers[i], dst_buffer_size, &dst_doca_buf[i]);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
                         doca_get_error_string(result));
            doca_mmap_destroy(remote_mmap);
            free(dpu_buffers[i]);
            dma_cleanup(&state, dma_ctx);
            return result;
        }
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
dma_copy_dpu(int thread_ID)
{
    /*struct program_core_objects state = {0};
    struct doca_event event = {0};
    struct doca_dma *dma_ctx;
    struct doca_buf *dst_doca_buf;
    struct doca_mmap *remote_mmap;*/
    doca_error_t result;
    struct timespec ts = {0};
    struct doca_event event = {0};
    /*uint32_t max_chunks = 2;
    char export_desc[1024] = {0};*/

    struct doca_buf **src_doca_bufs = new struct doca_buf*[BENCHMARK_DEPTH];
    struct doca_dma_job_memcpy* dma_jobs = new struct doca_dma_job_memcpy[BENCHMARK_DEPTH];
    char* local_remote_addr = remote_addr + (remote_addr_len / BENCHMARK_THREAD_NUM * thread_ID);
    size_t total_blocks = remote_addr_len / BENCHMARK_THREAD_NUM / BENCHMARK_BLOCK_SIZE;

    for(int blk_num = 0; blk_num < BENCHMARK_OP_NUM; blk_num += BENCHMARK_DEPTH){
        // init buffer
        for(int i = 0; i < BENCHMARK_DEPTH; i++){
            /* get_remote_block */
            unsigned int blk_no = blk_num + i;
            if (randomIO) {
                blk_no = hash::hash_funcs[0](&blk_no, sizeof(int), f_seed);
            }
            blk_no = blk_no % total_blocks;
            char* target_remote_buffer = local_remote_addr + blk_no * BENCHMARK_BLOCK_SIZE;
            assert(target_remote_buffer < remote_addr + remote_addr_len);
            /* Construct DOCA buffer for each address range */
            //result = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, target_remote_buffer, BENCHMARK_BLOCK_SIZE, &src_doca_bufs[i]);
            result = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, local_remote_addr, remote_addr_len / BENCHMARK_THREAD_NUM, &src_doca_bufs[i]);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s",
                            doca_get_error_string(result));
                doca_mmap_destroy(remote_mmap);
                for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
                    free(dpu_buffers[i]);
                }
                delete[] dpu_buffers;
                dma_cleanup(&state, dma_ctx);
                return result;
            }

            /* Construct DMA job */
            dma_jobs[i].base.type = DOCA_DMA_JOB_MEMCPY;
            dma_jobs[i].base.flags = DOCA_JOB_FLAGS_NONE;
            dma_jobs[i].base.ctx = state.ctx;
            if(BENCHMARK_TYPE_READ == true){
                // local dram buffer
                dma_jobs[i].dst_buff = dst_doca_buf[thread_ID];
                // host pm buffer
                dma_jobs[i].src_buff = src_doca_bufs[i];
                /* Set data position in src_buff */
                result = doca_buf_set_data(src_doca_bufs[i], target_remote_buffer, BENCHMARK_BLOCK_SIZE);
            }else{
                dma_jobs[i].dst_buff = src_doca_bufs[i];
                dma_jobs[i].src_buff = dst_doca_buf[thread_ID];
                /* Set data position in src_buff */
                result = doca_buf_set_data(dst_doca_buf[thread_ID], dpu_buffers[thread_ID], BENCHMARK_BLOCK_SIZE);
            }


            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to set data for DOCA buffer: %s", doca_get_error_string(result));
                return result;
            }
        }

        // submit request
        for(int i = 0;i < BENCHMARK_DEPTH;i++){
            /* Enqueue DMA job */
            result = doca_workq_submit(state.workq, &dma_jobs[i].base);
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(result));
                doca_buf_refcount_rm(dst_doca_buf[thread_ID], NULL);
                doca_buf_refcount_rm(src_doca_bufs[i], NULL);
                doca_mmap_destroy(remote_mmap);
                for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
                    free(dpu_buffers[i]);
                }
                delete[] dpu_buffers;
                dma_cleanup(&state, dma_ctx);
                return result;
            }
        }
        int total_completed = 0;
        for(int i=0; total_completed < BENCHMARK_DEPTH; i++){
            /* Wait for job completion */
            while ((result = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
                DOCA_ERROR_AGAIN) {
                ts.tv_nsec = SLEEP_IN_NANOS;
                nanosleep(&ts, &ts);
            }

            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("Failed to retrieve DMA job: %s", doca_get_error_string(result));
                // return result;
            }

            /* event result is valid */
            result = (doca_error_t)event.result.u64;
            if (result != DOCA_SUCCESS) {
                DOCA_LOG_ERR("DMA job event returned unsuccessfully: %s", doca_get_error_string(result));
                // return result;
            } else {
                total_completed++;
            }
        }

        for (int i = 0; i < BENCHMARK_DEPTH; ++i) {
            if (doca_buf_refcount_rm(src_doca_bufs[i], NULL) != DOCA_SUCCESS)
                DOCA_LOG_ERR("Failed to remove DOCA source buffer reference count");
        }

        // DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        // dpu_buffer[dst_buffer_size - 1] = '\0';
        // DOCA_LOG_INFO("Memory content: %s", dpu_buffer);
    }
    if (doca_buf_refcount_rm(dst_doca_buf[thread_ID], NULL) != DOCA_SUCCESS)
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

    result = init_dpu_side_buffer(dma_conf.export_desc_path, dma_conf.buf_info_path, &pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Init DPU buffer failed:%s\n", doca_get_error_string(result));
        return EXIT_FAILURE;
    }
    result = create_dpu_buffer_and_mmap();
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Create DPU buffer and mmap failed:%s\n", doca_get_error_string(result));
        return EXIT_FAILURE;
    }

    std::vector<std::thread> threads;
    threads.reserve(BENCHMARK_THREAD_NUM);

    auto start = std::chrono::high_resolution_clock::now();
    for(int i=0;i<BENCHMARK_THREAD_NUM;i++){
        threads.emplace_back(dma_copy_dpu, i);
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
    if (doca_mmap_destroy(remote_mmap) != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy remote memory map");

    /* Inform host that DMA operation is done */
    DOCA_LOG_INFO("Host sample can be closed, DMA copy ended");

    /* Clean and destroy all relevant objects */
    dma_cleanup(&state, dma_ctx);

    //free(dpu_buffer);
    for (int i = 0; i < BENCHMARK_THREAD_NUM; ++i) {
        free(dpu_buffers[i]);
    }
    delete[] dpu_buffers;

    doca_argp_destroy();

    return EXIT_SUCCESS;
}
