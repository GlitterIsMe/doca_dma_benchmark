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
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <cerrno>

#include <doca_argp.h>
#include <doca_dev.h>
#include <doca_log.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_mmap.h>

#include <libpmem.h>

#include "utils.h"
#include "dma_common.h"

#define _GB 1024*1024*1024UL

#define USE_PMEM

DOCA_LOG_REGISTER(DMA_COPY_HOST::MAIN);
//DOCA_LOG_REGISTER(DMA_COPY_HOST);

bool is_dma_done_on_dpu;	/* Shared variable to allow for a proper shutdown */

/*
 * Signal handler
 *
 * @signum [in]: Signal number to handle
 */
static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        DOCA_LOG_INFO("Signal %d received, preparing to exit...", signum);
        is_dma_done_on_dpu = true;
    }
}

/*
 * Saves export descriptor and buffer information into two separate files
 *
 * @export_desc [in]: Export descriptor to write into a file
 * @export_desc_len [in]: Export descriptor length
 * @src_buffer [in]: Source buffer
 * @src_buffer_len [in]: Source buffer length
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer information file path
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
save_config_info_to_files(char *export_desc, size_t export_desc_len, const char *src_buffer, size_t src_buffer_len,
                          char *export_desc_file_path, char *buffer_info_file_path)
{
    FILE *fp;
    uint64_t buffer_addr = (uintptr_t)src_buffer;
    uint64_t buffer_len = (uint64_t)src_buffer_len;

    fp = fopen(export_desc_file_path, "wb");
    if (fp == NULL) {
        DOCA_LOG_ERR("Failed to create the DMA copy file");
        return DOCA_ERROR_IO_FAILED;
    }

    if (fwrite(export_desc, 1, export_desc_len, fp) != export_desc_len) {
        DOCA_LOG_ERR("Failed to write all data into the file");
        fclose(fp);
        return DOCA_ERROR_IO_FAILED;
    }

    fclose(fp);

    fp = fopen(buffer_info_file_path, "w");
    if (fp == NULL) {
        DOCA_LOG_ERR("Failed to create the DMA copy file");
        return DOCA_ERROR_IO_FAILED;
    }

    fprintf(fp, "%" PRIu64 "\n", buffer_addr);
    fprintf(fp, "%" PRIu64 "", buffer_len);

    fclose(fp);

    return DOCA_SUCCESS;
}

/*
 * Run DOCA DMA Host copy sample
 *
 * @pcie_addr [in]: Device PCI address
 * @src_buffer [in]: Source buffer to copy
 * @src_buffer_size [in]: Buffer size
 * @export_desc_file_path [in]: Export descriptor file path
 * @buffer_info_file_path [in]: Buffer info file path
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t
dma_copy_host(struct doca_pci_bdf *pcie_addr, char *src_buffer, size_t src_buffer_size,
              char *export_desc_file_path, char *buffer_info_file_name)
{
    struct program_core_objects state = {0};
    doca_error_t result;
    char *export_desc;
    size_t export_desc_len;

    /* Signal the while loop to stop and destroy the memory map */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Open the relevant DOCA device */
    result = open_doca_device_with_pci(pcie_addr, &dma_jobs_is_supported, &state.dev);
    if (result != DOCA_SUCCESS)
        return result;

    /* Init all DOCA core objects */
    result = host_init_core_objects(&state);
    if (result != DOCA_SUCCESS) {
        host_destroy_core_objects(&state);
        return result;
    }

    /* Populate the memory map with the allocated memory */
    result = doca_mmap_populate(state.mmap, src_buffer, src_buffer_size, PAGE_SIZE, NULL, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("populate failed pgsize %d", PAGE_SIZE);
        host_destroy_core_objects(&state);
        return result;
    }

    /* Export DOCA mmap to enable DMA on Host*/
    result = doca_mmap_export(state.mmap, state.dev, (void **)&export_desc, &export_desc_len);
    if (result != DOCA_SUCCESS) {
        host_destroy_core_objects(&state);
        return result;
    }

    DOCA_LOG_INFO("Please copy %s and %s to the DPU and run DMA Copy DPU sample before closing", export_desc_file_path, buffer_info_file_name);

    /* Saves the export desc and buffer info to files, it is the user responsibility to transfer them to the dpu */
    result = save_config_info_to_files(export_desc, export_desc_len, src_buffer, src_buffer_size,
                                       export_desc_file_path, buffer_info_file_name);
    if (result != DOCA_SUCCESS) {
        free(export_desc);
        host_destroy_core_objects(&state);
        return result;
    }

    /* Wait until DMA copy on the DPU is over */
    while (!is_dma_done_on_dpu)
        sleep(1);

    /* Destroy all relevant DOCA core objects */
    host_destroy_core_objects(&state);

    /* Free API pre-allocated exported string */
    free(export_desc);

    return result;
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
    char *src_buffer;
    size_t length;
    doca_error_t result;

    /* Set the default configuration values (Example values) */
    strcpy(dma_conf.pci_address, "b1:00.0");
    //strcpy(dma_conf.cpy_txt, "This is a sample piece of text");
    strcpy(dma_conf.pm_addr, "/dev/dax1.0");
    dma_conf.pm_size = 0 * _GB;
    strcpy(dma_conf.export_desc_path, "/tmp/export_desc.txt");
    strcpy(dma_conf.buf_info_path, "/tmp/buffer_info.txt");

    result = doca_argp_init("dma_copy_host", &dma_conf);
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

#ifndef DOCA_ARCH_HOST
    DOCA_LOG_ERR("Sample can run only on the Host");
	doca_argp_destroy();
	return EXIT_FAILURE;
#endif

#ifdef USE_PMEM
    DOCA_LOG_ERR("Mapping PM device %s size %lu\n", dma_conf.pm_addr, dma_conf.pm_size);
    int is_pmem = 0;
    src_buffer = (char*)pmem_map_file(dma_conf.pm_addr, dma_conf.pm_size, PMEM_FILE_CREATE, 0666, &length, &is_pmem);
    if (!src_buffer) {
        DOCA_LOG_ERR("pmem_map_file failed for %s\n", strerror(errno));
        DOCA_LOG_ERR("Map PM file failed");
        doca_argp_destroy();
        return EXIT_FAILURE;
    } else {
        DOCA_LOG_ERR("Mapping PM device success size %lu\n", length);
        dma_conf.pm_size = length;
    }
#else
    length = 4096;
    src_buffer = (char *)malloc(length);
    DOCA_LOG_ERR("Malloc src_buffer");
    if (src_buffer == NULL) {
        DOCA_LOG_ERR("Source buffer allocation failed");
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    memcpy(src_buffer, "abcdefghijklmn", length);
    /*void* raw_pm = malloc(1*_GB);
    if (raw_pm == NULL) {
        DOCA_LOG_ERR("Source buffer allocation failed");
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
    size_t mapped_len = 1 * _GB;*/
#endif

    result = parse_pci_addr(dma_conf.pci_address, &pcie_dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to parse pci address: %s", doca_get_error_string(result));
        free(src_buffer);
        doca_argp_destroy();
        return EXIT_FAILURE;
    }

    result = dma_copy_host(&pcie_dev, (char*)src_buffer, length, dma_conf.export_desc_path, dma_conf.buf_info_path);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Sample function has failed: %s", doca_get_error_string(result));
        free(src_buffer);
        doca_argp_destroy();
        return EXIT_FAILURE;
    }
#ifdef USE_PMEM
    pmem_unmap(src_buffer, length);
#else
    free(src_buffer);
#endif
    doca_argp_destroy();

    return EXIT_SUCCESS;
}
