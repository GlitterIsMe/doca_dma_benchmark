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

#include <string.h>
#include <bsd/string.h>
#include <unistd.h>

#include <doca_buf_inventory.h>
#include <doca_dev.h>
#include <doca_dma.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_argp.h>
#include <string>

#include "dma_common.h"

DOCA_LOG_REGISTER(DMA_COMMON);

/*
 * ARGP Callback - Handle PCI device address parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
pci_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *addr = (char *)param;
    int addr_len = strnlen(addr, MAX_ARG_SIZE);

    if (addr_len == MAX_ARG_SIZE) {
        DOCA_LOG_ERR("Entered pci address exceeded buffer size of: %d", MAX_ARG_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

    strlcpy(conf->pci_address, addr, MAX_ARG_SIZE);

    return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle text to copy parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
/*static doca_error_t
text_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);

    if (txt_len == MAX_TXT_SIZE) {
        DOCA_LOG_ERR("Entered text exceeded buffer size of: %d", MAX_TXT_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

    strlcpy(conf->cpy_txt, txt, MAX_TXT_SIZE);

    return DOCA_SUCCESS;
}*/

static doca_error_t
path_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);

    if (txt_len == MAX_TXT_SIZE) {
        DOCA_LOG_ERR("Entered text exceeded buffer size of: %d", MAX_TXT_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

    strlcpy(conf->pm_addr, txt, MAX_TXT_SIZE);

    return DOCA_SUCCESS;
}

static doca_error_t
size_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);
    size_t tmp = std::stoi(std::string(txt, txt_len));
    conf->pm_size = tmp * 1024 * 1024 * 1024UL;
    return DOCA_SUCCESS;
}

static doca_error_t
threads_num_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);
    size_t tmp = std::stoi(std::string(txt, txt_len));
    conf->thread_num = tmp;
    return DOCA_SUCCESS;
}

static doca_error_t
block_size_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);
    size_t tmp = std::stoi(std::string(txt, txt_len));
    conf->block_size = tmp;
    return DOCA_SUCCESS;
}

static doca_error_t
depth_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *txt = (char *)param;
    int txt_len = strnlen(txt, MAX_TXT_SIZE);
    size_t tmp = std::stoi(std::string(txt, txt_len));
    conf->depth = tmp;
    return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle exported descriptor file path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
descriptor_path_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *path = (char *)param;
    int path_len = strnlen(path, MAX_ARG_SIZE);

    if (path_len == MAX_ARG_SIZE) {
        DOCA_LOG_ERR("Entered path exceeded buffer size: %d", MAX_ARG_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

#ifdef DOCA_ARCH_DPU
    if (access(path, F_OK | R_OK) != 0) {
		DOCA_LOG_ERR("Failed to find file path pointed by export descriptor: %s", path);
		return DOCA_ERROR_INVALID_VALUE;
	}
#endif

    strlcpy(conf->export_desc_path, path, MAX_ARG_SIZE);

    return DOCA_SUCCESS;
}

/*
 * ARGP Callback - Handle buffer information file path parameter
 *
 * @param [in]: Input parameter
 * @config [in/out]: Program configuration context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t
buf_info_path_callback(void *param, void *config)
{
    struct dma_config *conf = (struct dma_config *)config;
    const char *path = (char *)param;
    int path_len = strnlen(path, MAX_ARG_SIZE);

    if (path_len == MAX_ARG_SIZE) {
        DOCA_LOG_ERR("Entered path exceeded buffer size: %d", MAX_ARG_SIZE - 1);
        return DOCA_ERROR_INVALID_VALUE;
    }

#ifdef DOCA_ARCH_DPU
    if (access(path, F_OK | R_OK) != 0) {
		DOCA_LOG_ERR("Failed to find file path pointed by buffer information: %s", path);
		return DOCA_ERROR_INVALID_VALUE;
	}
#endif

    strlcpy(conf->buf_info_path, path, MAX_ARG_SIZE);

    return DOCA_SUCCESS;
}

doca_error_t
register_dma_params()
{
    doca_error_t result;
    struct doca_argp_param *pci_address_param, /**cpy_txt_param,*/ *export_desc_path_param, *buf_info_path_param;
    struct doca_argp_param *pm_addr_param, *pm_size_param;
    struct doca_argp_param *thread_num, *block_size, *depth;

    /* Create and register PCI address param */
    result = doca_argp_param_create(&pci_address_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(pci_address_param, "p");
    doca_argp_param_set_long_name(pci_address_param, "pci");
    doca_argp_param_set_description(pci_address_param, "DOCA DMA device PCI address");
    doca_argp_param_set_callback(pci_address_param, pci_callback);
    doca_argp_param_set_type(pci_address_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(pci_address_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    /* Create and register text to copy param */
    /*result = doca_argp_param_create(&cpy_txt_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(cpy_txt_param, "t");
    doca_argp_param_set_long_name(cpy_txt_param, "text");
    doca_argp_param_set_description(cpy_txt_param,
                                    "Text to DMA copy from the Host to the DPU (relevant only on the Host side)");
    doca_argp_param_set_callback(cpy_txt_param, text_callback);
    doca_argp_param_set_type(cpy_txt_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(cpy_txt_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }*/
    result = doca_argp_param_create(&pm_addr_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(pm_addr_param, "P");
    doca_argp_param_set_long_name(pm_addr_param, "path");
    doca_argp_param_set_description(pm_addr_param,
                                    "Path to the PM device (relevant only on the Host side)");
    doca_argp_param_set_callback(pm_addr_param, path_callback);
    doca_argp_param_set_type(pm_addr_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(pm_addr_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    result = doca_argp_param_create(&pm_size_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(pm_size_param, "s");
    doca_argp_param_set_long_name(pm_size_param, "size");
    doca_argp_param_set_description(pm_size_param,
                                    "Size of the PM device (relevant only on the Host side)");
    doca_argp_param_set_callback(pm_size_param, size_callback);
    doca_argp_param_set_type(pm_size_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(pm_size_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    result = doca_argp_param_create(&thread_num);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(thread_num, "t");
    doca_argp_param_set_long_name(thread_num, "threads");
    doca_argp_param_set_description(thread_num,
                                    "number of benchmark threads (relevant only on the DPU side)");
    doca_argp_param_set_callback(thread_num, threads_num_callback);
    doca_argp_param_set_type(thread_num, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(thread_num);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    result = doca_argp_param_create(&block_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(block_size, "B");
    doca_argp_param_set_long_name(block_size, "block_size");
    doca_argp_param_set_description(block_size,
                                    "block size of I/O (relevant only on the DPU side)");
    doca_argp_param_set_callback(block_size, block_size_callback);
    doca_argp_param_set_type(block_size, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(block_size);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    result = doca_argp_param_create(&depth);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(depth, "D");
    doca_argp_param_set_long_name(depth, "depth");
    doca_argp_param_set_description(depth,
                                    "number of outstanding requests (relevant only on the DPU side)");
    doca_argp_param_set_callback(depth, depth_callback);
    doca_argp_param_set_type(depth, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(depth);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }
    

    /* Create and register exported descriptor file path param */
    result = doca_argp_param_create(&export_desc_path_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(export_desc_path_param, "d");
    doca_argp_param_set_long_name(export_desc_path_param, "descriptor-path");
    doca_argp_param_set_description(export_desc_path_param,
                                    "Exported descriptor file path to save (Host) or to read from (DPU)");
    doca_argp_param_set_callback(export_desc_path_param, descriptor_path_callback);
    doca_argp_param_set_type(export_desc_path_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(export_desc_path_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    /* Create and register buffer information file param */
    result = doca_argp_param_create(&buf_info_path_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_get_error_string(result));
        return result;
    }
    doca_argp_param_set_short_name(buf_info_path_param, "b");
    doca_argp_param_set_long_name(buf_info_path_param, "buffer-path");
    doca_argp_param_set_description(buf_info_path_param,
                                    "Buffer information file path to save (Host) or to read from (DPU)");
    doca_argp_param_set_callback(buf_info_path_param, buf_info_path_callback);
    doca_argp_param_set_type(buf_info_path_param, DOCA_ARGP_TYPE_STRING);
    result = doca_argp_register_param(buf_info_path_param);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to register program param: %s", doca_get_error_string(result));
        return result;
    }

    return DOCA_SUCCESS;
}

doca_error_t
host_init_core_objects(struct program_core_objects *state)
{
    doca_error_t res;

    res = doca_mmap_create(NULL, &state->mmap);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to create mmap: %s", doca_get_error_string(res));
        return res;
    }

    res = doca_mmap_start(state->mmap);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to start memory map: %s", doca_get_error_string(res));
        return res;
    }

    res = doca_mmap_dev_add(state->mmap, state->dev);
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Unable to add device to mmap: %s", doca_get_error_string(res));

    return res;
}

void
dma_cleanup(struct program_core_objects *state, struct doca_dma *dma_ctx)
{
    doca_error_t res;

    destroy_core_objects(state);

    res = doca_dma_destroy(dma_ctx);
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy dma: %s", doca_get_error_string(res));

    state->ctx = NULL;
}

void
host_destroy_core_objects(struct program_core_objects *state)
{
    doca_error_t res;

    res = doca_mmap_destroy(state->mmap);
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to destroy mmap: %s", doca_get_error_string(res));
    state->mmap = NULL;

    res = doca_dev_close(state->dev);
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to close device: %s", doca_get_error_string(res));
    state->dev = NULL;
}

doca_error_t
dma_jobs_is_supported(struct doca_devinfo *devinfo)
{
    return doca_dma_job_get_supported(devinfo, DOCA_DMA_JOB_MEMCPY);
}
