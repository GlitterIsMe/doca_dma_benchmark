//
// Created by YiwenZhang on 2022/5/17.
//
#include <json-c/json.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>

#include "dma_common.h"
#include "receiver.h"
#include "hash.h"
#define f_seed 0xc70697UL

DOCA_LOG_REGISTER(DMA_REMOTE_COPY_RECEIVER);

char Receiver::export_json[1024] = {0};
char* Receiver::remote_addr = 0;
size_t Receiver::remote_addr_len = 0;
int Receiver::exit_count = 0;

Receiver::~Receiver() {
    if (doca_buf_refcount_rm(dst_doca_buf, NULL))
        DOCA_LOG_ERR("Failed to decrease DOCA buffer reference count");
    /* Destroy remote memory map */
    if (doca_mmap_destroy(remote_mmap))
        DOCA_LOG_ERR("Failed to destroy remote memory map");

    /* Inform sender node that DMA operation is done */
    send_ack_to_sender();

    /* Clean and destroy all relevant objects */
    cleanup_core_objects(&state);

    destroy_core_objects(&state);

    delete[] dst_buffer;

    delete[] dma_jobs;
}

bool Receiver::receive_json_from_sender(const char *port, char *export_buffer, size_t export_buffer_len) {
    struct json_object *from_export_json;
    struct json_object *addr;
    struct json_object *len;
    struct addrinfo *res, *it;
    struct addrinfo hints = {
            .ai_flags = AI_PASSIVE,
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM
    };
    int bytes_ret;
    int queue_size = 1;
    int optval = 1;

    if (getaddrinfo(NULL, port, &hints, &res)) {
        DOCA_LOG_ERR("Failed to retrieve network information");
        return false;
    }

    for (it = res; it; it = it->ai_next) {
        receiver_fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (receiver_fd >= 0) {
            setsockopt(receiver_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
            if (!bind(receiver_fd, it->ai_addr, it->ai_addrlen))
                break;
            close(receiver_fd);
            receiver_fd = -1;
        }
    }

    freeaddrinfo(res);

    if (receiver_fd < 0) {
        DOCA_LOG_ERR("Port listening failed");
        return false;
    }

    listen(receiver_fd, queue_size);

    DOCA_LOG_INFO("Waiting for sender node to send exported data");

    sender_fd = accept(receiver_fd, NULL, 0);

    close(receiver_fd);

    if (sender_fd < 0) {
        DOCA_LOG_ERR("Connection acceptance failed");
        return false;
    }

    bytes_ret = recv(sender_fd, export_buffer, export_buffer_len, 0);

    if (bytes_ret == -1) {
        DOCA_LOG_ERR("Couldn't receive data from sender node");
        close(sender_fd);
        return false;
    } else if (bytes_ret == export_buffer_len) {
        if (export_buffer[export_buffer_len - 1] != '\0') {
            DOCA_LOG_ERR("Exported data buffer size is not sufficient");
            return false;
        }
    }

    DOCA_LOG_INFO("Exported data was received");

    /* Parse the export json */
    from_export_json = json_tokener_parse(export_buffer);
    json_object_object_get_ex(from_export_json, "addr", &addr);
    json_object_object_get_ex(from_export_json, "len", &len);
    remote_addr = (char *) json_object_get_int64(addr);
    remote_addr_len = (size_t) json_object_get_int64(len);
    json_object_put(from_export_json);

    return true;
}

void Receiver::send_ack_to_sender() const {
    exit_count--;
    if (exit_count == 0) {
        int ret;
        char ack_buffer[] = "DMA operation on receiver node was completed";
        int length = strlen(ack_buffer) + 1;

        printf("[%d]: send_ack_to_sender\n", core_id);
        ret = write(sender_fd, ack_buffer, length);
        if (ret != length)
            DOCA_LOG_ERR("Failed to send ack message to sender node");

        close(sender_fd);
    }
}

doca_error_t Receiver::init_receiver(struct doca_pci_bdf *pcie_addr, const char *port) {
    doca_error_t res;
    uint32_t max_chunks = 1;
    uint32_t pg_sz = 1024 * 4;
    //char export_json[1024] = {0};

    res = open_local_device(pcie_addr, &state);
    if (res != DOCA_SUCCESS)
        return res;

    res = create_core_objects(&state);
    if (res != DOCA_SUCCESS) {
        destroy_core_objects(&state);
        return res;
    }

    res = init_core_objects(&state, max_chunks);
    if (res != DOCA_SUCCESS) {
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    res = populate_mmap(state.mmap, dst_buffer, dst_buffer_len, pg_sz);
    if (res != DOCA_SUCCESS) {
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    if (core_id == 0) {
        /* Receive exported data from sender */
        if (!receive_json_from_sender(port, export_json, sizeof(export_json) / sizeof(char))) {
            cleanup_core_objects(&state);
            destroy_core_objects(&state);
            return DOCA_ERROR_NOT_CONNECTED;
        }
        exit_count = total_core_num;
    }
    /* Create a local DOCA mmap from exported data */
    res = doca_mmap_create_from_export("my_mmap", (uint8_t *) export_json, strlen(export_json) + 1, state.dev,
                                       &remote_mmap);
    if (res != DOCA_SUCCESS) {
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    /* Construct DOCA buffer for each address range */
    res = doca_buf_inventory_buf_by_addr(state.buf_inv, state.mmap, dst_buffer, dst_buffer_len, &dst_doca_buf);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s", doca_get_error_string(res));
        //doca_buf_refcount_rm(src_doca_buf, NULL);
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    return res;
}

char *Receiver::get_random_remote_block() {
    int rand_blk = rand();
    return local_remote_addr + (rand_blk % total_blocks) * block_size;
}

char *Receiver::get_remote_block(int blk_num, bool random) {
    unsigned int blk_no = blk_num;
    if (random) {
        blk_no = hash::hash_funcs[0](&blk_no, sizeof(int), f_seed);
    }
    return local_remote_addr + (blk_no % total_blocks) * block_size;
}

bool Receiver::ExecuteDMAJobsRead() {
    doca_error_t res;
    struct doca_buf *src_doca_buf;
    /* Construct DOCA buffer for each address range */
    char* target_remote_buffer = get_random_remote_block();
    res = doca_buf_inventory_buf_by_addr(state.buf_inv,
                                         remote_mmap,
                                         target_remote_buffer,
                                         block_size,
                                         &src_doca_buf);
    /*res = doca_buf_inventory_buf_by_addr(state.buf_inv,
                                         remote_mmap,
                                         remote_addr,
                                         remote_addr_len,
                                         &src_doca_buf);*/
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    struct doca_job doca_job = {0};
    /* Construct DMA job */
    doca_job.type = DOCA_DMA_JOB_MEMCPY;
    doca_job.flags = DOCA_JOB_FLAGS_NONE;
    doca_job.ctx = state.ctx;

    dma_job.base = doca_job;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    dma_job.num_bytes_to_copy = dst_buffer_len;
    /* Enqueue DMA job */
    res = doca_workq_submit(state.workq, &dma_job.base);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
        doca_buf_refcount_rm(dst_doca_buf, NULL);
        doca_buf_refcount_rm(src_doca_buf, NULL);
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return false;
    }
    /* Wait for job completion */
    while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN) {
        /* Do nothing */
    }
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));

    /* On DOCA_SUCCESS, Verify DMA job result */
    if (event.result.u64 == DOCA_SUCCESS) {
        //DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        //DOCA_LOG_INFO("Memory content: %s", dst_buffer);
    } else {
        DOCA_LOG_ERR("DMA job returned unsuccessfully");
        res = DOCA_ERROR_UNKNOWN;
    }
    doca_buf_refcount_rm(src_doca_buf, NULL);
    return true;
}

bool Receiver::ExecuteDMAJobsRead(int blk_num, bool random) {
    doca_error_t res;
    struct doca_buf *src_doca_buf;
    /* Construct DOCA buffer for each address range */
    char* target_remote_buffer = get_remote_block(blk_num, random);
    res = doca_buf_inventory_buf_by_addr(state.buf_inv,
                                         remote_mmap,
                                         target_remote_buffer,
                                         block_size,
                                         &src_doca_buf);
    /*res = doca_buf_inventory_buf_by_addr(state.buf_inv,
                                         remote_mmap,
                                         remote_addr,
                                         remote_addr_len,
                                         &src_doca_buf);*/
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    struct doca_job doca_job = {0};
    /* Construct DMA job */
    doca_job.type = DOCA_DMA_JOB_MEMCPY;
    doca_job.flags = DOCA_JOB_FLAGS_NONE;
    doca_job.ctx = state.ctx;

    dma_job.base = doca_job;
    dma_job.dst_buff = dst_doca_buf;
    dma_job.src_buff = src_doca_buf;
    dma_job.num_bytes_to_copy = dst_buffer_len;
    /* Enqueue DMA job */
    res = doca_workq_submit(state.workq, &dma_job.base);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
        doca_buf_refcount_rm(dst_doca_buf, NULL);
        doca_buf_refcount_rm(src_doca_buf, NULL);
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return false;
    }
    /* Wait for job completion */
    while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN) {
        /* Do nothing */
    }
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));

    /* On DOCA_SUCCESS, Verify DMA job result */
    if (event.result.u64 == DOCA_SUCCESS) {
        //DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        //DOCA_LOG_INFO("Memory content: %s", dst_buffer);
    } else {
        DOCA_LOG_ERR("DMA job returned unsuccessfully");
        res = DOCA_ERROR_UNKNOWN;
    }
    doca_buf_refcount_rm(src_doca_buf, NULL);
    return true;
}

bool Receiver::ExecuteDMAJobsReadMulti(int blk_num, bool random, int nums) {
    doca_error_t res;
    struct doca_buf **src_doca_bufs = new struct doca_buf*[nums];
    struct doca_job* doca_job = new struct doca_job[nums];
    for (int i = 0; i < nums; ++i) {
        /* Construct DOCA buffer for each address range */
        char* target_remote_buffer = get_remote_block(blk_num + i, random);
        res = doca_buf_inventory_buf_by_addr(state.buf_inv,
                                             remote_mmap,
                                             target_remote_buffer,
                                             block_size,
                                             &src_doca_bufs[i]);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
            doca_mmap_destroy(remote_mmap);
            cleanup_core_objects(&state);
            destroy_core_objects(&state);
            return res;
        }

        /* Construct DMA job */
        doca_job[i].type = DOCA_DMA_JOB_MEMCPY;
        doca_job[i].flags = DOCA_JOB_FLAGS_NONE;
        doca_job[i].ctx = state.ctx;

        dma_jobs[i].base = doca_job[i];
        dma_jobs[i].dst_buff = dst_doca_buf;
        dma_jobs[i].src_buff = src_doca_bufs[i];
        dma_jobs[i].num_bytes_to_copy = dst_buffer_len;
    }

    /* Enqueue DMA job */
    for (int i = 0; i < nums; ++i) {
        res = doca_workq_submit(state.workq, &dma_jobs[i].base);
        if (res != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
            doca_buf_refcount_rm(dst_doca_buf, NULL);
            doca_buf_refcount_rm(src_doca_bufs[i], NULL);
            doca_mmap_destroy(remote_mmap);
            cleanup_core_objects(&state);
            destroy_core_objects(&state);
            return false;
        }
    }

    /* Wait for job completion */
    int total_completed = 0;
    for (int i = 0; total_completed < nums; ++i) {
        while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
               DOCA_ERROR_AGAIN) {
            /* Do nothing */
        }
        if (res != DOCA_SUCCESS)
            DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));

        /* On DOCA_SUCCESS, Verify DMA job result */
        if (event.result.u64 == DOCA_SUCCESS) {
            //DOCA_LOG_INFO("Remote DMA copy was done Successfully");
            //DOCA_LOG_INFO("Memory content: %s", dst_buffer);
        } else {
            DOCA_LOG_ERR("DMA job returned unsuccessfully");
            res = DOCA_ERROR_UNKNOWN;
        }
        doca_buf_refcount_rm(src_doca_bufs[i], NULL);
        total_completed++;
    }
    delete[] src_doca_bufs;
    delete[] doca_job;
    return true;
}

bool Receiver::ExecuteDMAJobsWrite() {
    doca_error_t res;

    struct doca_buf *src_doca_buf;
    /* Construct DOCA buffer for each address range */
    char* target_remote_buffer = get_random_remote_block();
    res = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, target_remote_buffer, block_size, &src_doca_buf);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    //clear local buffer
    memset(dst_buffer, '0', dst_buffer_len);

    struct doca_job doca_job = {0};
    /* Construct DMA job */
    doca_job.type = DOCA_DMA_JOB_MEMCPY;
    doca_job.flags = DOCA_JOB_FLAGS_NONE;
    doca_job.ctx = state.ctx;

    dma_job.base = doca_job;
    dma_job.dst_buff = src_doca_buf;
    dma_job.src_buff = dst_doca_buf;
    dma_job.num_bytes_to_copy = dst_buffer_len;
    /* Enqueue DMA job */
    res = doca_workq_submit(state.workq, &dma_job.base);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
        doca_buf_refcount_rm(dst_doca_buf, NULL);
        doca_buf_refcount_rm(src_doca_buf, NULL);
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return false;
    }
    /* Wait for job completion */
    while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN) {
        /* Do nothing */
    }
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));

    /* On DOCA_SUCCESS, Verify DMA job result */
    if (event.result.u64 == DOCA_SUCCESS) {
        //DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        //DOCA_LOG_INFO("Memory content: %s", dst_buffer);
    } else {
        DOCA_LOG_ERR("DMA job returned unsuccessfully");
        res = DOCA_ERROR_UNKNOWN;
    }
    doca_buf_refcount_rm(src_doca_buf, NULL);
    return true;
}

bool Receiver::ExecuteDMAJobsWrite(int blk_num, bool random) {
    doca_error_t res;

    struct doca_buf *src_doca_buf;
    /* Construct DOCA buffer for each address range */
    char* target_remote_buffer = get_remote_block(blk_num, random);
    res = doca_buf_inventory_buf_by_addr(state.buf_inv, remote_mmap, target_remote_buffer, block_size, &src_doca_buf);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Unable to acquire DOCA buffer representing remote buffer: %s", doca_get_error_string(res));
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return res;
    }

    //clear local buffer
    memset(dst_buffer, '0', dst_buffer_len);

    struct doca_job doca_job = {0};
    /* Construct DMA job */
    doca_job.type = DOCA_DMA_JOB_MEMCPY;
    doca_job.flags = DOCA_JOB_FLAGS_NONE;
    doca_job.ctx = state.ctx;

    dma_job.base = doca_job;
    dma_job.dst_buff = src_doca_buf;
    dma_job.src_buff = dst_doca_buf;
    dma_job.num_bytes_to_copy = dst_buffer_len;
    /* Enqueue DMA job */
    res = doca_workq_submit(state.workq, &dma_job.base);
    if (res != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));
        doca_buf_refcount_rm(dst_doca_buf, NULL);
        doca_buf_refcount_rm(src_doca_buf, NULL);
        doca_mmap_destroy(remote_mmap);
        cleanup_core_objects(&state);
        destroy_core_objects(&state);
        return false;
    }
    /* Wait for job completion */
    while ((res = doca_workq_progress_retrieve(state.workq, &event, DOCA_WORKQ_RETRIEVE_FLAGS_NONE)) ==
           DOCA_ERROR_AGAIN) {
        /* Do nothing */
    }
    if (res != DOCA_SUCCESS)
        DOCA_LOG_ERR("Failed to submit DMA job: %s", doca_get_error_string(res));

    /* On DOCA_SUCCESS, Verify DMA job result */
    if (event.result.u64 == DOCA_SUCCESS) {
        //DOCA_LOG_INFO("Remote DMA copy was done Successfully");
        //DOCA_LOG_INFO("Memory content: %s", dst_buffer);
    } else {
        DOCA_LOG_ERR("DMA job returned unsuccessfully");
        res = DOCA_ERROR_UNKNOWN;
    }
    doca_buf_refcount_rm(src_doca_buf, NULL);
    return true;
}