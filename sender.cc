//
// Created by YiwenZhang on 2022/5/17.
//

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>


#include "dma_common.h"
#include "sender.h"

DOCA_LOG_REGISTER(DMA_REMOTE_COPY_SENDER);

bool Sender::WaitingForExit() {
    char ack_buffer[1024] = {0};
    char exp_ack[] = "DMA operation on receiver node was completed";
    /* Waiting for DMA completion signal from receiver */
    DOCA_LOG_INFO("Waiting for receiver node to acknowledge DMA operation was ended");
    if (recv(sender_fd, ack_buffer, sizeof(ack_buffer), 0) < 0) {
        DOCA_LOG_ERR("Failed to receive ack message");
        close(sender_fd);
        return false;
    }

    if (strcmp(exp_ack, ack_buffer)) {
        DOCA_LOG_ERR("Ack message is not correct");
        close(sender_fd);
        return false;
    }

    DOCA_LOG_INFO("Ack message was received, closing memory mapping");

    close(sender_fd);
    return true;
}

bool Sender::send_json_to_receiver(char *ip, uint16_t port, char *export_str, size_t export_str_len)
{
    struct sockaddr_in addr;
    struct timeval timeout = {
            .tv_sec = 5,
    };
    //int sender_fd;
    int ret;
    char ack_buffer[1024] = {0};

    sender_fd = socket(AF_INET, SOCK_STREAM, 0);

    setsockopt(sender_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (connect(sender_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        DOCA_LOG_ERR("Couldn't establish a connection to receiver node");
        close(sender_fd);
        return false;
    }
    ret = write(sender_fd, export_str, export_str_len);
    if (ret != (int)export_str_len) {
        DOCA_LOG_ERR("Failed to send data to receiver node");
        close(sender_fd);
        return false;
    }

    /* Waiting for DMA completion signal from receiver *//*
    DOCA_LOG_INFO("Waiting for receiver node to acknowledge DMA operation was ended");
    if (recv(sender_fd, ack_buffer, sizeof(ack_buffer), 0) < 0) {
        DOCA_LOG_ERR("Failed to receive ack message");
        close(sender_fd);
        return false;
    }

    if (strcmp(exp_ack, ack_buffer)) {
        DOCA_LOG_ERR("Ack message is not correct");
        close(sender_fd);
        return false;
    }

    DOCA_LOG_INFO("Ack message was received, closing memory mapping");

    close(sender_fd);*/
    return true;
}

doca_error_t Sender::init_sender (struct doca_pci_bdf *pcie_addr, char *src_buffer, size_t length, char *receiver_ip, uint16_t receiver_port)
{
    //struct app_state state = {0};
    doca_error_t res;
    //char *export_str;
    size_t export_str_len;
    size_t pg_sz = 1024 * 4;

    res = open_local_device(pcie_addr, &state);
    if (res != DOCA_SUCCESS)
        return res;

    res = init_core_objects_sender(&state);
    if (res != DOCA_SUCCESS) {
        destroy_core_objects_sender(&state);
        return res;
    }

    res = populate_mmap(state.mmap, src_buffer, length, pg_sz);
    if (res != DOCA_SUCCESS) {
        destroy_core_objects_sender(&state);
        return res;
    }

    /* Export DOCA mmap to enable DMA */
    res = doca_mmap_export(state.mmap, state.dev, (uint8_t **)&export_str, &export_str_len);
    if (res != DOCA_SUCCESS) {
        destroy_core_objects_sender(&state);
        return res;
    }

    DOCA_LOG_INFO("Exported memory buffer content: %s", src_buffer);

    /* Send exported string and wait for ack that DMA was done on receiver node */
    if (!send_json_to_receiver(receiver_ip, receiver_port, export_str, export_str_len)) {
        destroy_core_objects_sender(&state);
        free(export_str);
        return DOCA_ERROR_NOT_CONNECTED;
    }

    return res;
}