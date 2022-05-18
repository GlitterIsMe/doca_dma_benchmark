//
// Created by YiwenZhang on 2022/5/17.
//

#ifndef DOCA_DMA_SENDER_H
#define DOCA_DMA_SENDER_H

class Sender {
public:
    explicit Sender(struct doca_pci_bdf *pcie_addr,
            char *src_buffer, size_t length,
            char *receiver_ip, uint16_t receiver_port,
            int core_num) {
        total_core_num = core_num;
        init_sender(pcie_addr, src_buffer, length, receiver_ip, receiver_port);
    }

    ~Sender() {
        destroy_core_objects_sender(&state);
        /* Free pre-allocated exported string */
        free(export_str);
    }

    bool WaitingForExit();

private:
    doca_error_t init_sender(struct doca_pci_bdf *pcie_addr, char *src_buffer, size_t length, char *receiver_ip, uint16_t receiver_port);
    bool send_json_to_receiver(char *ip, uint16_t port, char *export_str, size_t export_str_len);

    app_state state = {0};
    int sender_fd;
    char *export_str;

    int total_core_num;
};

#endif //DOCA_DMA_SENDER_H
