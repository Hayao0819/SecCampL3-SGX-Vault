#include "headers.hpp"

void ocall_write_config_file(const uint8_t* data, size_t data_len) {
    if (!config_file_path || !data || data_len == 0) {
        ocall_print("Invalid parameters for writing configuration file.", 2);
        return;
    }

    FILE* config_file = fopen(config_file_path, "wb");
    if (!config_file) {
        ocall_print("Failed to open configuration file for writing.", 2);
        return;
    }

    size_t written_size = fwrite(data, 1, data_len, config_file);
    fclose(config_file);

    if (written_size != data_len) {
        ocall_print("Failed to write the complete configuration data.", 2);
    } else {
        ocall_print("Configuration file written successfully.", 1);
    }
}
