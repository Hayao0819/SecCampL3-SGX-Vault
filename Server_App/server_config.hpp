#include "headers.hpp"

uint8_t* load_config_file(const char* config_file_path, long& config_size);
void ocall_write_config_file(const uint8_t* data, size_t data_len);
