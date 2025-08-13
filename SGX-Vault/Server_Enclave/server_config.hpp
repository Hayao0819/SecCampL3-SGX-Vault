
#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>

typedef struct {
    std::string master_password;
    std::map<std::string, std::string> user_data;
} SGXVaultConfig;

extern SGXVaultConfig* config;

// SGXVaultConfig -> bytes
void config_to_bytes(SGXVaultConfig* config, uint8_t* bytes, size_t bytes_len);

// bytes -> SGXVaultConfig
void parse_unsealed_data(uint8_t* unsealed_data, size_t unsealed_data_size, SGXVaultConfig* config);

int write_current_config();
