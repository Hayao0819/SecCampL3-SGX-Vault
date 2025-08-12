
#include "server_config.hpp"

#include <cstdint>
#include <cstring>
#include <map>
#include <stdexcept>
#include <string>

#include "server_enclave_headers.hpp"
#include "server_enclave_utils.hpp"

SGXVaultConfig* config = nullptr;

// SGXVaultConfig -> bytes
void config_to_bytes(SGXVaultConfig* config, uint8_t* bytes, size_t* bytes_len) {
    size_t required_size = 0;

    // サイズ計算用ラムダ
    auto add_size = [&](size_t n) {
        required_size += n;
    };

    // 実際に書き込む用ラムダ
    size_t offset = 0;
    auto write_uint32 = [&](uint32_t val) {
        std::memcpy(bytes + offset, &val, sizeof(uint32_t));
        offset += sizeof(uint32_t);
    };
    auto write_bytes = [&](const uint8_t* data, size_t len) {
        std::memcpy(bytes + offset, data, len);
        offset += len;
    };

    // ---- 必要サイズを計算 ----
    add_size(sizeof(uint32_t));  // master_password length
    add_size(config->master_password.size());

    add_size(sizeof(uint32_t));  // map size
    for (auto& kv : config->user_data) {
        add_size(sizeof(uint32_t));  // key len
        add_size(kv.first.size());
        add_size(sizeof(uint32_t));  // val len
        add_size(kv.second.size());
    }

    if (bytes == nullptr) {
        *bytes_len = required_size;
        return;
    }

    if (*bytes_len < required_size) {
        throw std::runtime_error("Buffer too small");
    }

    // ---- 実際の書き込み ----
    write_uint32(static_cast<uint32_t>(config->master_password.size()));
    write_bytes(reinterpret_cast<const uint8_t*>(config->master_password.data()),
                config->master_password.size());

    write_uint32(static_cast<uint32_t>(config->user_data.size()));
    for (auto& kv : config->user_data) {
        write_uint32(static_cast<uint32_t>(kv.first.size()));
        write_bytes(reinterpret_cast<const uint8_t*>(kv.first.data()), kv.first.size());

        write_uint32(static_cast<uint32_t>(kv.second.size()));
        write_bytes(reinterpret_cast<const uint8_t*>(kv.second.data()), kv.second.size());
    }

    *bytes_len = required_size;
}

// bytes -> SGXVaultConfig
void parse_unsealed_data(uint8_t* unsealed_data, size_t unsealed_data_size, SGXVaultConfig* config) {
    size_t offset = 0;

    auto read_uint32 = [&]() -> uint32_t {
        if (offset + sizeof(uint32_t) > unsealed_data_size) throw std::runtime_error("Buffer underflow");
        uint32_t val;
        std::memcpy(&val, unsealed_data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        return val;
    };

    auto read_bytes = [&](size_t len) -> std::string {
        if (offset + len > unsealed_data_size) throw std::runtime_error("Buffer underflow");
        std::string s(reinterpret_cast<char*>(unsealed_data + offset), len);
        offset += len;
        return s;
    };

    // master_password
    uint32_t mp_len = read_uint32();
    config->master_password = read_bytes(mp_len);

    // user_data
    uint32_t map_size = read_uint32();
    config->user_data.clear();
    for (uint32_t i = 0; i < map_size; i++) {
        uint32_t key_len = read_uint32();
        std::string key = read_bytes(key_len);

        uint32_t val_len = read_uint32();
        std::string val = read_bytes(val_len);

        config->user_data[key] = val;
    }
}

void sealing_config(uint8_t* sealed_data, size_t sealed_data_size) {
    if (config == nullptr) {
        ocall_print("Configuration is not initialized.", 2);
        return;
    }

    uint8_t* bytes;
    size_t bytes_len = 0;
    config_to_bytes(config, bytes, &bytes_len);

    if (bytes_len > sealed_data_size) {
        ocall_print("Sealed data buffer is too small.", 2);
        return;
    }

    sealing_bytes(bytes, bytes_len, sealed_data, sealed_data_size, MRSIGNER);

    ocall_print("Configuration updated successfully.", 1);
}

void write_current_config() {
    uint8_t* sealed_config;
    size_t sealed_config_size;

    try {
        sealing_config(sealed_config, sealed_config_size);
    } catch (const std::runtime_error& e) {
        ocall_print(e.what(), 2);
        return;
    }
    if (sealed_config == nullptr) {
        ocall_print("Failed to seal the configuration data.", 2);
        return;
    }

    ocall_write_config_file(sealed_config, sealed_config_size);
}
