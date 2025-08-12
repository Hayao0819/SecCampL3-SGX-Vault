#include "headers.hpp"

uint8_t* load_config_file(const char* config_file_path, long& config_size) {
    if (!config_file_path) {
        std::string message = "Configuration file is not specified.";
        print_debug_message(message, ERROR);
        return nullptr;
    }
    FILE* config_file = fopen(config_file_path, "r");
    if (!config_file) {
        // ファイルが存在しない場合は空ファイルを作成
        config_file = fopen(config_file_path, "w+");
        if (!config_file) {
            std::string message = "Failed to create empty configuration file: ";
            message += config_file_path;
            print_debug_message(message, ERROR);
            return nullptr;
        }
    }
    fseek(config_file, 0, SEEK_END);
    config_size = ftell(config_file);
    fseek(config_file, 0, SEEK_SET);

    uint8_t* config_data = nullptr;
    if (config_size > 0) {
        config_data = new uint8_t[config_size];
        size_t read_size = fread(config_data, 1, config_size, config_file);
        if (read_size != config_size) {
            std::string message = "Failed to read configuration file completely.";
            print_debug_message(message, ERROR);
            delete[] config_data;
            fclose(config_file);
            return nullptr;
        }
    } else {
        // 空ファイルの場合は空バッファを返す
        config_data = new uint8_t[0];
        config_size = 0;
    }
    fclose(config_file);
    return config_data;
}
