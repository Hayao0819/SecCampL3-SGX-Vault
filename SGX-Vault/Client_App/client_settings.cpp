#include "client_settings.hpp"

#include "client_headers.hpp"

settings_t g_settings;

/* iniファイルから読み込み、失敗時にはプログラムを即時終了する */
std::string load_from_ini(std::string section, std::string key) {
    mINI::INIFile file("settings_client.ini");
    mINI::INIStructure ini;

    if (!file.read(ini)) {
        std::string message = "file read error";
        print_debug_message(message, ERROR);
        exit(1);
    }
    std::string ret = ini.get(section).get(key);

    if (ret.length() == 0) {
        std::string message = "Failed to load setting " + key + " from settings_client.ini.";
        print_debug_message(message, ERROR);
        exit(1);
    }

    return ret;
}

/* 設定情報の読み込み */
void load_settings() {
    try {
        g_settings.maa_url = load_from_ini("client", "MAA_URL");
        g_settings.maa_api_version = load_from_ini("client", "MAA_API_VERSION");
        g_settings.client_id = std::stoi(load_from_ini("client", "CLIENT_ID"));
        g_settings.min_isv_svn = std::stoi(load_from_ini("client", "MINIMUM_ISVSVN"));
        g_settings.req_isv_prod_id = std::stoi(load_from_ini("client", "REQUIRED_ISV_PROD_ID"));
        g_settings.req_mrenclave = load_from_ini("client", "REQUIRED_MRENCLAVE");
        g_settings.req_mrsigner = load_from_ini("client", "REQUIRED_MRSIGNER");
    } catch (...) {
        print_debug_message(
            "Invalid setting. Probably non-integer value was set illegally.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }

    uint32_t skip_flag = std::stoi(load_from_ini("client", "SKIP_MRENCLAVE_CHECK"));

    if (!(skip_flag == 0 || skip_flag == 1)) {
        print_debug_message("MRENCLAVE check skip flag must be 0 or 1.", ERROR);
        print_debug_message("", ERROR);

        exit(1);
    }

    g_settings.skip_mrenclave_check = skip_flag;
}
