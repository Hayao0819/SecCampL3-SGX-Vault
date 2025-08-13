#include "client_headers.hpp"
#include "client_ra.hpp"

// ここはあなたのプロジェクトで使っているbase64やaes_128_gcm_encrypt等の関数の宣言や
// 必要なインクルードを適宜入れてください

struct EncryptedPayload {
    std::string cipher_b64;  // Base64エンコード済みの暗号文
    std::string iv_b64;      // Base64エンコード済みの初期化ベクトル（IV）
    std::string tag_b64;     // Base64エンコード済みの認証タグ（GCMタグ）
};

/**
 * @brief 平文をAES-128-GCMで暗号化し、Base64エンコードした構造体を返す
 * @param plaintext 暗号化対象の文字列
 * @param key 16バイトの暗号鍵（uint8_t*）
 * @return EncryptedPayload 暗号文・IV・タグのBase64文字列を持つ構造体
 * @throws std::runtime_error 暗号化やIV生成失敗時
 */
EncryptedPayload encrypt_and_base64(const std::string& plaintext, uint8_t* key) {
    size_t len = plaintext.size();
    // IVはGCMで通常12バイト
    uint8_t* iv = new uint8_t[12]();
    uint8_t* tag = new uint8_t[16]();
    uint8_t* cipher = new uint8_t[len]();

    // 12バイトのランダムIV生成
    if (generate_nonce(iv, 12)) {
        delete[] iv;
        delete[] tag;
        delete[] cipher;
        throw std::runtime_error("IV (nonce) generation failed");
    }

    // AES-GCM暗号化実行
    if (-1 == aes_128_gcm_encrypt(
                  reinterpret_cast<uint8_t*>(const_cast<char*>(plaintext.c_str())),
                  len,
                  key,
                  iv,
                  cipher,
                  tag)) {
        delete[] iv;
        delete[] tag;
        delete[] cipher;
        throw std::runtime_error("AES-128-GCM encryption failed");
    }

    // Base64エンコードして返す
    EncryptedPayload payload = {
        base64_encode<char, uint8_t>(cipher, len),
        base64_encode<char, uint8_t>(iv, 12),
        base64_encode<char, uint8_t>(tag, 16)};
    delete[] iv;
    delete[] tag;
    delete[] cipher;
    return payload;
}

/**
 * @brief Base64エンコードされたAES-128-GCM暗号文を復号し、平文を返す
 * @param payload 暗号文・IV・タグのBase64文字列を持つ構造体
 * @param key 16バイトの復号鍵
 * @return std::string 復号された平文文字列
 * @throws std::runtime_error 復号失敗やフォーマット異常時
 */
std::string decrypt_from_base64(const EncryptedPayload& payload, uint8_t* key) {
    size_t cipher_len, iv_len, tag_len;

    // Base64デコード
    uint8_t* cipher = base64_decode<uint8_t, char>(const_cast<char*>(payload.cipher_b64.c_str()), cipher_len);
    uint8_t* iv = base64_decode<uint8_t, char>(const_cast<char*>(payload.iv_b64.c_str()), iv_len);
    uint8_t* tag = base64_decode<uint8_t, char>(const_cast<char*>(payload.tag_b64.c_str()), tag_len);

    if (iv_len != 12) {
        delete[] cipher;
        delete[] iv;
        delete[] tag;
        throw std::runtime_error("Invalid IV length (expected 12 bytes)");
    }
    if (tag_len != 16) {
        delete[] cipher;
        delete[] iv;
        delete[] tag;
        throw std::runtime_error("Invalid GCM tag length (expected 16 bytes)");
    }

    // 復号用バッファ確保
    uint8_t* plain = new uint8_t[cipher_len]();

    // AES-GCM復号
    if (-1 == aes_128_gcm_decrypt(
                  cipher,
                  cipher_len,
                  key,
                  iv,
                  tag,
                  plain)) {
        delete[] cipher;
        delete[] iv;
        delete[] tag;
        delete[] plain;
        throw std::runtime_error("AES-128-GCM decryption failed");
    }

    // 平文を文字列化（バイナリデータでなければそのままOK）
    std::string result(reinterpret_cast<char*>(plain), cipher_len);
    delete[] cipher;
    delete[] iv;
    delete[] tag;
    delete[] plain;
    return result;
}
