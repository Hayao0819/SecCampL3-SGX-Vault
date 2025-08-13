#ifndef CLIENT_ENCRYPT_HPP
#define CLIENT_ENCRYPT_HPP

#include <cstdint>
#include <string>

struct EncryptedPayload {
    std::string cipher_b64;
    std::string iv_b64;
    std::string tag_b64;
};

EncryptedPayload encrypt_and_base64(const std::string& plaintext, uint8_t* key);
std::string decrypt_from_base64(const EncryptedPayload& payload, uint8_t* key);

#endif  // CLIENT_ENCRYPT_HPP
