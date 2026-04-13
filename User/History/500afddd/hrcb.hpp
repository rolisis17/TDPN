#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace truepn {

class CryptoContext {
public:
    static std::array<uint8_t, 32> deriveKey(const std::string& psk,
                                             const std::vector<uint8_t>& salt,
                                             const std::string& label);

    static std::vector<uint8_t> encryptAesGcm(const std::array<uint8_t, 32>& key,
                                              const std::array<uint8_t, 12>& nonce,
                                              const std::vector<uint8_t>& plaintext,
                                              const std::vector<uint8_t>& aad,
                                              std::array<uint8_t, 16>& outTag);

    static std::vector<uint8_t> decryptAesGcm(const std::array<uint8_t, 32>& key,
                                              const std::array<uint8_t, 12>& nonce,
                                              const std::vector<uint8_t>& ciphertext,
                                              const std::vector<uint8_t>& aad,
                                              const std::array<uint8_t, 16>& tag);
};

} // namespace truepn
