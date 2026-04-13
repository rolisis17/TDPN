#include "CryptoContext.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <cstring>
#include <stdexcept>

namespace truepn {

std::array<uint8_t, 32> CryptoContext::deriveKey(const std::string& psk,
                                                 const std::vector<uint8_t>& salt,
                                                 const std::string& label)
{
    std::array<uint8_t, 32> out{};

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (pctx == nullptr) {
        throw std::runtime_error("HKDF init failed");
    }

    size_t outLen = out.size();
    if (EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0
        || EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt.data(), static_cast<int>(salt.size())) <= 0
        || EVP_PKEY_CTX_set1_hkdf_key(pctx,
                                      reinterpret_cast<const unsigned char*>(psk.data()),
                                      static_cast<int>(psk.size()))
               <= 0
        || EVP_PKEY_CTX_add1_hkdf_info(
               pctx, reinterpret_cast<const unsigned char*>(label.data()), static_cast<int>(label.size()))
               <= 0
        || EVP_PKEY_derive(pctx, out.data(), &outLen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw std::runtime_error("HKDF derive failed");
    }

    EVP_PKEY_CTX_free(pctx);
    return out;
}

std::vector<uint8_t> CryptoContext::encryptAesGcm(const std::array<uint8_t, 32>& key,
                                                  const std::array<uint8_t, 12>& nonce,
                                                  const std::vector<uint8_t>& plaintext,
                                                  const std::vector<uint8_t>& aad,
                                                  std::array<uint8_t, 16>& outTag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) <= 0
        || EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM init failed");
    }

    int outLen = 0;
    if (!aad.empty() && EVP_EncryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM AAD failed");
    }

    std::vector<uint8_t> ciphertext(plaintext.size());
    if (!plaintext.empty()
        && EVP_EncryptUpdate(
               ctx, ciphertext.data(), &outLen, plaintext.data(), static_cast<int>(plaintext.size()))
               <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encrypt failed");
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM final failed");
    }
    ciphertext.resize(static_cast<size_t>(outLen + finalLen));

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(outTag.size()), outTag.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM tag extraction failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

std::vector<uint8_t> CryptoContext::decryptAesGcm(const std::array<uint8_t, 32>& key,
                                                  const std::array<uint8_t, 12>& nonce,
                                                  const std::vector<uint8_t>& ciphertext,
                                                  const std::vector<uint8_t>& aad,
                                                  const std::array<uint8_t, 16>& tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) <= 0
        || EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM decrypt init failed");
    }

    int outLen = 0;
    if (!aad.empty() && EVP_DecryptUpdate(ctx, nullptr, &outLen, aad.data(), static_cast<int>(aad.size())) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM decrypt AAD failed");
    }

    std::vector<uint8_t> plaintext(ciphertext.size());
    if (!ciphertext.empty()
        && EVP_DecryptUpdate(
               ctx, plaintext.data(), &outLen, ciphertext.data(), static_cast<int>(ciphertext.size()))
               <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM decrypt update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<uint8_t*>(tag.data()))
        <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM tag set failed");
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outLen, &finalLen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM authentication failed");
    }

    plaintext.resize(static_cast<size_t>(outLen + finalLen));
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

} // namespace truepn
