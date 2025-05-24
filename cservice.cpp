#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <znc/Server.h>
#include <znc/IRCSock.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <cstring>
#include <algorithm>
#include <stdexcept>

class CService : public CModule {
private:
    bool m_bUse2FA;
    CString m_sUserMode;
    std::vector<unsigned char> m_keyBytes;

    const std::string MASTER_KEY_HEX = "REPLACE_WITH_64_HEX_CHARS";

    bool IsHexKeyValid() const {
        if (MASTER_KEY_HEX.length() != 64) return false;
        for (char c : MASTER_KEY_HEX) {
            if (!isxdigit(c)) return false;
        }
        return true;
    }

    void HexToBytes(const std::string& hex, std::vector<unsigned char>& bytes) {
        bytes.clear();
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned int byte;
            std::stringstream ss;
            ss << std::hex << hex.substr(i, 2);
            ss >> byte;
            bytes.push_back(static_cast<unsigned char>(byte));
        }
    }

    void ValidateSecretKey(const CString& sKey) {
        if (sKey.empty()) throw std::runtime_error("Secret key cannot be empty");
        CString sUpper = sKey.AsUpper();
        if (sUpper.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=") != CString::npos) {
            throw std::runtime_error("Invalid Base32 characters in secret");
        }
    }

public:
    MODCONSTRUCTOR(CService) {
        m_bUse2FA = false;
        m_sUserMode = "+x!";

        AddHelpCommand();
        
        AddCommand("setusername", t_d("<username>"), 
            t_d("Set your UnderNet username (no spaces)"), 
            [=](const CString& sLine) { SetUsername(sLine); });
            
        AddCommand("setpassword", t_d("<password>"), 
            t_d("Set your UnderNet password (no spaces)"), 
            [=](const CString& sLine) { SetPassword(sLine); });
            
        AddCommand("setsecret", t_d("<secret>"), 
            t_d("Set your Base32 2FA secret"), 
            [=](const CString& sLine) { SetSecret(sLine); });
            
        AddCommand("enable2fa", "", 
            t_d("Enable 2FA authentication"), 
            [=](const CString&) { Enable2FA(); });
            
        AddCommand("disable2fa", "", 
            t_d("Disable 2FA authentication"), 
            [=](const CString&) { Disable2FA(); });
            
        AddCommand("setusermode", t_d("<mode>"), 
            t_d("Set user mode (-x!, +x!, -!+x)"), 
            [=](const CString& sLine) { SetUserMode(sLine); });
            
        AddCommand("showconfig", "", 
            t_d("Show current configuration"), 
            [=](const CString&) { ShowConfig(); });
            
        AddCommand("clearconfig", "", 
            t_d("Clear all configuration data"), 
            [=](const CString&) { ClearConfig(); });
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (!IsHexKeyValid()) {
            sMessage = "Invalid MASTER_KEY_HEX: Must be 64 hex characters";
            return false;
        }
        HexToBytes(MASTER_KEY_HEX, m_keyBytes);
        
        m_bUse2FA = GetNV("use2fa").ToBool();
        CString sSavedMode = GetNV("usermode");
        if (!sSavedMode.empty()) {
            m_sUserMode = sSavedMode;
        }
        return true;
    }

    CString EncryptData(const CString& sData) {
        if (sData.empty()) return "";
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        try {
            const EVP_CIPHER* cipher = EVP_aes_256_cbc();
            std::vector<unsigned char> iv(EVP_CIPHER_iv_length(cipher));
            if (RAND_bytes(iv.data(), iv.size()) != 1) {
                throw std::runtime_error("IV generation failed");
            }

            if (EVP_EncryptInit_ex(ctx, cipher, nullptr, m_keyBytes.data(), iv.data()) != 1) {
                throw std::runtime_error("Encryption init failed");
            }

            int block_size = EVP_CIPHER_block_size(cipher);
            std::vector<unsigned char> ciphertext(sData.size() + block_size);
            int out_len = 0, total_len = 0;

            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, 
                reinterpret_cast<const unsigned char*>(sData.data()), sData.size()) != 1) {
                throw std::runtime_error("Encryption failed");
            }
            total_len = out_len;

            if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &out_len) != 1) {
                throw std::runtime_error("Encryption finalization failed");
            }
            total_len += out_len;

            CString result(reinterpret_cast<const char*>(iv.data()), iv.size());
            result.append(reinterpret_cast<const char*>(ciphertext.data()), total_len);
            
            EVP_CIPHER_CTX_free(ctx);
            return result;
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }

    CString DecryptData(const CString& sEncrypted) {
        if (sEncrypted.empty()) return "";
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        try {
            const EVP_CIPHER* cipher = EVP_aes_256_cbc();
            size_t iv_len = EVP_CIPHER_iv_length(cipher);
            
            if (sEncrypted.size() < iv_len) {
                throw std::runtime_error("Invalid encrypted data");
            }

            std::vector<unsigned char> iv(
                reinterpret_cast<const unsigned char*>(sEncrypted.data()),
                reinterpret_cast<const unsigned char*>(sEncrypted.data()) + iv_len
            );

            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, m_keyBytes.data(), iv.data()) != 1) {
                throw std::runtime_error("Decryption init failed");
            }

            const char* ciphertext = sEncrypted.data() + iv_len;
            int ciphertext_len = sEncrypted.size() - iv_len;
            
            std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(cipher));
            int out_len = 0, total_len = 0;

            if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                reinterpret_cast<const unsigned char*>(ciphertext), ciphertext_len) != 1) {
                throw std::runtime_error("Decryption failed");
            }
            total_len = out_len;

            if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &out_len) != 1) {
                throw std::runtime_error("Decryption finalization failed");
            }
            total_len += out_len;

            EVP_CIPHER_CTX_free(ctx);
            return CString(reinterpret_cast<const char*>(plaintext.data()), total_len);
        } catch (...) {
            EVP_CIPHER_CTX_free(ctx);
            throw;
        }
    }

    void SetUsername(const CString& sLine) {
        CString sUsername = sLine.Token(1, true);
        if (sUsername.empty()) {
            PutModule("Error: Username cannot be empty");
            return;
        }
        if (sUsername.find(' ') != CString::npos) {
            PutModule("Error: Username cannot contain spaces");
            return;
        }
        SetNV("username", sUsername);
        PutModule("Username set to: " + sUsername);
    }

    void SetPassword(const CString& sLine) {
        CString sPassword = sLine.Token(1, true);
        if (sPassword.empty()) {
            PutModule("Error: Password cannot be empty");
            return;
        }
        if (sPassword.find(' ') != CString::npos) {
            PutModule("Error: Password cannot contain spaces");
            return;
        }
        
        try {
            CString encrypted = EncryptData(sPassword);
            SetNV("password", encrypted);
            PutModule("Password encrypted and stored");
        } catch (const std::exception& e) {
            PutModule("Error: " + CString(e.what()));
        }
    }

    void SetSecret(const CString& sLine) {
        CString sSecret = sLine.Token(1, true);
        try {
            ValidateSecretKey(sSecret);
            CString encrypted = EncryptData(sSecret);
            SetNV("secret", encrypted);
            PutModule("2FA secret encrypted and stored");
        } catch (const std::exception& e) {
            PutModule("Error: " + CString(e.what()));
        }
    }

    void Enable2FA() {
        CString sSecret = GetNV("secret");
        if (sSecret.empty()) {
            PutModule("Error: Set a 2FA secret first");
            return;
        }
        m_bUse2FA = true;
        SetNV("use2fa", "true");
        PutModule("Two-factor authentication enabled");
    }

    void Disable2FA() {
        m_bUse2FA = false;
        SetNV("use2fa", "false");
        PutModule("Two-factor authentication disabled");
    }

    void SetUserMode(const CString& sLine) {
        static const std::set<CString> allowedModes = {"-x!", "+x!", "-!+x"};
        CString sMode = sLine.Token(1);
        
        if (allowedModes.count(sMode)) {
            m_sUserMode = sMode;
            SetNV("usermode", m_sUserMode);
            PutModule("User mode set to: " + m_sUserMode);
        } else {
            PutModule("Error: Invalid mode. Allowed: -x!, +x!, -!+x");
        }
    }

    void ShowConfig() {
        CString sUsername = GetNV("username");
        CString sPassword = GetNV("password");
        CString sSecret = GetNV("secret");
        
        CString sMsg = "Current Configuration:\n";
        sMsg += CString("Username: ") + (sUsername.empty() ? CString("Not set") : sUsername) + "\n";
        sMsg += CString("Password: ") + (sPassword.empty() ? CString("Not set") : CString("********")) + "\n";
        sMsg += CString("2FA Secret: ") + (sSecret.empty() ? CString("Not set") : CString("********")) + "\n";
        sMsg += CString("2FA Status: ") + (m_bUse2FA ? "Enabled" : "Disabled") + "\n";
        sMsg += CString("User Mode: ") + m_sUserMode;
        
        PutModule(sMsg);
    }

    void ClearConfig() {
        DelNV("username");
        DelNV("password");
        DelNV("secret");
        DelNV("use2fa");
        DelNV("usermode");
        m_bUse2FA = false;
        m_sUserMode = "+x!";
        PutModule("All configuration data cleared");
    }

    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        CString sUsername = GetNV("username");
        CString sEncPassword = GetNV("password");
        CString sPassword;
        
        try {
            sPassword = DecryptData(sEncPassword);
        } catch (const std::exception& e) {
            PutModule("Error: Failed to decrypt password - " + CString(e.what()));
            return CONTINUE;
        }

        if (sUsername.empty() || sPassword.empty()) {
            PutModule("Error: Missing username or password");
            return CONTINUE;
        }

        CString sAuth = m_sUserMode + " " + sUsername + " " + sPassword;

        if (m_bUse2FA) {
            try {
                CString sEncSecret = GetNV("secret");
                CString sSecret = DecryptData(sEncSecret);
                sAuth += " " + GenerateTOTP(sSecret);
            } catch (const std::exception& e) {
                PutModule("Error: 2FA failed - " + CString(e.what()));
            }
        }

        pIRCSock->SetPass(sAuth);
        return CONTINUE;
    }

    CString GenerateTOTP(const CString& sSecret) {
        const int TIME_STEP = 30;
        uint64_t timestamp = time(nullptr) / TIME_STEP;
        
        unsigned char time_bytes[8];
        for (int i = 7; i >= 0; --i) {
            time_bytes[i] = timestamp & 0xFF;
            timestamp >>= 8;
        }

        CString sDecodedSecret = DecodeBase32(sSecret);
        if (sDecodedSecret.empty()) {
            throw std::runtime_error("Invalid Base32 secret");
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len;
        HMAC(EVP_sha1(), 
            reinterpret_cast<const unsigned char*>(sDecodedSecret.data()), sDecodedSecret.size(),
            time_bytes, sizeof(time_bytes),
            digest, &digest_len);

        int offset = digest[digest_len - 1] & 0x0F;
        uint32_t code = (digest[offset] & 0x7F) << 24
                      | (digest[offset + 1] & 0xFF) << 16
                      | (digest[offset + 2] & 0xFF) << 8
                      | (digest[offset + 3] & 0xFF);

        code %= 1000000;
        std::ostringstream oss;
        oss << std::setw(6) << std::setfill('0') << code;
        return oss.str();
    }

    CString DecodeBase32(const CString& sInput) {
        const std::string BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::map<char, unsigned char> CHAR_MAP;
        for (size_t i = 0; i < BASE32_CHARS.size(); ++i) {
            CHAR_MAP[BASE32_CHARS[i]] = i;
        }

        CString sClean = sInput.AsUpper();
        size_t input_len = sClean.length();
        std::vector<unsigned char> output((input_len * 5) / 8, 0);
        
        int buffer = 0;
        int bits_left = 0;
        size_t count = 0;

        for (unsigned char c : sClean) {
            if (c == '=') break;
            if (CHAR_MAP.find(c) == CHAR_MAP.end()) continue;

            buffer <<= 5;
            buffer |= CHAR_MAP[c];
            bits_left += 5;

            if (bits_left >= 8) {
                output[count++] = (buffer >> (bits_left - 8)) & 0xFF;
                bits_left -= 8;
            }
        }

        return CString(reinterpret_cast<const char*>(output.data()), count);
    }
};

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet with TOTP (2FA) and LoC support")
