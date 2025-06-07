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
#include <set>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <memory>
#include <cmath>

class CService : public CModule {
private:
    bool m_bUse2FA;
    CString m_sUserMode;
    std::vector<unsigned char> m_keyBytes;

    std::string m_sMasterKeyHex;
    
    // Constants for better maintainability
    static constexpr int TOTP_TIME_STEP = 30;
    static constexpr int TOTP_DIGITS = 6;
    static constexpr size_t AES_KEY_SIZE = 32; // 256 bits
    static constexpr size_t MASTER_KEY_HEX_LENGTH = 64;

    bool IsHexKeyValid(const std::string& key) const {
        if (key.length() != MASTER_KEY_HEX_LENGTH) return false;
        return std::all_of(key.begin(), key.end(), 
                          [](char c) { return std::isxdigit(c); });
    }

    bool LoadMasterKey(CString& sError) {
        // Try multiple possible locations for the key file
        std::vector<CString> keyPaths = {
            GetSavePath() + "/cservice.key",  // User's ZNC data directory
            GetUser()->GetUserPath() + "/cservice.key",  // User's config directory
            "~/.znc/modules/cservice.key",    // Default location
            "/etc/znc/cservice.key"           // System-wide location
        };

        for (const auto& path : keyPaths) {
            CFile keyFile(path);
            if (keyFile.Exists() && keyFile.IsReg()) {
                if (!keyFile.Open(O_RDONLY)) {
                    sError = "Cannot read key file: " + path + " (permission denied)";
                    continue;
                }

                CString keyContent;
                if (!keyFile.ReadFile(keyContent)) {
                    sError = "Failed to read key file: " + path;
                    keyFile.Close();
                    continue;
                }
                keyFile.Close();

                // Clean the key content (remove whitespace, newlines)
                keyContent.Trim();
                m_sMasterKeyHex = keyContent.c_str(); // Fixed: use c_str() instead of AsString()

                if (IsHexKeyValid(m_sMasterKeyHex)) {
                    return true;
                } else {
                    sError = "Invalid key in file: " + path + " (must be 64 hex characters)";
                    continue;
                }
            }
        }

        if (sError.empty()) {
            sError = "Key file not found. Please create one of: " + keyPaths[0] + 
                    ", " + keyPaths[1] + ", " + keyPaths[2] + ", or " + keyPaths[3];
        }
        return false;
    }

    void HexToBytes(const std::string& hex, std::vector<unsigned char>& bytes) {
        bytes.clear();
        bytes.reserve(hex.size() / 2);
        
        for (size_t i = 0; i < hex.size(); i += 2) {
            try {
                unsigned int byte = std::stoi(hex.substr(i, 2), nullptr, 16);
                bytes.push_back(static_cast<unsigned char>(byte));
            } catch (const std::exception& e) {
                throw std::runtime_error("Invalid hex string: " + std::string(e.what()));
            }
        }
    }

    void ValidateSecretKey(const CString& sKey) {
        if (sKey.empty()) {
            throw std::runtime_error("Secret key cannot be empty");
        }
        
        CString sUpper = sKey.AsUpper();
        // Remove padding for validation
        size_t end = sUpper.find_last_not_of('=');
        if (end != CString::npos) {
            sUpper = sUpper.substr(0, end + 1);
        }
        
        if (sUpper.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") != CString::npos) {
            throw std::runtime_error("Invalid Base32 characters in secret");
        }
        
        // Check minimum length (should be at least 16 characters for reasonable security)
        if (sUpper.length() < 16) {
            throw std::runtime_error("Secret key too short (minimum 16 characters)");
        }
    }

    // RAII wrapper for EVP_CIPHER_CTX
    class CipherContext {
    private:
        EVP_CIPHER_CTX* ctx;
    public:
        CipherContext() : ctx(EVP_CIPHER_CTX_new()) {
            if (!ctx) throw std::runtime_error("Failed to create cipher context");
        }
        ~CipherContext() { 
            if (ctx) EVP_CIPHER_CTX_free(ctx); 
        }
        EVP_CIPHER_CTX* get() { return ctx; }
        // Disable copy/move
        CipherContext(const CipherContext&) = delete;
        CipherContext& operator=(const CipherContext&) = delete;
    };

    CString EncryptData(const CString& sData) {
        if (sData.empty()) return "";
        
        CipherContext ctx;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        
        // Generate random IV
        std::vector<unsigned char> iv(EVP_CIPHER_iv_length(cipher));
        if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
            throw std::runtime_error("IV generation failed");
        }

        if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, m_keyBytes.data(), iv.data()) != 1) {
            throw std::runtime_error("Encryption init failed");
        }

        // Allocate buffer with proper size
        int block_size = EVP_CIPHER_block_size(cipher);
        std::vector<unsigned char> ciphertext(sData.size() + block_size);
        int out_len = 0, total_len = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len, 
            reinterpret_cast<const unsigned char*>(sData.data()), 
            static_cast<int>(sData.size())) != 1) {
            throw std::runtime_error("Encryption failed");
        }
        total_len = out_len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total_len, &out_len) != 1) {
            throw std::runtime_error("Encryption finalization failed");
        }
        total_len += out_len;

        // Combine IV + ciphertext
        CString result(reinterpret_cast<const char*>(iv.data()), iv.size());
        result.append(reinterpret_cast<const char*>(ciphertext.data()), total_len);
        
        return result;
    }

    CString DecryptData(const CString& sEncrypted) {
        if (sEncrypted.empty()) return "";
        
        CipherContext ctx;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();
        size_t iv_len = EVP_CIPHER_iv_length(cipher);
        
        if (sEncrypted.size() < iv_len) {
            throw std::runtime_error("Invalid encrypted data: too short");
        }

        // Extract IV
        std::vector<unsigned char> iv(
            reinterpret_cast<const unsigned char*>(sEncrypted.data()),
            reinterpret_cast<const unsigned char*>(sEncrypted.data()) + iv_len
        );

        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, m_keyBytes.data(), iv.data()) != 1) {
            throw std::runtime_error("Decryption init failed");
        }

        const char* ciphertext = sEncrypted.data() + iv_len;
        int ciphertext_len = static_cast<int>(sEncrypted.size() - iv_len);
        
        // Allocate buffer with proper size
        std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(cipher));
        int out_len = 0, total_len = 0;

        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
            reinterpret_cast<const unsigned char*>(ciphertext), ciphertext_len) != 1) {
            throw std::runtime_error("Decryption failed");
        }
        total_len = out_len;

        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total_len, &out_len) != 1) {
            throw std::runtime_error("Decryption finalization failed - possibly corrupted data");
        }
        total_len += out_len;

        return CString(reinterpret_cast<const char*>(plaintext.data()), total_len);
    }

    CString GenerateTOTP(const CString& sSecret) {
        uint64_t timestamp = static_cast<uint64_t>(time(nullptr)) / TOTP_TIME_STEP;
        
        // Convert timestamp to big-endian bytes
        unsigned char time_bytes[8];
        for (int i = 7; i >= 0; --i) {
            time_bytes[i] = timestamp & 0xFF;
            timestamp >>= 8;
        }

        CString sDecodedSecret = DecodeBase32(sSecret);
        if (sDecodedSecret.empty()) {
            throw std::runtime_error("Failed to decode Base32 secret");
        }

        // Generate HMAC-SHA1
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        
        if (!HMAC(EVP_sha1(), 
                 reinterpret_cast<const unsigned char*>(sDecodedSecret.data()), 
                 sDecodedSecret.size(),
                 time_bytes, sizeof(time_bytes),
                 digest, &digest_len)) {
            throw std::runtime_error("HMAC generation failed");
        }

        // Dynamic truncation
        int offset = digest[digest_len - 1] & 0x0F;
        uint32_t code = ((digest[offset] & 0x7F) << 24)
                      | ((digest[offset + 1] & 0xFF) << 16)
                      | ((digest[offset + 2] & 0xFF) << 8)
                      | (digest[offset + 3] & 0xFF);

        code %= 1000000; // 10^6 for 6-digit TOTP
        
        std::ostringstream oss;
        oss << std::setw(TOTP_DIGITS) << std::setfill('0') << code;
        return oss.str();
    }

    CString DecodeBase32(const CString& sInput) {
        static const std::string BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        static std::map<char, unsigned char> char_map;
        
        // Initialize map once
        if (char_map.empty()) {
            for (size_t i = 0; i < BASE32_CHARS.size(); ++i) {
                char_map[BASE32_CHARS[i]] = static_cast<unsigned char>(i);
            }
        }

        CString sClean = sInput.AsUpper();
        if (sClean.empty()) {
            return "";
        }
        
        // Remove padding
        size_t padding_pos = sClean.find('=');
        if (padding_pos != CString::npos) {
            sClean = sClean.substr(0, padding_pos);
        }
        
        size_t input_len = sClean.length();
        if (input_len == 0) {
            return "";
        }
        
        std::vector<unsigned char> output;
        output.reserve((input_len * 5) / 8);
        
        int buffer = 0;
        int bits_left = 0;

        for (char c : sClean) {
            auto it = char_map.find(c);
            if (it == char_map.end()) {
                throw std::runtime_error("Invalid Base32 character: " + std::string(1, c));
            }

            buffer = (buffer << 5) | it->second;
            bits_left += 5;

            if (bits_left >= 8) {
                output.push_back((buffer >> (bits_left - 8)) & 0xFF);
                bits_left -= 8;
            }
        }

        return CString(reinterpret_cast<const char*>(output.data()), output.size());
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
            
        AddCommand("2fa", t_d("on|off"), 
            t_d("Enable or disable 2FA authentication"), 
            [=](const CString& sLine) { Handle2FACommand(sLine); });
            
        AddCommand("setusermode", t_d("<mode>"), 
            t_d("Set user mode (-x!, +x!, -!+x)"), 
            [=](const CString& sLine) { SetUserMode(sLine); });
            
        AddCommand("showconfig", "", 
            t_d("Show current configuration"), 
            [=](const CString&) { ShowConfig(); });
            
        AddCommand("createkey", "", 
            t_d("Generate a new random master key file"), 
            [=](const CString&) { CreateKeyFile(); });
            
        AddCommand("clearconfig", "", 
            t_d("Clear all configuration data"), 
            [=](const CString&) { ClearConfig(); });
            
        AddCommand("testtotp", "", 
            t_d("Generate a test TOTP code"), 
            [=](const CString&) { TestTOTP(); });
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        // Load master key from file
        if (!LoadMasterKey(sMessage)) {
            return false;
        }
        
        try {
            HexToBytes(m_sMasterKeyHex, m_keyBytes);
        } catch (const std::exception& e) {
            sMessage = "Failed to parse master key: " + CString(e.what());
            return false;
        }
        
        m_bUse2FA = GetNV("use2fa").ToBool();
        CString sSavedMode = GetNV("usermode");
        if (!sSavedMode.empty()) {
            m_sUserMode = sSavedMode;
        }
        return true;
    }

    void SetUsername(const CString& sLine) {
        CString sUsername = sLine.Token(1, true).Trim_n();
        
        if (sUsername.empty()) {
            PutModule("Error: Username cannot be empty");
            return;
        }
        
        if (sUsername.find(' ') != CString::npos || sUsername.find('\t') != CString::npos) {
            PutModule("Error: Username cannot contain whitespace");
            return;
        }
        
        // Additional validation for UnderNet username format
        if (sUsername.length() > 12) {
            PutModule("Warning: Username longer than 12 characters may cause issues");
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
        
        if (sPassword.find(' ') != CString::npos || sPassword.find('\t') != CString::npos) {
            PutModule("Error: Password cannot contain whitespace");
            return;
        }
        
        try {
            CString encrypted = EncryptData(sPassword);
            SetNV("password", encrypted);
            PutModule("Password encrypted and stored successfully");
        } catch (const std::exception& e) {
            PutModule("Error encrypting password: " + CString(e.what()));
        }
    }

    void SetSecret(const CString& sLine) {
        CString sSecret = sLine.Token(1, true).Trim_n();
        
        try {
            ValidateSecretKey(sSecret);
            CString encrypted = EncryptData(sSecret);
            SetNV("secret", encrypted);
            PutModule("2FA secret encrypted and stored successfully");
        } catch (const std::exception& e) {
            PutModule("Error: " + CString(e.what()));
        }
    }

    void Handle2FACommand(const CString& sLine) {
        CString sAction = sLine.Token(1).AsLower();
        
        if (sAction == "on") {
            Enable2FA();
        } else if (sAction == "off") {
            Disable2FA();
        } else {
            PutModule("Usage: 2fa <on|off>");
            PutModule("Current status: " + CString(m_bUse2FA ? "Enabled" : "Disabled"));
        }
    }

    void Enable2FA() {
        CString sSecret = GetNV("secret");
        if (sSecret.empty()) {
            PutModule("Error: Set a 2FA secret first using 'setsecret <secret>'");
            return;
        }
        
        // Test if we can decrypt and use the secret
        try {
            CString decrypted = DecryptData(sSecret);
            GenerateTOTP(decrypted); // This will throw if secret is invalid
        } catch (const std::exception& e) {
            PutModule("Error: Cannot enable 2FA - " + CString(e.what()));
            return;
        }
        
        m_bUse2FA = true;
        SetNV("use2fa", "true");
        PutModule("Two-factor authentication enabled successfully");
    }

    void Disable2FA() {
        m_bUse2FA = false;
        SetNV("use2fa", "false");
        PutModule("Two-factor authentication disabled");
    }

    void SetUserMode(const CString& sLine) {
        static const std::set<CString> allowedModes = {"-x!", "+x!", "-!+x"};
        CString sMode = sLine.Token(1).Trim_n();
        
        if (sMode.empty()) {
            PutModule("Current user mode: " + m_sUserMode);
            PutModule("Available modes: -x!, +x!, -!+x");
            return;
        }
        
        if (allowedModes.count(sMode)) {
            m_sUserMode = sMode;
            SetNV("usermode", m_sUserMode);
            PutModule("User mode set to: " + m_sUserMode);
        } else {
            PutModule("Error: Invalid mode '" + sMode + "'. Allowed: -x!, +x!, -!+x");
        }
    }

    void ShowConfig() {
        CString sUsername = GetNV("username");
        CString sPassword = GetNV("password");
        CString sSecret = GetNV("secret");
        
        PutModule("=== Current Configuration ===");
        PutModule("Username: " + (sUsername.empty() ? CString("Not set") : sUsername));
        PutModule("Password: " + (sPassword.empty() ? CString("Not set") : CString("Set (encrypted)")));
        PutModule("2FA Secret: " + (sSecret.empty() ? CString("Not set") : CString("Set (encrypted)")));
        PutModule("2FA Status: " + CString(m_bUse2FA ? "Enabled" : "Disabled"));
        PutModule("User Mode: " + m_sUserMode);
        PutModule("=============================");
    }

    void CreateKeyFile() {
        CString keyPath = GetSavePath() + "/cservice.key";
        
        // Generate 32 random bytes (256 bits)
        std::vector<unsigned char> keyBytes(32);
        if (RAND_bytes(keyBytes.data(), static_cast<int>(keyBytes.size())) != 1) {
            PutModule("Error: Failed to generate random key");
            return;
        }
        
        // Convert to hex string
        std::ostringstream hexStream;
        for (unsigned char byte : keyBytes) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        std::string hexKey = hexStream.str();
        
        // Write to file
        CFile keyFile(keyPath);
        if (!keyFile.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
            PutModule("Error: Cannot create key file at " + keyPath);
            return;
        }
        
        if (!keyFile.Write(hexKey)) {
            PutModule("Error: Failed to write key to file");
            keyFile.Close();
            return;
        }
        
        keyFile.Close();
        PutModule("Master key file created at: " + keyPath);
        PutModule("Key file permissions set to 600 (owner read/write only)");
        PutModule("Please restart ZNC or reload this module to use the new key");
    }

    void TestTOTP() {
        if (!m_bUse2FA) {
            PutModule("2FA is not enabled");
            return;
        }
        
        try {
            CString sEncSecret = GetNV("secret");
            if (sEncSecret.empty()) {
                PutModule("No 2FA secret configured");
                return;
            }
            
            CString sSecret = DecryptData(sEncSecret);
            CString code = GenerateTOTP(sSecret);
            PutModule("Current TOTP code: " + code);
            PutModule("(This code is valid for ~" + 
                     CString(TOTP_TIME_STEP - (time(nullptr) % TOTP_TIME_STEP)) + 
                     " more seconds)");
        } catch (const std::exception& e) {
            PutModule("Error generating TOTP: " + CString(e.what()));
        }
    }

    void ClearConfig() {
        DelNV("username");
        DelNV("password");
        DelNV("secret");
        DelNV("use2fa");
        DelNV("usermode");
        m_bUse2FA = false;
        m_sUserMode = "+x!";
        PutModule("All configuration data cleared successfully");
    }

    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        CString sUsername = GetNV("username");
        CString sEncPassword = GetNV("password");
        
        if (sUsername.empty() || sEncPassword.empty()) {
            PutModule("Error: Missing username or password configuration");
            return CONTINUE;
        }

        try {
            CString sPassword = DecryptData(sEncPassword);
            CString sAuth = m_sUserMode + " " + sUsername + " " + sPassword;

            if (m_bUse2FA) {
                CString sEncSecret = GetNV("secret");
                if (sEncSecret.empty()) {
                    PutModule("Error: 2FA enabled but no secret configured");
                    return CONTINUE;
                }
                
                CString sSecret = DecryptData(sEncSecret);
                CString totpCode = GenerateTOTP(sSecret);
                sAuth += " " + totpCode;
                
            }

            pIRCSock->SetPass(sAuth);
            
        } catch (const std::exception& e) {
            PutModule("Authentication failed: " + CString(e.what()));
        }
        
        return CONTINUE;
    }
};

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet with TOTP (2FA) and LoC support")
