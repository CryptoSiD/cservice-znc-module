#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <znc/Server.h>
#include <znc/IRCSock.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>
#include <set>
#include <array>
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <memory>
#include <cmath>
#include <mutex>

// -----------------------------------------------------------------------------
// Compile-time Base32 lookup table — 0xFF marks invalid characters.
// Defined at namespace scope so it can be used as a constexpr inside CService.
// -----------------------------------------------------------------------------
static constexpr std::array<unsigned char, 256> MakeBase32Table() {
    std::array<unsigned char, 256> t{};
    for (auto& v : t) v = 0xFF;
    for (int i = 0; i < 26; ++i) t['A' + i] = static_cast<unsigned char>(i);
    for (int i = 0; i < 6;  ++i) t['2' + i] = static_cast<unsigned char>(26 + i);
    for (int i = 0; i < 26; ++i) t['a' + i] = static_cast<unsigned char>(i);
    return t;
}
static constexpr std::array<unsigned char, 256> BASE32_TABLE = MakeBase32Table();

class CService : public CModule {
private:
    bool m_bUse2FA;
    bool m_bAllowConnectOnFail;
    CString m_sUserMode;
    std::vector<unsigned char> m_keyBytes;
    // NOTE: m_sMasterKeyHex is cleared immediately after HexToBytes in OnLoad/CreateKeyFile

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------
    static constexpr int    TOTP_TIME_STEP       = 30;
    static constexpr int    TOTP_DIGITS          = 6;
    static constexpr size_t AES_KEY_SIZE         = 32;   // 256-bit key
    static constexpr size_t AES_CBC_IV_LEN      = 16;   // 128-bit IV for CBC
    static constexpr size_t MASTER_KEY_HEX_LEN  = 64;   // 32 bytes → 64 hex chars
    static constexpr int    TOTP_WINDOW          = 1;    // ±1 time step accepted

    // BASE32_TABLE is defined at namespace scope above the class (thread-safe, constexpr)

    // -------------------------------------------------------------------------
    // Secure memory helpers
    // -------------------------------------------------------------------------
    static void SecureClearMem(void* ptr, size_t n) {
        if (ptr && n > 0) OPENSSL_cleanse(ptr, n);
    }

    static void SecureClear(std::string& s) {
        if (!s.empty()) {
            OPENSSL_cleanse(&s[0], s.size());
            s.clear();
            s.shrink_to_fit();
        }
    }

    // CString: cast data() to non-const — ZNC's CString wraps std::string internally.
    static void SecureClear(CString& s) {
        if (!s.empty()) {
            OPENSSL_cleanse(const_cast<char*>(s.data()), s.size());
            s.clear();
        }
    }

    static void SecureClear(std::vector<unsigned char>& v) {
        if (!v.empty()) {
            OPENSSL_cleanse(v.data(), v.size());
            v.clear();
            v.shrink_to_fit();
        }
    }

    // -------------------------------------------------------------------------
    // Hex helpers
    // -------------------------------------------------------------------------
    bool IsHexKeyValid(const std::string& key) const {
        if (key.length() != MASTER_KEY_HEX_LEN) return false;
        return std::all_of(key.begin(), key.end(),
                           [](char c){ return std::isxdigit(static_cast<unsigned char>(c)); });
    }

    void HexToBytes(const std::string& hex, std::vector<unsigned char>& bytes) {
        bytes.clear();
        bytes.reserve(hex.size() / 2);
        for (size_t i = 0; i < hex.size(); i += 2) {
            unsigned int byte = 0;
            std::istringstream ss(hex.substr(i, 2));
            ss >> std::hex >> byte;
            if (ss.fail()) throw std::runtime_error("Invalid hex at position " + std::to_string(i));
            bytes.push_back(static_cast<unsigned char>(byte));
        }
    }

    // -------------------------------------------------------------------------
    // Key file loading
    // -------------------------------------------------------------------------
    bool LoadMasterKey(CString& sError) {
        std::vector<CString> keyPaths = {
            GetSavePath() + "/cservice.key",
            GetUser()->GetUserPath() + "/cservice.key",
            "~/.znc/modules/cservice.key",
            "/etc/znc/cservice.key"
        };

        for (const auto& path : keyPaths) {
            CFile keyFile(path);
            if (!keyFile.Exists() || !keyFile.IsReg()) continue;

            if (!keyFile.Open(O_RDONLY)) {
                // Don't leak the path to PutModule here — just try the next one
                continue;
            }

            CString keyContent;
            bool readOk = keyFile.ReadFile(keyContent);
            keyFile.Close();

            if (!readOk) continue;

            keyContent.Trim();
            std::string hexKey = keyContent.c_str();
            SecureClear(keyContent); // wipe ZNC-owned copy

            if (!IsHexKeyValid(hexKey)) {
                SecureClear(hexKey);
                continue;
            }

            try {
                HexToBytes(hexKey, m_keyBytes);
            } catch (...) {
                SecureClear(hexKey);
                SecureClear(m_keyBytes);
                continue;
            }

            // Wipe hex key from memory immediately — m_keyBytes is all we need
            SecureClear(hexKey);
            return true;
        }

        sError = "Key file not found. Use 'createkey' to generate one at: " + keyPaths[0];
        return false;
    }

    // -------------------------------------------------------------------------
    // RAII EVP_CIPHER_CTX wrapper
    // -------------------------------------------------------------------------
    struct CipherCtx {
        EVP_CIPHER_CTX* ctx;
        CipherCtx()  : ctx(EVP_CIPHER_CTX_new()) {
            if (!ctx) throw std::runtime_error("Failed to create cipher context");
        }
        ~CipherCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
        EVP_CIPHER_CTX* get() { return ctx; }
        CipherCtx(const CipherCtx&) = delete;
        CipherCtx& operator=(const CipherCtx&) = delete;
    };

    // -------------------------------------------------------------------------
    // AES-256-CBC Encrypt
    // Layout: [16-byte IV] [ciphertext]
    // Compatible with blobs encrypted by the original module.
    // -------------------------------------------------------------------------
    CString EncryptData(const CString& sData) {
        if (sData.empty()) return "";
        if (m_keyBytes.empty())
            throw std::runtime_error("No master key loaded. Use 'createkey' to generate one.");

        CipherCtx ctx;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();

        // Random 128-bit IV
        std::vector<unsigned char> iv(AES_CBC_IV_LEN);
        if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1)
            throw std::runtime_error("IV generation failed");

        if (EVP_EncryptInit_ex(ctx.get(), cipher, nullptr,
                               m_keyBytes.data(), iv.data()) != 1)
            throw std::runtime_error("CBC encrypt init failed");

        int block_size = EVP_CIPHER_block_size(cipher);
        std::vector<unsigned char> ciphertext(sData.size() + block_size);
        int out_len = 0, total_len = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                              reinterpret_cast<const unsigned char*>(sData.data()),
                              static_cast<int>(sData.size())) != 1) {
            SecureClear(ciphertext);
            SecureClear(iv);
            throw std::runtime_error("CBC encrypt failed");
        }
        total_len = out_len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total_len, &out_len) != 1) {
            SecureClear(ciphertext);
            SecureClear(iv);
            throw std::runtime_error("CBC encrypt final failed");
        }
        total_len += out_len;

        // Pack: IV + ciphertext
        CString result(reinterpret_cast<const char*>(iv.data()), iv.size());
        result.append(reinterpret_cast<const char*>(ciphertext.data()), total_len);

        SecureClear(ciphertext);
        SecureClear(iv);
        return result;
    }

    // -------------------------------------------------------------------------
    // AES-256-CBC Decrypt
    // -------------------------------------------------------------------------
    CString DecryptData(const CString& sEncrypted) {
        if (sEncrypted.empty()) return "";
        if (m_keyBytes.empty())
            throw std::runtime_error("No master key loaded. Use 'createkey' to generate one.");

        if (sEncrypted.size() < AES_CBC_IV_LEN)
            throw std::runtime_error("Invalid encrypted data: too short");

        const unsigned char* raw = reinterpret_cast<const unsigned char*>(sEncrypted.data());

        std::vector<unsigned char> iv(raw, raw + AES_CBC_IV_LEN);
        const unsigned char* ciphertext_ptr = raw + AES_CBC_IV_LEN;
        int ciphertext_len = static_cast<int>(sEncrypted.size() - AES_CBC_IV_LEN);

        CipherCtx ctx;
        const EVP_CIPHER* cipher = EVP_aes_256_cbc();

        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr,
                               m_keyBytes.data(), iv.data()) != 1) {
            SecureClear(iv);
            throw std::runtime_error("CBC decrypt init failed");
        }

        std::vector<unsigned char> plaintext(ciphertext_len + EVP_CIPHER_block_size(cipher));
        int out_len = 0, total_len = 0;

        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len,
                              ciphertext_ptr, ciphertext_len) != 1) {
            SecureClear(plaintext);
            SecureClear(iv);
            throw std::runtime_error("CBC decrypt failed");
        }
        total_len = out_len;

        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total_len, &out_len) != 1) {
            SecureClear(plaintext);
            SecureClear(iv);
            throw std::runtime_error("CBC decrypt failed — data may be corrupted");
        }
        total_len += out_len;

        CString result(reinterpret_cast<const char*>(plaintext.data()), total_len);
        SecureClear(plaintext);
        SecureClear(iv);
        return result;
    }

    // -------------------------------------------------------------------------
    // Base32 decode (thread-safe compile-time table)
    // -------------------------------------------------------------------------
    CString DecodeBase32(const CString& sInput) {
        if (sInput.empty()) return "";

        // Strip padding
        CString sClean = sInput.AsUpper();
        size_t padPos = sClean.find('=');
        if (padPos != CString::npos) sClean = sClean.substr(0, padPos);
        if (sClean.empty()) return "";

        std::vector<unsigned char> output;
        output.reserve((sClean.size() * 5) / 8);

        int buffer = 0, bits_left = 0;
        for (unsigned char c : sClean) {
            unsigned char val = BASE32_TABLE[c];
            if (val == 0xFF) {
                SecureClear(output);
                throw std::runtime_error("Invalid Base32 character");
            }
            buffer = (buffer << 5) | val;
            bits_left += 5;
            if (bits_left >= 8) {
                output.push_back(static_cast<unsigned char>((buffer >> (bits_left - 8)) & 0xFF));
                bits_left -= 8;
            }
        }

        CString result(reinterpret_cast<const char*>(output.data()), output.size());
        SecureClear(output);
        return result;
    }

    // -------------------------------------------------------------------------
    // TOTP generation (RFC 6238 / HOTP RFC 4226)
    // -------------------------------------------------------------------------
    CString GenerateTOTP(const CString& sSecret) {
        CString sDecodedSecret = DecodeBase32(sSecret);
        if (sDecodedSecret.empty())
            throw std::runtime_error("Failed to decode Base32 secret");

        uint64_t time_step = static_cast<uint64_t>(time(nullptr)) / TOTP_TIME_STEP;

        // Big-endian encode
        unsigned char time_bytes[8];
        uint64_t ts = time_step;
        for (int j = 7; j >= 0; --j) {
            time_bytes[j] = ts & 0xFF;
            ts >>= 8;
        }

        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int  digest_len = 0;

        if (!HMAC(EVP_sha1(),
                  reinterpret_cast<const unsigned char*>(sDecodedSecret.data()),
                  static_cast<int>(sDecodedSecret.size()),
                  time_bytes, sizeof(time_bytes),
                  digest, &digest_len)) {
            SecureClear(sDecodedSecret);
            SecureClearMem(digest,     sizeof(digest));
            SecureClearMem(time_bytes, sizeof(time_bytes));
            throw std::runtime_error("HMAC generation failed");
        }

        int offset = digest[digest_len - 1] & 0x0F;
        uint32_t code = ((digest[offset]     & 0x7F) << 24)
                      | ((digest[offset + 1] & 0xFF) << 16)
                      | ((digest[offset + 2] & 0xFF) <<  8)
                      |  (digest[offset + 3] & 0xFF);
        code %= 1000000;

        SecureClear(sDecodedSecret);
        SecureClearMem(digest,     sizeof(digest));
        SecureClearMem(time_bytes, sizeof(time_bytes));

        std::ostringstream oss;
        oss << std::setw(TOTP_DIGITS) << std::setfill('0') << code;
        return oss.str();
    }

    // -------------------------------------------------------------------------
    // TOTP verification with constant-time compare across ±TOTP_WINDOW steps
    // -------------------------------------------------------------------------
    bool VerifyTOTP(const CString& sSecret, const CString& sUserCode) {
        if (sUserCode.size() != TOTP_DIGITS) return false;

        uint64_t now = static_cast<uint64_t>(time(nullptr)) / TOTP_TIME_STEP;
        bool matched = false;

        for (int i = -TOTP_WINDOW; i <= TOTP_WINDOW; ++i) {
            uint64_t ts = now + i;
            unsigned char time_bytes[8];
            for (int j = 7; j >= 0; --j) { time_bytes[j] = ts & 0xFF; ts >>= 8; }

            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int  digest_len = 0;
            if (!HMAC(EVP_sha1(),
                      reinterpret_cast<const unsigned char*>(sSecret.data()),
                      static_cast<int>(sSecret.size()),
                      time_bytes, sizeof(time_bytes),
                      digest, &digest_len)) {
                SecureClearMem(digest, sizeof(digest));
                continue;
            }

            int offset = digest[digest_len - 1] & 0x0F;
            uint32_t code = ((digest[offset]     & 0x7F) << 24)
                          | ((digest[offset + 1] & 0xFF) << 16)
                          | ((digest[offset + 2] & 0xFF) <<  8)
                          |  (digest[offset + 3] & 0xFF);
            code %= 1000000;

            std::ostringstream oss;
            oss << std::setw(TOTP_DIGITS) << std::setfill('0') << code;
            std::string expected = oss.str();

            // Constant-time compare
            if (CRYPTO_memcmp(expected.data(), sUserCode.data(), TOTP_DIGITS) == 0)
                matched = true;  // don't break — keep loop to avoid timing leak

            SecureClearMem(digest, sizeof(digest));
            SecureClearMem(time_bytes, sizeof(time_bytes));
        }

        return matched;
    }

    // -------------------------------------------------------------------------
    // Secret key validation
    // -------------------------------------------------------------------------
    void ValidateSecretKey(const CString& sKey) {
        if (sKey.empty())
            throw std::runtime_error("Secret key cannot be empty");

        CString sUpper = sKey.AsUpper();
        size_t end = sUpper.find_last_not_of('=');
        if (end != CString::npos) sUpper = sUpper.substr(0, end + 1);

        for (unsigned char c : sUpper) {
            if (BASE32_TABLE[c] == 0xFF)
                throw std::runtime_error("Invalid Base32 character in secret");
        }

        if (sUpper.length() < 16)
            throw std::runtime_error("Secret key too short (minimum 16 Base32 characters)");
    }

public:
    MODCONSTRUCTOR(CService) {
        m_bUse2FA            = false;
        m_bAllowConnectOnFail = false;
        m_sUserMode          = "+x!";

        AddHelpCommand();

        AddCommand("setusername", t_d("<username>"),
            t_d("Set your UnderNet username"),
            [=](const CString& sLine){ SetUsername(sLine); });

        AddCommand("setpassword", t_d("<password>"),
            t_d("Set your UnderNet password (encrypted at rest)"),
            [=](const CString& sLine){ SetPassword(sLine); });

        AddCommand("setsecret", t_d("<secret>"),
            t_d("Set your Base32 2FA secret (encrypted at rest)"),
            [=](const CString& sLine){ SetSecret(sLine); });

        AddCommand("2fa", t_d("on|off"),
            t_d("Enable or disable 2FA"),
            [=](const CString& sLine){ Handle2FACommand(sLine); });

        AddCommand("setusermode", t_d("<mode>"),
            t_d("Set user mode (-x!, +x!, -!+x)"),
            [=](const CString& sLine){ SetUserMode(sLine); });

        AddCommand("setconnectpolicy", t_d("on|off"),
            t_d("Allow or block connection on auth failure"),
            [=](const CString& sLine){ SetConnectPolicy(sLine); });

        AddCommand("showconfig", "",
            t_d("Show current configuration"),
            [=](const CString&){ ShowConfig(); });

        AddCommand("createkey", "",
            t_d("Generate a new random master key file"),
            [=](const CString&){ CreateKeyFile(); });

        AddCommand("clearconfig", "",
            t_d("Clear all stored configuration"),
            [=](const CString&){ ClearConfig(); });

        AddCommand("testtotp", "",
            t_d("Display the current TOTP code"),
            [=](const CString&){ TestTOTP(); });
    }

    ~CService() {
        SecureClear(m_keyBytes);
    }

    // -------------------------------------------------------------------------
    // OnLoad
    // -------------------------------------------------------------------------
    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (!LoadMasterKey(sMessage)) {
            PutModule("Warning: " + sMessage);
            // Allow module to load so the user can run 'createkey'
        }
        // m_sMasterKeyHex never lingers — LoadMasterKey calls HexToBytes and
        // wipes the hex string before returning.

        m_bUse2FA             = GetNV("use2fa").ToBool();
        m_bAllowConnectOnFail = GetNV("allowconnectonfail").ToBool();
        CString sSavedMode    = GetNV("usermode");
        if (!sSavedMode.empty()) m_sUserMode = sSavedMode;

        return true;
    }

    // -------------------------------------------------------------------------
    // Commands
    // -------------------------------------------------------------------------
    void SetUsername(const CString& sLine) {
        CString sUsername = sLine.Token(1, true).Trim_n();
        if (sUsername.empty()) { PutModule("Error: Username cannot be empty"); return; }
        if (sUsername.find(' ') != CString::npos) {
            PutModule("Error: Username cannot contain spaces"); return;
        }
        if (sUsername.length() > 12)
            PutModule("Warning: Username longer than 12 characters may cause issues");
        SetNV("username", sUsername);
        PutModule("Username set to: " + sUsername);
    }

    void SetPassword(const CString& sLine) {
        CString sPassword = sLine.Token(1, true);
        if (sPassword.empty()) { PutModule("Error: Password cannot be empty"); return; }
        if (sPassword.find(' ') != CString::npos) {
            PutModule("Error: Password cannot contain spaces"); return;
        }
        try {
            SetNV("password", EncryptData(sPassword));
            PutModule("Password encrypted (AES-256-CBC) and stored");
        } catch (const std::exception& e) {
            PutModule("Error encrypting password: " + CString(e.what()));
        }
        SecureClear(sPassword);
    }

    void SetSecret(const CString& sLine) {
        CString sSecret = sLine.Token(1, true).Trim_n();
        try {
            ValidateSecretKey(sSecret);
            SetNV("secret", EncryptData(sSecret));
            PutModule("2FA secret encrypted (AES-256-CBC) and stored");
        } catch (const std::exception& e) {
            PutModule("Error: " + CString(e.what()));
        }
        SecureClear(sSecret);
    }

    void Handle2FACommand(const CString& sLine) {
        CString sAction = sLine.Token(1).AsLower();
        if      (sAction == "on")  Enable2FA();
        else if (sAction == "off") Disable2FA();
        else {
            PutModule("Usage: 2fa <on|off>");
            PutModule("Current status: " + CString(m_bUse2FA ? "Enabled" : "Disabled"));
        }
    }

    void Enable2FA() {
        CString sSecret = GetNV("secret");
        if (sSecret.empty()) {
            PutModule("Error: Set a 2FA secret first using 'setsecret <secret>'"); return;
        }
        try {
            CString dec = DecryptData(sSecret);
            GenerateTOTP(dec);
            SecureClear(dec);
        } catch (const std::exception& e) {
            PutModule("Error: Cannot enable 2FA — " + CString(e.what())); return;
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
        static const std::set<CString> allowed = {"-x!", "+x!", "-!+x"};
        CString sMode = sLine.Token(1).Trim_n();
        if (sMode.empty()) {
            PutModule("Current user mode: " + m_sUserMode);
            PutModule("Available modes: -x!, +x!, -!+x");
            return;
        }
        if (allowed.count(sMode)) {
            m_sUserMode = sMode;
            SetNV("usermode", m_sUserMode);
            PutModule("User mode set to: " + m_sUserMode);
        } else {
            PutModule("Error: Invalid mode. Allowed: -x!, +x!, -!+x");
        }
    }

    void SetConnectPolicy(const CString& sLine) {
        CString sPolicy = sLine.Token(1).AsLower();
        if (sPolicy == "on") {
            m_bAllowConnectOnFail = true;
            SetNV("allowconnectonfail", "true");
            PutModule("Policy: allow connection on auth failure");
        } else if (sPolicy == "off") {
            m_bAllowConnectOnFail = false;
            SetNV("allowconnectonfail", "false");
            PutModule("Policy: block connection on auth failure");
        } else {
            PutModule("Usage: setconnectpolicy <on|off>");
            PutModule("Current: " + CString(m_bAllowConnectOnFail
                ? "Allow on failure" : "Block on failure"));
        }
    }

    void ShowConfig() {
        PutModule("=== CService Configuration ===");
        PutModule("Username      : " + (GetNV("username").empty()
            ? CString("Not set") : GetNV("username")));
        PutModule("Password      : " + CString(GetNV("password").empty()
            ? "Not set" : "Set (AES-256-CBC encrypted)"));
        PutModule("2FA Secret    : " + CString(GetNV("secret").empty()
            ? "Not set" : "Set (AES-256-CBC encrypted)"));
        PutModule("2FA Status    : " + CString(m_bUse2FA ? "Enabled" : "Disabled"));
        PutModule("User Mode     : " + m_sUserMode);
        PutModule("Master Key    : " + CString(m_keyBytes.empty() ? "Not loaded" : "Loaded"));
        PutModule("Connect Policy: " + CString(m_bAllowConnectOnFail
            ? "Allow on failure" : "Block on failure"));
        PutModule("================================");
    }

    void CreateKeyFile() {
        CString keyPath = GetSavePath() + "/cservice.key";

        std::vector<unsigned char> keyBytes(AES_KEY_SIZE);
        if (RAND_bytes(keyBytes.data(), static_cast<int>(keyBytes.size())) != 1) {
            SecureClear(keyBytes);
            PutModule("Error: Failed to generate random key");
            return;
        }

        std::ostringstream oss;
        for (unsigned char b : keyBytes)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        std::string hexKey = oss.str();

        CFile keyFile(keyPath);
        if (!keyFile.Open(O_WRONLY | O_CREAT | O_TRUNC, 0600)) {
            SecureClear(keyBytes);
            SecureClear(hexKey);
            PutModule("Error: Cannot create key file at " + keyPath);
            return;
        }
        if (!keyFile.Write(hexKey)) {
            keyFile.Close();
            SecureClear(keyBytes);
            SecureClear(hexKey);
            PutModule("Error: Failed to write key to file");
            return;
        }
        keyFile.Close();

        // Load the new key and immediately wipe the hex string
        try {
            HexToBytes(hexKey, m_keyBytes);
        } catch (const std::exception& e) {
            SecureClear(hexKey);
            SecureClear(keyBytes);
            PutModule("Error loading new key: " + CString(e.what()));
            return;
        }
        SecureClear(hexKey);   // wipe hex immediately
        SecureClear(keyBytes); // wipe raw bytes (m_keyBytes is the live copy)

        PutModule("Master key created and loaded: " + keyPath);
        PutModule("File permissions: 0600 (owner read/write only)");
        PutModule("NOTE: Any previously stored password/secret was encrypted with the old key.");
        PutModule("Re-run 'setpassword' and 'setsecret' to re-encrypt with the new key.");
    }

    void TestTOTP() {
        if (!m_bUse2FA)         { PutModule("2FA is not enabled"); return; }
        if (m_keyBytes.empty()) { PutModule("Error: No master key loaded"); return; }

        CString sEncSecret = GetNV("secret");
        if (sEncSecret.empty()) { PutModule("No 2FA secret configured"); return; }

        try {
            CString sSecret = DecryptData(sEncSecret);
            CString code    = GenerateTOTP(sSecret);
            SecureClear(sSecret);

            uint64_t remaining = TOTP_TIME_STEP - (static_cast<uint64_t>(time(nullptr)) % TOTP_TIME_STEP);
            PutModule("Current TOTP code : " + code);
            PutModule("Valid for ~" + CString(remaining) + " more second(s)");
        } catch (const std::exception& e) {
            PutModule("Error: " + CString(e.what()));
        }
    }

    void ClearConfig() {
        DelNV("username");
        DelNV("password");
        DelNV("secret");
        DelNV("use2fa");
        DelNV("usermode");
        DelNV("allowconnectonfail");
        m_bUse2FA             = false;
        m_bAllowConnectOnFail = false;
        m_sUserMode           = "+x!";
        PutModule("All configuration cleared");
    }

    // -------------------------------------------------------------------------
    // IRC connection hook — sets the server password to the auth string
    // -------------------------------------------------------------------------
    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        CString sUsername    = GetNV("username");
        CString sEncPassword = GetNV("password");

        if (sUsername.empty() || sEncPassword.empty()) {
            PutModule("Error: Missing username or password");
            return m_bAllowConnectOnFail ? CONTINUE : HALT;
        }
        if (m_keyBytes.empty()) {
            PutModule("Error: No master key loaded");
            return m_bAllowConnectOnFail ? CONTINUE : HALT;
        }

        CString sPassword, sAuth;
        try {
            sPassword = DecryptData(sEncPassword);
            sAuth     = m_sUserMode + " " + sUsername + " " + sPassword;

            if (m_bUse2FA) {
                CString sEncSecret = GetNV("secret");
                if (sEncSecret.empty()) {
                    SecureClear(sPassword);
                    SecureClear(sAuth);
                    PutModule("Error: 2FA enabled but no secret configured");
                    return m_bAllowConnectOnFail ? CONTINUE : HALT;
                }
                CString sSecret = DecryptData(sEncSecret);
                CString totpCode = GenerateTOTP(sSecret);
                SecureClear(sSecret);
                sAuth += " " + totpCode;
            }

            pIRCSock->SetPass(sAuth);

        } catch (const std::exception& e) {
            PutModule("Authentication error: " + CString(e.what()));
            SecureClear(sPassword);
            SecureClear(sAuth);
            return m_bAllowConnectOnFail ? CONTINUE : HALT;
        }

        SecureClear(sPassword);
        SecureClear(sAuth);
        return CONTINUE;
    }
};

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet with TOTP (2FA) and LoC support")
