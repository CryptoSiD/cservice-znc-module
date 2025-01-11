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
#include <fstream>

class CService : public CModule {
private:
    bool m_bUse2FA;
    CString m_sSecretKey;
    CString m_sUserMode;

    // To generate a secure key, use the following OpenSSL command:
    // openssl rand -hex 32
    const std::string MASTER_KEY = "REPLACE_WITH_YOUR_OWN_SECURE_KEY";

public:
    MODCONSTRUCTOR(CService) {
        m_bUse2FA = false;
        m_sUserMode = "+x!";

        AddHelpCommand();

        AddCommand("setusername", t_d("<username>"), t_d("Set your UnderNet username"), [=](const CString& sLine) {
            SetUsername(sLine);
        });
        AddCommand("setpassword", t_d("<password>"), t_d("Set your UnderNet password"), [=](const CString& sLine) {
            SetPassword(sLine);
        });
        AddCommand("setsecret", t_d("<secret>"), t_d("Set your 2FA/TOTP secret key"), [=](const CString& sLine) {
            SetSecret(sLine);
        });
        AddCommand("enable2fa", t_d(""), t_d("Enable 2FA/TOTP authentication"), [=](const CString&) {
            Enable2FA();
        });
        AddCommand("disable2fa", t_d(""), t_d("Disable 2FA/TOTP authentication"), [=](const CString&) {
            Disable2FA();
        });
        AddCommand("setusermode", t_d("<mode>"), t_d("Define the user mode prefix (-x!, +x!, -!+x) used by LoC during server connection."), [=](const CString& sLine) {
            SetUserMode(sLine);
        });
        AddCommand("showconfig", t_d(""), t_d("Show the current configuration settings"), [=](const CString&) {
            ShowConfig();
        });
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        CString sUse2FA = GetNV("use2fa");
        m_bUse2FA = sUse2FA.ToBool();
        CString sUserMode = GetNV("usermode");
        if (!sUserMode.empty()) {
            m_sUserMode = sUserMode;
        }
        return true;
    }

    void ShowConfig() {
        CString sConfigText = t_s("Current Configuration:\n");
        sConfigText += t_s("Username: ") + GetNV("username") + t_s("\n");
        sConfigText += t_s("Password: ") + CString("********") + t_s("\n");
        sConfigText += t_s("2FA Secret: ") + CString("********") + t_s("\n");
        sConfigText += t_s("2FA Enabled: ") + (m_bUse2FA ? t_s("Yes") : t_s("No")) + t_s("\n");
        sConfigText += t_s("User Mode: ") + m_sUserMode + t_s("\n");
        PutModule(sConfigText);
    }

    CString EncryptData(const CString& sData) {
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));

        unsigned char ciphertext[1024];
        int len = 0, ciphertextLen = 0;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(MASTER_KEY.data()), iv);

        EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(sData.data()), sData.size());
        ciphertextLen += len;

        EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &len);
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        CString result(reinterpret_cast<const char*>(iv), sizeof(iv));
        result += CString(reinterpret_cast<const char*>(ciphertext), ciphertextLen);
        return result;
    }

    CString DecryptData(const CString& sEncryptedData) {
        unsigned char iv[16];
        memcpy(iv, sEncryptedData.data(), sizeof(iv));

        unsigned char ciphertext[1024];
        int ciphertextLen = sEncryptedData.size() - sizeof(iv);
        memcpy(ciphertext, sEncryptedData.data() + sizeof(iv), ciphertextLen);

        unsigned char plaintext[1024];
        int len = 0, plaintextLen = 0;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                           reinterpret_cast<const unsigned char*>(MASTER_KEY.data()), iv);

        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertextLen);
        plaintextLen += len;

        EVP_DecryptFinal_ex(ctx, plaintext + plaintextLen, &len);
        plaintextLen += len;

        EVP_CIPHER_CTX_free(ctx);

        return CString(reinterpret_cast<const char*>(plaintext), plaintextLen);
    }

    void SetPassword(const CString& sLine) {
        CString sPassword = sLine.Token(1);
        CString encryptedPassword = EncryptData(sPassword);
        SetNV("password", encryptedPassword);
        PutModule(t_s("Password set successfully (encrypted)."));
    }

    void SetSecret(const CString& sLine) {
        CString sSecret = sLine.Token(1);
        CString encryptedSecret = EncryptData(sSecret);
        SetNV("secret", encryptedSecret);
        PutModule(t_s("2FA secret key set successfully (encrypted)."));
    }

    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        CString sUsername = GetNV("username");
        CString sEncryptedPassword = GetNV("password");
        CString sDecryptedPassword = DecryptData(sEncryptedPassword);

        CString sServerPassword = m_sUserMode + " " + sUsername + " " + sDecryptedPassword;

        if (m_bUse2FA) {
            CString sEncryptedSecret = GetNV("secret");
            CString sDecryptedSecret = DecryptData(sEncryptedSecret);
            if (!sDecryptedSecret.empty()) {
                CString sTOTP = GenerateTOTP(sDecryptedSecret);
                sServerPassword += " " + sTOTP;
            }
        }

        pIRCSock->SetPass(sServerPassword);
        return CONTINUE;
    }

    void SetUsername(const CString& sLine) {
        CString sUsername = sLine.Token(1);
        SetNV("username", sUsername);
        PutModule(t_s("Username set successfully."));
    }

    void Enable2FA() {
        m_bUse2FA = true;
        SetNV("use2fa", "true");
        PutModule(t_s("2FA is now enabled."));
    }

    void Disable2FA() {
        m_bUse2FA = false;
        SetNV("use2fa", "false");
        PutModule(t_s("2FA is now disabled."));
    }

    void SetUserMode(const CString& sLine) {
        CString sMode = sLine.Token(1);
        if (sMode == "-x!" || sMode == "+x!" || sMode == "-!+x" || sMode == "") {
            m_sUserMode = sMode;
            SetNV("usermode", m_sUserMode);
            PutModule(t_s("User mode set to: ") + m_sUserMode);
        } else {
            PutModule(t_s("Error: Invalid user mode. Allowed values are: -x!, +x!, -!+x."));
        }
    }

    CString GenerateTOTP(const CString& sSecretKey) {
        CString sDecodedSecret = DecodeBase32(sSecretKey);
        uint64_t timeStep = std::time(nullptr) / 30;

        unsigned char timeStepBytes[8];
        for (int i = 7; i >= 0; --i) {
            timeStepBytes[i] = timeStep & 0xFF;
            timeStep >>= 8;
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        HMAC(EVP_sha1(),
             reinterpret_cast<const unsigned char*>(sDecodedSecret.data()),
             sDecodedSecret.length(),
             timeStepBytes,
             sizeof(timeStepBytes),
             hash,
             &hashLen);

        int offset = hash[hashLen - 1] & 0xF;

        uint32_t truncatedHash = 0;
        for (int i = 0; i < 4; ++i) {
            truncatedHash <<= 8;
            truncatedHash |= hash[offset + i];
        }

        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= 1000000;

        std::ostringstream oss;
        oss << std::setw(6) << std::setfill('0') << truncatedHash;
        return CString(oss.str());
    }

    CString DecodeBase32(const CString& sEncoded) {
        static const char* base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::map<char, int> base32Map;
        for (int i = 0; i < 32; ++i) {
            base32Map[base32Chars[i]] = i;
        }

        std::vector<unsigned char> bytes;
        int buffer = 0;
        int bitsLeft = 0;
        for (char c : sEncoded) {
            if (c == '=') continue;
            buffer <<= 5;
            buffer |= base32Map[c];
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                bytes.push_back((buffer >> bitsLeft) & 0xFF);
            }
        }

        return CString(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }
};

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet with TOTP (2FA) and LoC support")
