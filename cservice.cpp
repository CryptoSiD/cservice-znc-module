#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <znc/Server.h>
#include <znc/IRCSock.h> // Include CIRCSock definition
#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>

class CService : public CModule {
private:
    bool m_bUse2FA;          // Whether 2FA/TOTP is enabled
    CString m_sSecretKey;    // The 2FA secret key
    CString m_sUserMode;     // User mode prefix (-x!, +x!, etc.)

public:
    MODCONSTRUCTOR(CService) {
        m_bUse2FA = false;
        m_sUserMode = "+x!"; // Default user mode

        AddHelpCommand(); // Add help command automatically

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
        AddCommand("setusermode", t_d("<mode>"), t_d("Define the user mode prefix (-x!, +x!, -!+x) used by LoC during server connection.\n\nExplanation:\n- !: Do not connect to the server if LoC fails (e.g., X is split from the network).\n- x: Set usermode +x to hide client hostname."), [=](const CString& sLine) {
            SetUserMode(sLine);
        });
        AddCommand("showconfig", t_d(""), t_d("Show the current configuration settings"), [=](const CString&) {
            ShowConfig();
        });
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        // Load the saved 2FA and user mode settings from NV storage
        CString sUse2FA = GetNV("use2fa");
        m_bUse2FA = sUse2FA.ToBool();
        CString sUserMode = GetNV("usermode");
        if (!sUserMode.empty()) {
            m_sUserMode = sUserMode;
        }
        return true; // Indicate successful loading
    }

    void ShowConfig() {
        CString sConfigText = "Current Configuration:\n";
        sConfigText += "Username: " + GetNV("username") + "\n";
        sConfigText += "Password: " + CString(GetNV("password").empty() ? "Not Set" : "Set (hidden for security)") + "\n";
        sConfigText += "2FA Secret: " + CString(GetNV("secret").empty() ? "Not Set" : "Set (hidden for security)") + "\n";
        sConfigText += "2FA Enabled: " + CString(m_bUse2FA ? "Yes" : "No") + "\n";
        sConfigText += "User Mode: " + m_sUserMode + "\n";
        PutModule(sConfigText);
    }

    void SetUsername(const CString& sLine) {
        CString sUsername = sLine.Token(1, true).Trim_n();
        SetNV("username", sUsername);
        PutModule("Username set successfully.");
    }

    void SetPassword(const CString& sLine) {
        CString sPassword = sLine.Token(1, true).Trim_n();
        SetNV("password", sPassword);
        PutModule("Password set successfully.");
    }

    void SetSecret(const CString& sLine) {
        CString sSecret = sLine.Token(1, true).Trim_n();
        SetNV("secret", sSecret);
        PutModule("2FA secret key set successfully.");
    }

    void Enable2FA() {
        m_bUse2FA = true;
        SetNV("use2fa", "true");
        PutModule("2FA is now enabled.");
    }

    void Disable2FA() {
        m_bUse2FA = false;
        SetNV("use2fa", "false");
        PutModule("2FA is now disabled.");
    }

    void SetUserMode(const CString& sLine) {
        CString sMode = sLine.Token(1, true).Trim_n();
        if (sMode == "-x!" || sMode == "+x!" || sMode == "-!+x" || sMode == "") {
            m_sUserMode = sMode;
            SetNV("usermode", m_sUserMode);
            PutModule("User mode set to: " + m_sUserMode);
        } else {
            PutModule("Error: Invalid user mode. Allowed values are: -x!, +x!, -!+x.");
        }
    }

    // Generate a Time-Based One-Time Password (TOTP) based on the secret key
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

    // Automatically handles IRC connection setup with LoC and TOTP if enabled
    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        CString sUsername = GetNV("username");
        CString sPassword = GetNV("password");
        CString sServerPassword = m_sUserMode + " " + sUsername + " " + sPassword;

        if (m_bUse2FA) {
            CString sSecretKey = GetNV("secret");
            if (!sSecretKey.empty()) {
                CString sTOTP = GenerateTOTP(sSecretKey);
                sServerPassword += " " + sTOTP;
            }
        }

        // Send server password with optional TOTP and user mode
        pIRCSock->SetPass(sServerPassword);
        return CONTINUE;
    }
};

template<> void TModInfo<CService>(CModInfo& Info) {
    // No wiki page reference
}

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet with TOTP (2FA) and LoC support")
