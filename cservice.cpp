#include <znc/Modules.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>
#include <openssl/hmac.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <map>

class CService : public CModule {
private:
    bool m_bUse2FA;          // Whether 2FA is enabled
    CString m_sSecretKey;    // The 2FA secret key
    bool m_bLoggedIn;        // Whether the user is logged in

public:
    MODCONSTRUCTOR(CService) {
        m_bUse2FA = false;
        m_bLoggedIn = false;
    }

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        // Load the saved 2FA setting from NV storage
        CString sUse2FA = GetNV("use2fa");
        m_bUse2FA = sUse2FA.Equals("true");
//        PutModule("2FA setting loaded: " + CString(m_bUse2FA ? "Enabled" : "Disabled"));
        return true; // Indicate successful loading
    }

    void OnModCommand(const CString& sCommand) override {
        CString sAction = sCommand.Token(0).AsLower();
        if (sAction == "help") {
            ShowHelp();
        } else if (sAction == "showconfig") {
            ShowConfig();
        } else if (sAction == "setusername") {
            SetUsername(sCommand);
        } else if (sAction == "setpassword") {
            SetPassword(sCommand);
        } else if (sAction == "setsecret") {
            SetSecret(sCommand);
        } else if (sAction == "enable2fa") {
            Enable2FA();
        } else if (sAction == "disable2fa") {
            Disable2FA();
        }
    }

    void ShowHelp() {
        CString sHelpText = "Available Commands:\n";
        sHelpText += "setusername <username> - Set your UnderNet username.\n";
        sHelpText += "setpassword <password> - Set your UnderNet password.\n";
        sHelpText += "setsecret <secret> - Set your 2FA secret key.\n";
        sHelpText += "enable2fa - Enable 2FA authentication.\n";
        sHelpText += "disable2fa - Disable 2FA authentication.\n";
        sHelpText += "showconfig - Show the current configuration settings.\n";
        sHelpText += "help - Show this help message.\n";
        PutModule(sHelpText);
    }

    void ShowConfig() {
        CString sConfigText = "Current Configuration:\n";
        sConfigText += "Username: " + GetNV("username") + "\n";
        sConfigText += "Password: " + CString(GetNV("password").empty() ? "Not Set" : "Set (hidden for security)") + "\n";
        sConfigText += "2FA Secret: " + CString(GetNV("secret").empty() ? "Not Set" : "Set (hidden for security)") + "\n";
        sConfigText += "2FA Enabled: " + CString(m_bUse2FA ? "Yes" : "No") + "\n";
        PutModule(sConfigText);
    }

    void SetUsername(const CString& sCommand) {
        SetNV("username", sCommand.Token(1, true));
        PutModule("Username set successfully.");
    }

    void SetPassword(const CString& sCommand) {
        SetNV("password", sCommand.Token(1, true));
        PutModule("Password set successfully.");
    }

    void SetSecret(const CString& sCommand) {
        SetNV("secret", sCommand.Token(1, true));
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

    void AttemptLogin() {
        CString sUsername = GetNV("username");
        CString sPassword = GetNV("password");
        CString sSecretKey = GetNV("secret");

        if (m_bUse2FA && !sSecretKey.empty()) {
            CString sTOTP = GenerateTOTP(sSecretKey);
            GetNetwork()->PutIRC("PRIVMSG X@channels.undernet.org :LOGIN " + sUsername + " " + sPassword + " " + sTOTP);
        } else {
            GetNetwork()->PutIRC("PRIVMSG X@channels.undernet.org :LOGIN " + sUsername + " " + sPassword);
        }
        m_bLoggedIn = true;
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
        return CString(oss.str().c_str());
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

    void OnIRCConnected() override {
        m_bLoggedIn = false;
        AttemptLogin();
    }
};

template<> void TModInfo<CService>(CModInfo& Info) {
    Info.SetWikiPage("cservice");
}

NETWORKMODULEDEFS(CService, "Logs in to X on UnderNet and supports 2FA, with reconnection handling")
