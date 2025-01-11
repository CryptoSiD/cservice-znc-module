# CService ZNC Module

The `CService` ZNC module provides secure login functionality for X on UnderNet, including support for 2FA/TOTP authentication and LoC (Login on Connect). It allows users to configure login details, enable/disable 2FA, and specify user modes.

---

## Features

1. **Secure Login**: Authenticate securely with UnderNet using your username, password, and optional TOTP-based 2FA.
2. **2FA/TOTP Support**: Enhance security by adding time-based one-time passwords to your login process.
3. **LoC (Login on Connect)**: Seamlessly log in to UnderNet using their LoC feature. Learn more: [UnderNet LoC](https://www.undernet.org/loc/).
4. **Custom User Modes**: Set your preferred user mode prefix (`-x!`, `+x!`, or `-!+x`) during server connection.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repository/cservice-znc-module.git
   cd cservice-znc-module
   ```

2. Generate your `MASTER_KEY` for encrypting sensitive data (password and 2FA secret):
   ```bash
   openssl rand -hex 32
   ```
   Replace the placeholder `MASTER_KEY` in the module code with the generated key:
   ```cpp
   const std::string MASTER_KEY = "REPLACE_WITH_YOUR_OWN_SECURE_KEY";
   ```

3. Build the module:
   ```bash
   znc-buildmod cservice.cpp
   ```

4. Place the compiled module in your ZNC modules directory:
   ```bash
   mv cservice.so ~/.znc/modules/
   ```

5. Load the module in ZNC:
   ```text
   /znc loadmod cservice
   ```

---

## Configuration

After loading the module, run the following command for help and configuration options:
```text
/msg *cservice help
```

You can set:
- Your UnderNet username and password.
- Your 2FA secret for TOTP.
- Enable or disable 2FA.
- Your preferred user mode (`-x!`, `+x!`, or `-!+x`).

---

## Password and 2FA Encryption

This module encrypts sensitive data (password and 2FA secret) using AES-256 encryption. Each user must generate their own encryption key (referred to as `MASTER_KEY`) and update the module code before building it.

### Generating a Secure Encryption Key

To generate a secure 256-bit (32-byte) hexadecimal key, use the following OpenSSL command:
```bash
openssl rand -hex 32
```

Replace the placeholder `MASTER_KEY` in the module code with the generated key:
```cpp
const std::string MASTER_KEY = "REPLACE_WITH_YOUR_OWN_SECURE_KEY";
```

---

## Notes

- **Security Warning**: Always keep your `MASTER_KEY` private. If the key is exposed, encrypted data can be compromised.
- For changes to take effect, reload the module after updating configuration or code:
  ```text
  /znc unloadmod cservice
  /znc loadmod cservice
  ```

---

Enjoy secure and seamless logins with the `CService` ZNC module! For more information, visit [UnderNet](https://www.undernet.org).
