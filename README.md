# CService ZNC Module

The `CService` ZNC module provides secure login functionality for X on UnderNet, including support for 2FA/TOTP authentication and LoC (Login on Connect). It allows users to configure login details, enable/disable 2FA, and specify user modes. Sensitive data, such as passwords and 2FA secrets, are encrypted using AES-256 encryption for enhanced security.

---

## Features

1. **Secure Login**: Authenticate securely with UnderNet using your username, password, and optional TOTP-based 2FA.
2. **2FA/TOTP Support**: Enhance security by adding time-based one-time passwords to your login process.
3. **LoC (Login on Connect)**: Seamlessly log in to UnderNet using their LoC feature. Learn more: [UnderNet LoC](https://www.undernet.org/loc/).
4. **Custom User Modes**: Set your preferred user mode prefix (`-x!`, `+x!`, or `-!+x`) during server connection.
5. **Encrypted Credentials**: Protect your password and 2FA secret with AES-256 encryption, ensuring that sensitive data is stored securely.
6. **Clear Configuration**: Delete all stored credentials and settings with the `clearconfig` command.

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

### Commands

- **`setusername <username>`**  
  Set your UnderNet username.  
  Example: `/msg *cservice setusername myusername`

- **`setpassword <password>`**  
  Set your UnderNet password (stored encrypted).  
  Example: `/msg *cservice setpassword mypassword`

- **`setsecret <secret>`**  
  Set your 2FA/TOTP secret key (stored encrypted). Ensure the secret is formatted correctly (uppercase with no spaces).  
  Example: `/msg *cservice setsecret A1B2C3D4E5F6G7H8`

- **`enable2fa`**  
  Enable 2FA/TOTP authentication.  
  Example: `/msg *cservice enable2fa`

- **`disable2fa`**  
  Disable 2FA/TOTP authentication.  
  Example: `/msg *cservice disable2fa`

- **`setusermode <mode>`**  
  Define the user mode prefix (`-x!`, `+x!`, or `-!+x`) used by LoC during server connection.  
  Example: `/msg *cservice setusermode +x!`

- **`showconfig`**  
  Show the current configuration settings (username, 2FA status, user mode, etc.).  
  Example: `/msg *cservice showconfig`

- **`clearconfig`**  
  Delete all stored configuration data (username, password, 2FA secret, etc.).  
  Example: `/msg *cservice clearconfig`

---

### Formatting the 2FA Secret Key

The CService website provides the 2FA secret key in eight groups separated by spaces, like this:
```
a1b2 c3d4 e5f6 g7h8 i9j0 k1l2 m3n4 o5p6
```
Before entering the key into the module, you must:
1. Remove all spaces.
2. Convert all lowercase letters to uppercase.

For example, if CService gives you `a1b2 c3d4 e5f6 g7h8 i9j0 k1l2 m3n4 o5p6`, you should enter it as:
```
A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6
```
This ensures compatibility with the module.

You can use the following Linux command to reformat the key automatically:
```bash
echo "a1b2 c3d4 e5f6 g7h8 i9j0 k1l2 m3n4 o5p6" | tr -d ' ' | tr '[:lower:]' '[:upper:]'
```

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

- **Security Warning**: Always keep your `MASTER_KEY` private. If the key is exposed, encrypted data can be compromised. If the `MASTER_KEY` is lost, the encrypted password and 2FA secret will no longer work, and you will have to reconfigure the module.
- For changes to take effect, reload the module after updating configuration or code:
  ```text
  /znc unloadmod cservice
  /znc loadmod cservice
  ```

---

Enjoy secure and seamless logins with the `CService` ZNC module!
