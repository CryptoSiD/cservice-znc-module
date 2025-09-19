# CService ZNC Module

The `CService` ZNC module provides secure login functionality for X on UnderNet, including support for 2FA/TOTP authentication and LoC (Login on Connect). It allows users to configure login details, enable/disable 2FA, and specify user modes. Sensitive data, such as passwords and 2FA secrets, are encrypted using AES-256-CBC encryption (v2.0+ upgrade) for enhanced security.

---

## Features

1. **Secure Login**: Authenticate securely with UnderNet using your username, password, and optional TOTP-based 2FA.
2. **2FA/TOTP Support**: Enhance security by adding time-based one-time passwords to your login process.
3. **LoC (Login on Connect)**: Seamlessly log in to UnderNet using their LoC feature. Learn more: [UnderNet LoC](https://www.undernet.org/loc/).
4. **Custom User Modes**: Set your preferred user mode prefix (`-x!`, `+x!`, or `-!+x`) during server connection.
5. **Encrypted Credentials**: Protect your password and 2FA secret with AES-256-CBC encryption (v2.0+ upgrade), ensuring sensitive data is stored securely.
6. **Clear Configuration**: Delete all stored credentials and settings with the `clearconfig` command.

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/CryptoSiD/cservice-znc-module.git
   cd cservice-znc-module
   ```

2. Build the module:
   ```bash
   znc-buildmod cservice.cpp
   ```

3. Place the compiled module in your ZNC modules directory:
   ```bash
   mv cservice.so ~/.znc/modules/
   ```

4. Load the module in ZNC:
   ```
   /znc loadmod cservice
   ```

---

## Master Key Configuration

The module uses AES-256-CBC encryption to protect sensitive data and requires a 64-character hex master key stored in a file named `cservice.key`.

### Important Change from Previous Versions

**Previous versions** required you to modify the source code and replace a placeholder in the code:
```cpp
const std::string MASTER_KEY_HEX = "REPLACE_WITH_YOUR_64_CHAR_HEX";
```

**Current version** uses an external key file instead. This provides better security and eliminates the need to modify source code. The hardcoded `MASTER_KEY_HEX` variable has been removed entirely.

### Key File Locations

The module will search for the key file in the following locations (in order):
- `~/.znc/users/[username]/moddata/cservice/cservice.key` (User's ZNC data directory)
- `~/.znc/users/[username]/cservice.key` (User's config directory)  
- `~/.znc/modules/cservice.key` (Default location)
- `/etc/znc/cservice.key` (System-wide location)

### Generating a Master Key

You can generate a master key using one of these methods:

**Method 1: Using the module command (recommended)**
```
/msg *cservice createkey
```
This will generate a new key file automatically in your ZNC data directory with proper permissions.

**Method 2: Manual generation**
```bash
openssl rand -hex 32 > ~/.znc/modules/cservice.key
chmod 600 ~/.znc/modules/cservice.key
```

### Security Notes

- The key file should have restrictive permissions (600) - readable/writable by owner only
- Keep your master key file secure and backed up
- If you lose the key file, you'll need to reconfigure all credentials
- Each user should have their own unique key file

---

## Configuration

After loading the module, run the following command for help and configuration options:
```
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

- **`2fa on|off`**  
  Enable or disable 2FA/TOTP authentication.  
  Example: `/msg *cservice 2fa on`  
  Example: `/msg *cservice 2fa off`

- **`setusermode <mode>`**  
  Define the user mode prefix (`-x!`, `+x!`, or `-!+x`) used by LoC during server connection.  
  Example: `/msg *cservice setusermode +x!`

  - **`setconnectpolicy on|off`**  
  Configure whether to allow or block connections when authentication fails. When set to on, ZNC will continue connecting to the server even if authentication fails. When set to off (default), ZNC will block the connection if authentication fails.
  Example: `/msg *cservice setconnectpolicy on`
  Example: `/msg *cservice setconnectpolicy off`

- **`testtotp`**  
  Generate and display the current TOTP code for testing purposes. This command shows the current 6-digit authentication code and how many seconds remain until it expires (codes refresh every 30 seconds). Useful for verifying your 2FA secret is configured correctly before enabling automatic authentication.  
  Example: `/msg *cservice testtotp`

- **`showconfig`**  
  Show the current configuration settings (username, 2FA status, user mode, etc.).  
  Example: `/msg *cservice showconfig`

- **`createkey`**  
  Generate a new random master key file in your ZNC data directory with proper permissions.  
  Example: `/msg *cservice createkey`

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

This module encrypts sensitive data using AES-256-CBC encryption (v2.0+). Each user must have their own master key file as described in the Master Key Configuration section above.

---

## Notes

- **Version 2.0 Upgrade**: Existing configurations are incompatible. You must:
  1. Run `/msg *cservice clearconfig`
  2. Re-enter all credentials with the new encryption system

- **Key File Migration**: If upgrading from a version that used hardcoded keys in the source code, you no longer need to modify the source. Simply generate a key file using the methods described above.

- **Security Warning**: Keep your `cservice.key` file private and secure. Changing or losing it requires full reconfiguration.

- To apply changes after modifying the key file:
  1. `/znc unloadmod cservice`
  2. `/znc loadmod cservice`

---

## See Also
* [UnderNet LoC Documentation](https://www.undernet.org/loc/)

---

Enjoy secure and seamless logins with the CService ZNC module!
