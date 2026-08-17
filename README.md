# ⚡ C3SER

<p align="center">
<img src="https://img.shields.io/badge/version-v4.1.0-ff0080?style=for-the-badge">
<img src="https://img.shields.io/badge/python-3.x-00ff88?style=for-the-badge">
<img src="https://img.shields.io/badge/platform-cross--platform-00d4ff?style=for-the-badge">
<img src="https://img.shields.io/badge/status-active-success?style=for-the-badge">
</p>

<p align="center">

```text
 ██████╗ ██████╗ ███████╗███████╗██████╗
██╔════╝╚════██╗██╔════╝██╔════╝██╔══██╗
██║      █████╔╝███████╗█████╗  ██████╔╝
██║      ╚═══██╗╚════██║██╔══╝  ██╔══██╗
╚██████╗██████╔╝███████║███████╗██║  ██║
 ╚═════╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝
```

**Terminal-Native Cipher & Crypto Toolkit**

*Encode • Decode • Crack • Analyze • Encrypt • Hash*

</p>

---

## 🕶️ Overview

C3SER is a hacker-style cryptography and cipher toolkit built entirely in Python.

Designed for:

* 🔐 Cryptography enthusiasts
* 🎓 Students learning classical ciphers
* 🧩 CTF players
* 🔍 Security researchers
* 💻 Terminal power users

The toolkit combines classical ciphers, modern cryptography, entropy analysis, hashing utilities, JWT handling, file operations, codec conversion, and cryptanalysis into a single script.

---

# 🚀 Features

## 🧠 Classical Cipher Toolkit

### Caesar Cipher

* Encode text
* Decode text
* Custom shift support

### ROT13

* Instant transformation

### Atbash Cipher

* Classical substitution cipher

### Vigenère Cipher

* Encode with keyword
* Decode with keyword
* Input validation

### Caesar Auto-Crack

* Chi-Squared Analysis
* Language Profiles:

  * English
  * French
  * German
  * Spanish

### Brute Force Mode

* Try all 26 shifts
* Preview mode
* Full output mode

---

## 🔐 Modern Cryptography

Optional Cryptography Module Support

### AES-256-GCM

* Authenticated encryption
* Password-based key derivation

### ChaCha20-Poly1305

* Modern authenticated cipher

### Fernet Encryption

* Secure token-based encryption

### JWT Toolkit

* Encode JWT
* Decode JWT
* Signature verification
* Claims validation

---

## 📦 Encoding & Decoding

Supported formats:

| Format | Encode | Decode |
| ------ | ------ | ------ |
| Base64 | ✅      | ✅      |
| Base32 | ✅      | ✅      |
| Base85 | ✅      | ✅      |
| Hex    | ✅      | ✅      |

---

## 🔍 Cryptanalysis

### Frequency Analysis

* Letter frequency histogram
* Index of Coincidence
* Language detection assistance

### Entropy Scanner

* Shannon Entropy
* Compression detection
* Archive detection
* Executable fingerprinting
* Base64 likelihood scoring

### Magic Byte Detection

Detects:

* ZIP
* RAR
* 7z
* GZIP
* ELF
* PE Executables
* PDF
* PNG
* JPEG
* GIF
* UPX Packed Files

---

## 🧾 Hashing Utilities

Supported Algorithms:

* MD5
* SHA1
* SHA256
* SHA512

Hash:

* Strings
* Files
* Bulk comparisons

---

## 📂 File Operations

### Text File Processing

* Encode files
* Decode files
* Stream processing
* Low memory usage

### Binary Mode

Supports:

* ZIP
* PDF
* Images
* Executables
* Arbitrary binary files

### Batch Processing

Process multiple files using glob patterns.

Example:

```bash
*.txt
*.log
*.cfg
```

---

## 🎨 Hacker Aesthetic UI

Features:

* Matrix Rain
* ANSI Colors
* Rainbow Progress Bars
* Animated Terminal Output
* Cyberpunk Banner
* Interactive Menu System

---

# ⚙️ Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/c3ser.git
cd c3ser
```

## Run

```bash
python3 c3ser.py
```

---

## Optional Dependencies

For AES, Fernet, ChaCha20 and advanced JWT support:

```bash
pip install cryptography
```

---

# 🖥️ Usage

## Encode Text

```bash
python3 c3ser.py encode "HELLO WORLD" -s 3
```

## Decode Text

```bash
python3 c3ser.py decode "KHOOR ZRUOG" -s 3
```

## Auto Crack

```bash
python3 c3ser.py crack "KHOOR ZRUOG"
```

## Hash Text

```bash
python3 c3ser.py hash "password123"
```

## Entropy Scan

```bash
python3 c3ser.py entropy file.zip
```

## Encrypt File

```bash
python3 c3ser.py file secret.txt -s 3 -m encode
```

---

# 📊 Why C3SER?

| Feature           | C3SER |
| ----------------- | ----- |
| Classical Ciphers | ✅     |
| Modern Encryption | ✅     |
| Entropy Analysis  | ✅     |
| JWT Support       | ✅     |
| Hashing           | ✅     |
| File Encryption   | ✅     |
| Batch Mode        | ✅     |
| Interactive UI    | ✅     |
| Single File Build | ✅     |

---

# 🛡️ Security Notice

```text
[ WARNING ]

This tool is intended for:

 • Educational purposes
 • Research
 • CTF challenges
 • Security training

Users are responsible for complying with
all applicable laws and regulations.

Unauthorized access, misuse, or malicious
activity is strictly discouraged.
```

---

# 📜 License

<p align="center">

[![License](https://img.shields.io/badge/LICENSE-Apache-ff0080?style=for-the-badge\&logo=opensourceinitiative\&logoColor=white)](LICENSE)

</p>

---

# ⭐ Support

If you find this project useful:

```text
⭐ Star the repository
🍴 Fork the project
🐛 Report issues
🚀 Contribute improvements
```

---

<p align="center">

```text
> ACCESS GRANTED
> C3SER v4.1 ONLINE
> READY FOR OPERATION
```

**Made with ☕, Python & Cyberpunk Energy**

</p>
