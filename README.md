# 🔐 CryptoApp

CryptoApp adalah aplikasi CLI berbasis Python yang mendukung berbagai algoritma kriptografi klasik dan modern. Proyek ini ditujukan untuk pembelajaran dan eksperimen dalam enkripsi dan dekripsi data menggunakan berbagai algoritma dan mode operasi.

## ✨ Fitur

- 🔒 Enkripsi dan dekripsi teks
- 🔄 Dukungan berbagai algoritma:
  - AES, Blowfish, DES, TripleDES, ARC4, CAST-128, ChaCha20
  - Extended ciphers: GOST 28147-89, Twofish, XTEA
- ⚙️ Mode operasi:
  - CBC, CFB, OFB, ECB, CTR, STREAM
- 🧩 Pilihan output encoding: Base64 dan Hex
- 🧪 Padding otomatis, IV randomisasi, dan key derivation via PBKDF2 (untuk future expansion)

## 📦 Requirements

- Python 3.7+
- pycryptodome

Install dependensi:

```bash
pip install -r requirements.txt
```
🚀 Cara Menjalankan
```bash
python3 CryptoApp.py
```
Kemudian kamu akan melihat menu CLI seperti:
```bash
=== CRYPTOGRAPHY TOOL ===
1. Encrypt
2. Decrypt
3. Exit
```
Ikuti petunjuk di layar untuk melakukan enkripsi/dekripsi.

📁 Struktur File
```
CryptoApp/
├── CryptoApp.py         # Antarmuka utama CLI
├── extended_ciphers.py  # Implementasi GOST, Twofish, XTEA
└── requirements.txt     # Dependensi Python
```
⚠️ Catatan

Algoritma seperti Serpent, RC2, LOKI97, dan lainnya belum diimplementasikan.

Twofish dan Rijndael-128 masih menggunakan placeholder AES sementara (bisa dikembangkan lebih lanjut).


🛡️ Legal

Proyek ini hanya untuk tujuan edukasi dan eksperimen pribadi. Jangan gunakan untuk tujuan ilegal atau menyimpan data sensitif tanpa audit keamanan yang tepat.


---

---
