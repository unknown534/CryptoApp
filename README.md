# 🔐 CryptoApp

CryptoApp adalah tool enkripsi dan dekripsi berbasis terminal yang mendukung berbagai algoritma kriptografi simetris, baik standar maupun custom. Proyek ini cocok untuk eksperimen dan pembelajaran algoritma cipher blok dan stream secara langsung lewat CLI.

---

## 🔧 Algoritma yang Didukung

### Cipher Inti (via PyCryptodome)
- Simetris: AES, Blowfish, DES, TripleDES, CAST-128, ChaCha20
- Stream: ARC4

### Cipher Tambahan (implementasi manual)
- GOST 28147-89 — Cipher blok Soviet berbasis Feistel
- XTEA — Cipher ringan, 64-round
- Twofish — Finalis AES (placeholder)

---

## ⚙️ Fitur

- Mode operasi: CBC, CFB, OFB, ECB, CTR, STREAM
- Output encoding: Base64 dan Hex
- Padding otomatis, IV random sesuai algoritma
- Struktur modular, mudah dikembangkan
- Dukungan PBKDF2 untuk derivasi kunci (bisa diaktifkan)

---

## 📦 Instalasi

### Syarat:
- Python 3.7+
- PyCryptodome 3.15+
- (Opsional): serpent, rc2

```bash
pip3 install -r requirements.txt
```
# atau manual
```
pip3 install pycryptodome serpent rc2

```
---

# 🚀 Menjalankan Aplikasi
```
python3 CryptoApp.py

=== CRYPTOGRAPHY TOOL ===
1. Encrypt
2. Decrypt
3. Exit
```
Contoh Alur Penggunaan:

1. Pilih: Enkripsi atau Dekripsi


2. Pilih algoritma (dari 10+ yang tersedia)


3. Pilih mode operasi (CBC/OFB/etc.)


4. Masukkan plaintext & kunci, atau ciphertext untuk dekripsi


5. Hasil tampil lengkap: Algoritma, IV, hasil enkripsi/dekripsi




---

##🗂️ Struktur Proyek
```
CryptoApp/
├── CryptoApp.py          # CLI utama
├── extended_ciphers.py   # Cipher ekstensi:
│   ├── GOST              # Implementasi lengkap
│   ├── XTEA              # Cipher blok ringan
│   └── Twofish           # Placeholder
└── requirements.txt

```
---

##⚠️ Catatan

Status Implementasi:

✅ Berfungsi penuh: AES, GOST, XTEA, ChaCha20, ARC4

🧪 Placeholder: Twofish (pakai AES untuk dummy)

##🚧 Belum ada:

Serpent, RC2 (bisa ditambahkan via pip)

Cipher historis: LOKI97, Enigma, SAFER+



##🛡️Keamanan:

> Aplikasi ini tidak disarankan untuk sistem produksi atau perlindungan data nyata.
Dirancang hanya untuk pembelajaran dan pengujian algoritma dalam lingkungan aman.




---

📄 Lisensi

Hanya untuk penggunaan edukatif. Tidak ada jaminan keamanan.

---
