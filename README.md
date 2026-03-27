# Secure CLI Password Manager

Sebuah aplikasi pengelola kata sandi berbasis antarmuka baris perintah (*Command Line Interface / CLI*) yang dirancang khusus menggunakan standar kriptografi modern. Proyek ini sangat berfokus pada ketahanan terhadap upaya pembongkaran paksa secara *offline* (*Offline Brute-Force Attacks*) dan perlindungan privasi jangka pendek (seperti *clipboard snooping*).

---

## Fitur Utama

- **Kriptografi Mutakhir (Argon2id + AES-GCM 256-bit)**  
  Menggunakan Argon2id (Pemenang kompetisi *Password Hashing Competition*) untuk mengelola Master Password, lalu menggunakan AES-GCM untuk memastikan seluruh isi data terenkripsi seutuhnya sekaligus bebas dari segala manipulasi (*Authenticated Encryption*).
- **Anti-Brute Force (High Cost Parameter)**  
  Tingkat konsumsi Argon2id ditingkatkan (Cost RAM ~256 MB) demi memberikan jeda komputasi sebesar ~500ms di CPU/GPU modern pada setiap satu kali percobaan tebak password, membuat serangan *brute force offline* skala besar secara finansial merugikan.
- **Ringan & Bebas State (Operasi CRUD Lengkap)**  
  Aplikasi dirancang esensial murni mendukung penambahan (*add*), perputaran sandi (*update*), pembacaan (*get*), dan penghapusan (*delete*) tanpa menambahkan atau menyisakan *lock file* riwayat login. Format penyimpanan 100% bergantung pada kekuatan kriptografi algoritmanya semata ketimbang mengotori I/O _disk_ Anda.
- **Auto-Clear Clipboard (Anti-Snooping)**  
  Seluruh password yang disalin menggunakan perintah `get` atau `generate` hanya akan bertahan di memori/clipboard Anda selama 12 detik. Aplikasi secara otomatis menghapusnya sesudah waktu hitung mundur selesai.
- **Kunci Akses File Level Sistem Lokal**  
  Otomatis menerapkan hak akses super ketat `(chmod 600)` pada file database lokal Anda agar tidak dapat dibuka pakai program lain secara asal.

---

## Instalasi

Aplikasi ini bersifat **Lintas-Platform (Cross-Platform)** dan dijamin dapat berjalan mulus di **Windows**, **macOS** (arsitektur Intel maupun lini Apple Silicon M-series), dan berbagai distribusi **Linux**.

Pastikan Anda memiliki instalasi Python 3. Karena aplikasi mengakses antarmuka kriptografi tingkat rendah, ikuti panduan instalasi berikut:

1. _(Opsional namun direkomendasikan)_ Buat *Virtual Environment*:
   ```bash
   python3 -m venv venv
   
   # -> Aktivasi di macOS & Linux:
   source venv/bin/activate
   
   # -> Aktivasi di Windows (CMD/PowerShell):
   venv\Scripts\activate
   ```

2. Instal pustaka kriptografi beserta `pyperclip`:
   ```bash
   pip install -r requirements.txt
   ```

> **Catatan Khusus Pengguna Linux**: Jika Anda mengalami error terkait modul _Clipboard_, silakan instal utilitas sistem untuk _copy-paste_ terlebih dahulu via manajer paket bawaan Anda (karena Linux tidak membawa modul clipboard default yang selaras). Gunakan `sudo apt install xclip` atau `xsel` (untuk Ubuntu/Debian dengan display X11) atau `sudo apt install wl-clipboard` (untuk sesi display Wayland). Pengguna Windows dan macOS tidak perlu mengatur apa pun.

---

## Panduan Penggunaan (Commands)

Akses skrip via terminal Anda menggunakan `python passman.py <command> [opsi]`.

### 1. Inisialisasi Database Pertama Kali
```bash
python passman.py init
```
*Membuat file lokal `vault.enc` yang berisi kunci unik (Salt & Nonce) dan menentukan Master Password Anda.*

### 2. Menyimpan Password Baru ke Vault
```bash
python passman.py add <label_aplikasi> <username> [-n "catatan tambahan"]
# Contoh 1: Menambahkan kredensial biasa
python passman.py add github octocat@gmail.com
# Contoh 2: Menambahkan kredensial beserta catatan pemulihan/recovery code
python passman.py add github octocat@gmail.com -n "Recovery: 1234-ABCD"
```
*Program akan meminta Master Password Anda, lalu menyuruh Anda memasukkan password baru untuk Github. Tekan/Kosongkan ENTER pada form password jika ingin alat ini yang otomatis memikirkannya (Auto-Generate).*

### 3. Memperbarui Password (Update / Siklus Rotasi)
```bash
python passman.py update github [-n "catatan baru"]
```
*Mengganti kata sandi atau catatan untuk kredensial web/label yang sebelumnya sudah tersimpan di dalam database Anda. Anda bisa mengosongkan kata sandi pada *prompt* jika hanya ingin mengubah Catatan/Notes saja.*

### 4. Menghapus Akun Permanen (Delete)
```bash
python passman.py delete github
```
*Mencabut dan menghapus seutuhnya data kredensial usang Anda secara permanen dari dalam struktural terenkripsi vault database.*

### 5. Mengambil / Membaca Password
```bash
python passman.py get github
```
*Bila Master Password benar, ia akan secara mandiri memasukkan password Github milik Anda langsung ke clipboard/fitur "Copy" sistem Anda.*

### 6. Melihat Daftar Akun
```bash
python passman.py list
```
*Akan mencetak semua nama website / label email Anda dari vault tanpa mengekspos kata sandi aslinya sama sekali.*

### 7. Membuat Sandi Acak (Tanpa Simpan)
```bash
python passman.py generate -l 24
```
*Mencetak string acak 24-karakter dengan komposisi kompleks dan sangat kuat serta otomatis menyalinkannya ke clipboard.*

---

## Mengapa Sistem Ini Aman? (Technical Details)

Jika seorang penyerang berhasil mencuri `vault.enc` Anda, mereka akan menyadari kerumitan berikut:
1. File tersebut sama sekali **tidak memiliki identitas Plaintext**; struktur murni file biner yang terbagi atas `Salt(16) | Nonce(12) | AES Ciphetext(...)`.
2. Setiap Vault dibuat spesifik melalui Argon2id. Penyerang membutuhkan algoritma super-berat yang dirancang memakan RAM hanya untuk menebak 1 kata sandi per komputasi, yang menghilangkan fungsionalitas memecahkan sistem menggunakan ASIC / GPU massal layaknya SHA-256. 
3. *Error Handling* diciptakan sebosam mungkin (*Generic Exception*). Menyarankan kode otentikasi tag MAC (AES-GCM) yang gagal tanpa membongkar karakter Master Password mana yang salah.
4. *Cryptography Nonce* selalu digenerate ulang setiap kali save, ini mengamankan sandi yang sama dipakai dari serangan kriptanalisis Replay Attacks.
