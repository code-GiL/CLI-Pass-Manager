#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import getpass
import secrets
import string
import argparse

try:
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Pustaka keamanan (cryptography, argon2-cffi) belum terinstal.")
    print("Jalankan: pip install -r requirements.txt")
    sys.exit(1)

try:
    import pyperclip
    HAS_PYCLIP = True
except ImportError:
    HAS_PYCLIP = False

DB_FILE = "vault.enc"

class PasswordManager:
    def __init__(self, db_path=DB_FILE):
        self.db_path = db_path

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """KDF Argon2id dengan parameter berbiaya tinggi untuk pertahanan optimal."""
        key = hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=3,          # Jumlah iterasi CPU
            memory_cost=262144,   # ~256 MB kebutuhan RAM per operasi
            parallelism=4,        # Jumlah thread CPU minimum yang digunakan
            hash_len=32,          # Sesuai target algoritma AES-256
            type=Type.ID
        )
        return key

    def init_db(self):
        if os.path.exists(self.db_path):
            print("Database sudah ada! Operasi dibatalkan.")
            return

        mp1 = getpass.getpass("Buat Master Password baru: ")
        mp2 = getpass.getpass("Konfirmasi Master Password: ")

        if mp1 != mp2:
            print("Error: Password tidak cocok!")
            del mp1, mp2
            sys.exit(1)

        print("Membuat database terenkripsi (sedang melakukan derivasi kunci keamanan tinggi)...")
        
        salt = os.urandom(16)
        key = self._derive_key(mp1, salt)
        del mp1, mp2

        # Data JSON kosong
        db_data = json.dumps({}).encode('utf-8')

        # Enkripsi AEAD dengan AES-GCM
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, db_data, None)

        # Usahakan clear variabel memori secepatnya
        del key

        # Simpan layout binary: SALT(16 bytes) | NONCE(12 bytes) | CIPHERTEXT
        with open(self.db_path, "wb") as f:
            f.write(salt + nonce + ciphertext)

        # [Proteksi] Kunci hak akses (chmod 600) khusus di keluarga Unix (macOS/Linux)
        if os.name == 'posix':
            try:
                os.chmod(self.db_path, 0o600)
            except Exception:
                pass

        print(f"Database ({self.db_path}) berhasil diinisialisasi dengan akses ketat (600).")

    def _load_db(self, master_password: str) -> dict:
        """Melakukan dekripsi isi file, disertai verifikasi integritas."""

        with open(self.db_path, "rb") as f:
            content = f.read()

        salt = content[:16]
        nonce = content[16:28]
        ciphertext = content[28:]

        key = self._derive_key(master_password, salt)
        aesgcm = AESGCM(key)

        try:
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            db = json.loads(decrypted_data.decode('utf-8'))
            
            # Pembersihan memori eksplist
            del key
            del decrypted_data
            
            return db
        except (InvalidTag, ValueError):
            del key
            # Pesan kesalahan generik agar tak ada oracle attack leakage
            print("Peringatan: Gagal membuka database! Pastikan Master Password benar dan file tidak rusak.")
            sys.exit(1)

    def _save_db(self, db: dict, master_password: str):
        """Menyimpan pembaruan database Vault dengan nonce enkripsi yang baru."""
        with open(self.db_path, "rb") as f:
            salt = f.read(16) # Memakai salt yang sama

        key = self._derive_key(master_password, salt)
        data = json.dumps(db).encode('utf-8')

        aesgcm = AESGCM(key)
        nonce = os.urandom(12) # Generate nonce kriptografis baru TIAP penyimpan ke file
        ciphertext = aesgcm.encrypt(nonce, data, None)

        with open(self.db_path, "wb") as f:
            f.write(salt + nonce + ciphertext)
            
        # [Proteksi] Kunci hak akses (chmod 600) khusus di keluarga Unix (macOS/Linux)
        if os.name == 'posix':
            try:
                os.chmod(self.db_path, 0o600)
            except Exception:
                pass
            
        del key, data

    def add_entry(self, master_password: str, label: str, username: str, password: str, notes: str = ""):
        db = self._load_db(master_password)
        
        new_data = {
            "username": username,
            "password": password,
            "notes": notes
        }

        if label in db:
            existing = db[label]
            if isinstance(existing, list):
                for item in existing:
                    if item["username"] == username:
                        print(f"Data untuk label '{label}' dengan username '{username}' sudah ada! Gunakan fungsionalitas 'update'.")
                        del db
                        sys.exit(1)
                existing.append(new_data)
                db[label] = existing
            else:
                if existing["username"] == username:
                    print(f"Data untuk label '{label}' dengan username '{username}' sudah ada! Gunakan fungsionalitas 'update'.")
                    del db
                    sys.exit(1)
                db[label] = [existing, new_data]
        else:
            db[label] = new_data
        
        print(f"Menyimpan ke {self.db_path}...")
        self._save_db(db, master_password)
        print(f"Akun [{label}] berhasil ditambahkan.")
        
        del db, password

    def update_entry(self, master_password: str, label: str, username: str = None, password: str = None, notes: str = None):
        db = self._load_db(master_password)
        if label not in db:
            print(f"Label '{label}' tidak ditemukan! Gunakan perintah 'add' untuk membuat akun baru.")
            del db
            sys.exit(1)

        entry = db[label]
        target = None
        is_list = isinstance(entry, list)

        if is_list:
            if username is None:
                usernames = [e['username'] for e in entry]
                print(f"Terdapat beberapa akun untuk label '{label}'.")
                print(f"Usernames: {', '.join(usernames)}")
                print(f"Harap spesifikasikan username, contoh: python passman.py update {label} <username> [opsi]")
                del db
                sys.exit(1)
            else:
                for e in entry:
                    if e["username"] == username:
                        target = e
                        break
                if not target:
                    print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                    del db
                    sys.exit(1)
        else:
            if username is not None and entry["username"] != username:
                print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                del db
                sys.exit(1)
            target = entry

        updated = False
        if password:
            target["password"] = password
            updated = True
        if notes is not None:
            target["notes"] = notes
            updated = True
            
        if not updated:
            print("Tidak ada data yang diperbarui.")
            del db
            return
            
        print(f"Memperbarui data untuk {label}...")
        self._save_db(db, master_password)
        print(f"Password [{label}] berhasil diperbarui.")
        
        del db, password

    def delete_entry(self, master_password: str, label: str, username: str = None):
        db = self._load_db(master_password)
        if label not in db:
            print(f"Label '{label}' tidak ditemukan!")
            del db
            sys.exit(1)

        entry = db[label]
        is_list = isinstance(entry, list)

        if is_list:
            if username is None:
                usernames = [e['username'] for e in entry]
                print(f"Terdapat beberapa akun untuk label '{label}'.")
                print(f"Usernames: {', '.join(usernames)}")
                print(f"Harap spesifikasikan username, contoh: python passman.py delete {label} <username>")
                del db
                sys.exit(1)
            else:
                new_entry = [e for e in entry if e["username"] != username]
                if len(new_entry) == len(entry):
                    print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                    del db
                    sys.exit(1)
                
                if len(new_entry) == 1:
                    db[label] = new_entry[0]
                elif len(new_entry) == 0:
                    del db[label]
                else:
                    db[label] = new_entry
        else:
            if username is not None and entry["username"] != username:
                print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                del db
                sys.exit(1)
            del db[label]
        
        print(f"Mencabut dan menghapus data [{label}] dari {self.db_path}...")
        self._save_db(db, master_password)
        print(f"Akun [{label}] telah berhasil dihapus secara permanen.")
        
        del db

    def get_entry(self, master_password: str, label: str, username: str = None):
        db = self._load_db(master_password)
        
        if label not in db:
            print(f"Label '{label}' tidak ditemukan!")
            del db
            sys.exit(1)
            
        entry = db[label]
        target = None
        is_list = isinstance(entry, list)

        if is_list:
            if username is None:
                usernames = [e['username'] for e in entry]
                print(f"Terdapat beberapa akun untuk label '{label}'.")
                print(f"Usernames: {', '.join(usernames)}")
                print(f"Harap spesifikasikan username, contoh: python passman.py get {label} <username>")
                del db
                sys.exit(1)
            else:
                for e in entry:
                    if e["username"] == username:
                        target = e
                        break
                if not target:
                    print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                    del db
                    sys.exit(1)
        else:
            if username is not None and entry["username"] != username:
                print(f"Username '{username}' tidak ditemukan pada label '{label}'!")
                del db
                sys.exit(1)
            target = entry

        pwd = target["password"]
        print(f"Username: {target['username']}")
        if "notes" in target and target["notes"]:
            print(f"Notes   : {target['notes']}")
        
        if HAS_PYCLIP:
            pyperclip.copy(pwd)
            print("Password telah disalin ke clipboard!")
            print("[Proteksi Tambahan] Clipboard akan terhapus otomatis dalam 12 detik mencegah kebocoran...")
            try:
                for i in range(12, 0, -1):
                    sys.stdout.write(f"\rMenghapus clipboard dalam {i} detik... ")
                    sys.stdout.flush()
                    time.sleep(1)
                pyperclip.copy("")
                sys.stdout.write("\r[Aman] Clipboard telah dibersihkan!              \n")
            except KeyboardInterrupt:
                pyperclip.copy("")
                print("\n[Aman] Clipboard dibersihkan.")
        else:
            print(f"Password: {pwd}")
            
        del pwd, db

    def list_entries(self, master_password: str):
        db = self._load_db(master_password)
        if not db:
            print("Vault database Anda masih kosong.")
            del db
            return
            
        print("\nDaftar Akun Tersimpan:")
        for label, data in db.items():
            if isinstance(data, list):
                for item in data:
                    print(f"- {label} ({item['username']})")
            else:
                print(f"- {label} ({data['username']})")
            
        del db

    @staticmethod
    def generate_password(length=16) -> str:
        """Membuat password kuat dengan kriteria kompleksitas yang ketat."""
        if length < 16:
            print("Peringatan: Password modern direkomendasikan memiliki panjang minimal 16 karakter.")
            
        chars = string.ascii_letters + string.digits + string.punctuation
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and sum(1 for c in pwd if c in string.punctuation) >= 2):
                return pwd

def main():
    parser = argparse.ArgumentParser(description="Secure CLI Password Manager (Argon2id + AES-GCM)")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Inisialisasi vault tersandi baru")

    cmd_add = subparsers.add_parser("add", help="Tambah record password (akun baru)")
    cmd_add.add_argument("label", help="Nama web/layanan (contoh: github)")
    cmd_add.add_argument("username", help="Username/email terkait identifier akun")
    cmd_add.add_argument("-n", "--notes", default="", help="Catatan tambahan (opsional)")

    cmd_update = subparsers.add_parser("update", help="Perbarui password pada akun yang telah ada")
    cmd_update.add_argument("label", help="Label aplikasi yang ingin diperbarui sandinya")
    cmd_update.add_argument("username", nargs="?", default=None, help="Username (diperlukan jika label memiliki >1 akun)")
    cmd_update.add_argument("-n", "--notes", default=None, help="Perbarui catatan (opsional)")

    cmd_del = subparsers.add_parser("delete", help="Hapus akun permanen dari vault")
    cmd_del.add_argument("label", help="Label aplikasi yang ingin dihapus")
    cmd_del.add_argument("username", nargs="?", default=None, help="Username (diperlukan jika label memiliki >1 akun)")

    cmd_get = subparsers.add_parser("get", help="Ambil password tersimpan")
    cmd_get.add_argument("label", help="Label aplikasi yang ingin diambil")
    cmd_get.add_argument("username", nargs="?", default=None, help="Username (diperlukan jika label memiliki >1 akun)")

    subparsers.add_parser("list", help="Lihat semua akun tersimpan")

    cmd_gen = subparsers.add_parser("generate", help="Buat random string password super kuat")
    cmd_gen.add_argument("-l", "--length", type=int, default=16, help="Panjang karakter (default: 16)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    pm = PasswordManager()

    if args.command == "init":
        pm.init_db()
        sys.exit(0)
        
    if args.command == "generate":
        pwd = pm.generate_password(args.length)
        print(f"Generated Password: {pwd}")
        if HAS_PYCLIP:
            pyperclip.copy(pwd)
            print("[INFO] Password sudah tercopy ke ekosistem Clipboard.")
            try:
                for i in range(12, 0, -1):
                    sys.stdout.write(f"\rMenghapus clipboard dalam {i} detik... ")
                    sys.stdout.flush()
                    time.sleep(1)
                pyperclip.copy("")
                sys.stdout.write("\r[Aman] Clipboard telah dibersihkan!              \n")
            except KeyboardInterrupt:
                pyperclip.copy("")
                print("\n[Aman] Clipboard dibersihkan.")
        del pwd
        sys.exit(0)

    if not os.path.exists(DB_FILE):
        print("Error: Database vaults tidak ditemukan. Silakan jalankan 'init' terlebih dulu.")
        sys.exit(1)

    mp = getpass.getpass("Masukkan Master Password: ")

    try:
        if args.command == "add":
            pwd = getpass.getpass(f"Masukkan password untuk {args.label} (Kosongkan lalu ENTER untuk random generator): ")
            if not pwd:
                pwd = pm.generate_password()
                print("Password acak generator telah digunakan.")
            pm.add_entry(mp, args.label, args.username, pwd, args.notes)
            del pwd

        elif args.command == "update":
            pwd = getpass.getpass(f"Masukkan password BARU untuk {args.label} (Kosongkan untuk abaikan sandi, isi '-' untuk generate): ")
            if pwd == "-":
                pwd = pm.generate_password()
                print("Password acak generator telah digunakan.")
            elif not pwd:
                pwd = None
            pm.update_entry(mp, args.label, args.username, pwd, args.notes)
            if pwd:
                del pwd
            
        elif args.command == "delete":
            pm.delete_entry(mp, args.label, args.username)
            
        elif args.command == "get":
            pm.get_entry(mp, args.label, args.username)
            
        elif args.command == "list":
            pm.list_entries(mp)
            
    finally:
        del mp
        
if __name__ == "__main__":
    main()
