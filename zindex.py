import os
import uuid
import json
from pathlib import Path
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import shutil
from datetime import datetime

# ================= CONFIG =================
APPDATA_VAULTS = Path(os.getenv("LOCALAPPDATA")) / "zindex" / "vaults"
SHARABLE_VAULTS = Path
APPDATA_VAULTS.mkdir(parents=True, exist_ok=True)

# ================= UTILITIES =================
def hash_password(password: str, salt: bytes) -> bytes:
    """Hash password with PBKDF2 + SHA256"""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)

def aes_encrypt_folder(folder: Path, blob_file: Path, key: bytes):
    """Encrypt all files in folder into a single .zb blob"""
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    with open(blob_file, "wb") as f:
        for item in folder.iterdir():
            if item.is_file():
                data = item.read_bytes()
                ciphertext, tag = cipher.encrypt_and_digest(data)
                # write file name + ciphertext + tag
                name_bytes = item.name.encode('utf-8')
                f.write(len(name_bytes).to_bytes(2, 'big'))
                f.write(name_bytes)
                f.write(len(ciphertext).to_bytes(8, 'big'))
                f.write(ciphertext)
                f.write(tag)

def aes_decrypt_blob(blob_file: Path, key: bytes, restore_path: Path):
    """Decrypt a .zb blob back to folder"""
    cipher = AES.new(key, AES.MODE_EAX)
    restore_path.mkdir(parents=True, exist_ok=True)

    with open(blob_file, "rb") as f:
        while f.tell() < os.fstat(f.fileno()).st_size:
            name_len = int.from_bytes(f.read(2), "big")
            name = f.read(name_len).decode('utf-8')
            data_len = int.from_bytes(f.read(8), "big")
            ciphertext = f.read(data_len)
            tag = f.read(16)
            try:
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            except Exception:
                print(f"[WARN] Could not decrypt file {name}, skipping")
                continue
            with open(restore_path / name, "wb") as out:
                out.write(plaintext)

def sharable(folder_path: Path, vault_id: str, vault_folder: Path, mode: bool):
    SHARABLE_VAULTS = Path.home() / "zindex" / "vaults"
    SHARABLE_VAULTS.mkdir(parents=True, exist_ok=True)

    if mode and not vault_folder.exists():
        vault_folder = SHARABLE_VAULTS / f"{vault_id}.vlt"
        vault_folder.mkdir(parents=True, exist_ok=True)

    zbdata_path = vault_folder / f"{vault_id}.zbdata"
    zbdata = {
        "vault_id": vault_id,
        "timestamp": datetime.now().strftime("%m-%D-%Y %M:%H"),
        "inpath": str(folder_path),
        "sharable": 1 if mode else 0
    }
    with open(zbdata_path, "w") as f:
        json.dump(zbdata, f, indent=2)

    return vault_folder

# ================= VAULT CLASS =================
class Vault:
    def __init__(self, debug=False):
        self.debug = debug

    # -------- LOCK FOLDER --------
    def lock(self, folder_path: str, password: str, out: str = None, sharable_mode: bool = False) -> str:
        folder_path = Path(folder_path)

        if not folder_path.exists() or not folder_path.is_dir():
            raise FileNotFoundError(f"Folder not found: {folder_path}")

        vault_id = uuid.uuid4().hex

        # Decide where the vault will live
        if out:
            vault_root = Path(out)
        elif sharable_mode:
            vault_root = Path.home() / "zindex" / "vaults"
        else:
            vault_root = APPDATA_VAULTS

        vault_root.mkdir(parents=True, exist_ok=True)

        # Create .vlt folder
        vault_folder = vault_root / f"{vault_id}.vlt"
        vault_folder.mkdir(parents=True, exist_ok=True)

        # Encrypt folder contents into .zb blob
        blob_file = vault_folder / "vault.zb"
        key_bytes = password.encode("utf-8").ljust(32, b"\0")
        aes_encrypt_folder(folder_path, blob_file, key_bytes)

        # Password hashing + salt
        salt = get_random_bytes(16)
        hashed_pw = hash_password(password, salt)

        # Create .zindex file at original folder location
        zindex_path = folder_path.parent / f"{folder_path.name}.zindex"
        zindex_data = {
            "folder": str(folder_path),
            "vault_id": vault_id,
            "password": hashed_pw.hex(),
            "salt": salt.hex(),
            "sharable": sharable_mode
        }

        with open(zindex_path, "w") as f:
            json.dump(zindex_data, f)

        # Remove original folder (data now inside vault.zb)
        shutil.rmtree(folder_path)

        # ⭐ Create sharable metadata if enabled
        if sharable_mode:
            self.sharable(folder_path, vault_id, vault_folder)

        # Add custom folder icon
        desktop_ini = vault_folder / "desktop.ini"
        icon_path = Path(r"C:\Users\gafut\Downloads\Untitled Design (6).ico")

        with open(desktop_ini, "w") as f:
            f.write("[.ShellClassInfo]\n")
            f.write(f"IconResource={icon_path},0\n")

        os.system(f'attrib +s +h "{vault_folder}"')
        os.system(f'attrib +s +h "{desktop_ini}"')

        if self.debug:
            print(f"[DEBUG] Vault: {vault_folder}")
            print(f"[DEBUG] .zindex: {zindex_path}")
            print(f"[DEBUG] Sharable Mode: {sharable_mode}")

        return str(vault_folder)


    # -------- UNLOCK FOLDER --------
    def unlock(self, zindex_file: str):
        zindex_path = Path(zindex_file)
        if not zindex_path.exists() or zindex_path.suffix != ".zindex":
            raise FileNotFoundError(f".zindex file not found: {zindex_path}")

        # Read vault info
        with open(zindex_path, "r") as f:
            data = json.load(f)

        vault_folder = APPDATA_VAULTS / f"{data['vault_id']}.vlt"
        original_folder = Path(data["folder"])
        blob_file = vault_folder / "vault.zb"

        if not blob_file.exists():
            raise FileNotFoundError(f"Vault blob not found: {blob_file}")

        # Prompt for password
        pw_input = getpass("Enter password: ")
        hashed_input = hash_password(pw_input, bytes.fromhex(data["salt"]))

        if hashed_input.hex() != data["password"]:
            print("[Z-Index] Wrong password!")
            return

        # Decrypt .zb back to folder
        aes_decrypt_blob(blob_file, pw_input.encode('utf-8').ljust(32, b'\0'), original_folder)

        print(f"[Z-Index] Folder restored to {original_folder}")

