# Z-Index 🔒

**Modern, secure folder encryption made simple.**

Z‑Index locks any folder into a ```.vlt``` vault containing a single encrypted ```.zb``` blob. The ```.zb``` file is completely unreadable outside Z‑Index.

---

## CLI Commands ⚡

Z‑Index comes with three commands:

```zindex lock <folder>``` — Encrypts a folder into a .vlt vault

```zindex unlock <vault>``` — Decrypts a .vlt vault and restores the folder

```zindex help``` — Shows help text

---

## How it Works 🧠

Run ``` zindex lock "C:\Path\To\Folder" ```

Z‑Index creates a .vlt folder:


```
myvault.vlt/
 └─ vault.zb       <- encrypted blob
 └─ desktop.ini    <- optional icon (Windows only)
```


The original folder is deleted.

To restore, run ``` zindex unlock "C:\Path\To\myvault.vlt"```  and provide your password.

- ```.vlt```: folder container
- ```.zb```: encrypted blob, unreadable outside Z-Index

---

## Examples 💻

Lock a folder:

```bash
C:\> zindex lock "C:\Path\To\Folder"
Vault created: C:\Path\To\vaults\XXXXXX.vlt
Enter password: ****
```

Unlock a vault:

```bash
C:\> zindex unlock "C:\Path\To\vaults\XXXXXX.vlt"
Enter password: ****
Folder restored to: C:\Path\To\RestoredFolder
```

Help command:

```bash
C:\> zindex help

Commands:
  lock <folder>    Encrypt folder into a .vlt vault
  unlock <vault>   Decrypt a .vlt vault to restore folder
  help             Show this help text
```

---

## Notes 🔐

```.zb``` blobs are AES-256 encrypted.

```.vlt``` folders are only containers; all security is in the ```.zb```.

Without Z‑Index, the blob cannot be opened.

.vlt folders can optionally have a custom icon for Windows Explorer.

---

## Why Z-Index? 💎

- Stronger than password-protected ZIPs

- Clean, single-file encryption

- Optional visual polish (icons)

- Works for beginners and pros alike

---

### File Structure 📂
Vault Example:
```
XXXXXX.vlt/
 └─ vault.zb       <- encrypted blob
 └─ desktop.ini    <- optional icon
```

---

## License 📜

Created by BAG Studios

Open source under Apache 2.0 License
