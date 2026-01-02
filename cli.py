import sys
from zindex import Vault
from pathlib import Path
from getpass import getpass

# ================= CONFIG =================
VERSION = "1.1.0-beta.4"
REPO_LINK = "https://github.com/YourUsername/Z-Index"
CHANGELOGS = {
    "1.0.0": "- Initial beta release.\n- Basic lock/unlock functionality.",
    "1.1.0-beta.1": "- Added .vlt custom icon support.\n- Added .zb blobs.",
    "1.1.0-beta.4": "- Multi-vault support with UUIDs.\n- Debug improvements.",
}

vault = Vault()

# ================= HELP =================
def print_help():
    print("""
Z-Index CLI 🔒

Commands:
  lock <folder>          Encrypt a folder into a .vlt vault
  unlock <.zindex>       Decrypt a .vlt vault and restore the folder
  help                   Show this help text
  --version              Show current version
  repo                   Show the GitHub repository link
  logs                   Show changelog for your version
  logs --version <ver>   Show changelog for a specific version
  comp --prev            Compare your version to previous changelog
  comp <version>         Compare your version to selected version
  comp --ptl             Compare latest vs previous version
""")

# ================= LOGS =================
def show_changelog(version: str):
    log = CHANGELOGS.get(version)
    if log:
        print(f"Changelog for version {version}:\n{log}")
    else:
        print(f"No changelog found for version {version}")

def compare_changelogs(v1: str, v2: str):
    log1 = CHANGELOGS.get(v1, "")
    log2 = CHANGELOGS.get(v2, "")
    print(f"Comparing {v1} → {v2}:\n")
    print("---- Old Version ----")
    print(log1)
    print("\n---- New Version ----")
    print(log2)

# ================= MAIN CLI =================
def main():
    args = sys.argv[1:]

    if not args or args[0].lower() == "help":
        print_help()
        return

    cmd = args[0].lower()

    try:
        if cmd == "lock" and len(args) > 1:
            folder = args[1]
            password = getpass("Enter password for vault: ")
            vault.lock(folder, password)
            print(f"[Z-Index] Locked folder: {folder}")
        
        elif cmd == "unlock" and len(args) > 1:
            zindex_file = args[1]
            vault.unlock(zindex_file)
        
        elif cmd == "--version":
            print(f"Z-Index version: {VERSION}")
        
        elif cmd == "repo":
            print(f"GitHub repo: {REPO_LINK}")
        
        elif cmd == "logs":
            if len(args) == 3 and args[1] == "--version":
                show_changelog(args[2])
            else:
                show_changelog(VERSION)
        
        elif cmd == "comp":
            if len(args) == 2 and args[1] == "--prev":
                versions = list(CHANGELOGS.keys())
                idx = versions.index(VERSION) if VERSION in versions else -1
                if idx > 0:
                    compare_changelogs(versions[idx - 1], VERSION)
                else:
                    print("[Z-Index] No previous version to compare.")
            elif len(args) == 2 and args[1] == "--ptl":
                versions = list(CHANGELOGS.keys())
                if len(versions) >= 2:
                    compare_changelogs(versions[-2], versions[-1])
                else:
                    print("[Z-Index] Not enough versions to compare.")
            elif len(args) == 2:
                compare_changelogs(VERSION, args[1])
            else:
                print("[ERROR] Invalid comp command")
        
        else:
            print(f"[ERROR] Unknown command: {cmd}")
            print_help()

    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
