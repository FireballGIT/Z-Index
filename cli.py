import argparse
import sys

import zindex


def main():
    parser = argparse.ArgumentParser(
        prog="zindex",
        description="Z-Index Vault Encryption Tool"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -------- LOCK --------
    lock_parser = subparsers.add_parser("lock", help="Lock a folder into a vault")
    lock_parser.add_argument(
        "path",
        help="Path to folder to lock"
    )
    lock_parser.add_argument(
        "password",
        help="Encryption password"
    )
    lock_parser.add_argument(
        "--out",
        dest="out",
        help="Custom output directory for the .vlt",
        default=None
    )
    lock_parser.add_argument(
        "--sharable",
        action="store_true",
        help="Enable sharable mode (uses default sharable vault path)"
    )
    lock_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )

    # -------- UNLOCK --------
    unlock_parser = subparsers.add_parser("unlock", help="Unlock a vault")
    unlock_parser.add_argument(
        "zindex",
        help="Path to .zindex file"
    )
    unlock_parser.add_argument(
        "password",
        help="Vault password"
    )
    unlock_parser.add_argument(
        "--keep-vault",
        action="store_true",
        help="Do not delete the vault after unlocking"
    )
    unlock_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )

    args = parser.parse_args()

    z = zindex(debug=getattr(args, "debug", False))

    try:
        if args.command == "lock":
            result = z.lock(
                folder_path=args.path,
                password=args.password,
                out=args.out,
                sharable_mode=args.sharable
            )
            print(f"Vault created: {result}")

        elif args.command == "unlock":
            result = z.unlock(
                zindex_path=args.zindex,
                password=args.password,
                keep_vault=args.keep_vault
            )
            print(f"Folder restored: {result}")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()