#!/usr/bin/env python3
"""
Password Generator v3.0 — Ultimate Edition
A local, menu-driven password generator for Python / Pydroid 3.

Uses only the Python standard library. Passwords are generated with
the cryptographically secure `secrets` module.
"""

from __future__ import annotations

import secrets
import string
import sys
from datetime import datetime
from pathlib import Path

APP_NAME = "Password Generator"
VERSION = "3.0.0"
MAX_LENGTH = 4096
MAX_BATCH = 100
REPORT_DIR = Path("password_generator_exports")

# Characters that are easy to confuse in some fonts.
AMBIGUOUS = set("0O1lI|")

SETS = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{};:,.?/\\~",
}


class UI:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    DIM = "\033[2m"

    @staticmethod
    def paint(text: str, color: str) -> str:
        # ANSI colors are supported in many terminals, but plain text is okay too.
        if not sys.stdout.isatty():
            return text
        return f"{color}{text}{UI.RESET}"


def banner() -> None:
    print(UI.paint("=" * 52, UI.CYAN))
    print(UI.paint("       PASSWORD GENERATOR v3.0.0", UI.BOLD + UI.CYAN))
    print(UI.paint("       Ultimate Edition • Local & Secure", UI.DIM))
    print(UI.paint("=" * 52, UI.CYAN))
    print("  Uses Python's secrets module for randomness.")
    print("  Generated passwords are not sent over the network.")
    print()


def ask_int(prompt: str, minimum: int, maximum: int) -> int:
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print(UI.paint(f"Enter a whole number from {minimum} to {maximum}.", UI.YELLOW))
            continue
        if minimum <= value <= maximum:
            return value
        print(UI.paint(f"Choose a number from {minimum} to {maximum}.", UI.YELLOW))


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{prompt} ({hint}): ").strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer y or n.")


def choose_character_sets() -> tuple[str, list[str]]:
    selected: list[str] = []
    labels = [
        ("1", "uppercase", "Uppercase letters (A-Z)"),
        ("2", "lowercase", "Lowercase letters (a-z)"),
        ("3", "digits", "Numbers (0-9)"),
        ("4", "symbols", "Symbols (!@#$...)"),
    ]
    print("\nChoose character types:")
    for number, key, label in labels:
        default = True
        if ask_yes_no(f"  Include {label}?", default):
            selected.append(key)

    if not selected:
        print(UI.paint("You must choose at least one character type.", UI.YELLOW))
        return choose_character_sets()

    return build_alphabet(selected), selected


def build_alphabet(selected: list[str], exclude_ambiguous: bool = False) -> str:
    chars = "".join(SETS[key] for key in selected)
    if exclude_ambiguous:
        chars = "".join(ch for ch in chars if ch not in AMBIGUOUS)
    # Remove duplicates while preserving order.
    return "".join(dict.fromkeys(chars))


def secure_shuffle(items: list[str]) -> None:
    # Fisher-Yates shuffle using secrets.randbelow rather than random.shuffle.
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def generate_password(length: int, selected: list[str],
                      exclude_ambiguous: bool = False,
                      ensure_each_type: bool = True) -> str:
    """Generate one password with secure randomness and selected character types."""
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("Length must be an integer.")
    if not 1 <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between 1 and {MAX_LENGTH}.")
    if not selected or any(key not in SETS for key in selected):
        raise ValueError("Select at least one valid character type.")

    selected = list(dict.fromkeys(selected))
    char_sets = []
    for key in selected:
        chars = SETS[key]
        if exclude_ambiguous:
            chars = "".join(ch for ch in chars if ch not in AMBIGUOUS)
        if chars:
            char_sets.append(chars)

    if not char_sets:
        raise ValueError("Your options leave no available characters.")
    if ensure_each_type and length < len(char_sets):
        raise ValueError(
            f"Length must be at least {len(char_sets)} to include every selected type."
        )

    alphabet = "".join(dict.fromkeys("".join(char_sets)))
    if not alphabet:
        raise ValueError("No usable characters are available.")

    chars_out: list[str] = []
    if ensure_each_type:
        # Guarantee at least one character from every chosen type.
        chars_out.extend(secrets.choice(chars) for chars in char_sets)
        remaining = length - len(chars_out)
    else:
        remaining = length

    chars_out.extend(secrets.choice(alphabet) for _ in range(remaining))
    secure_shuffle(chars_out)
    return "".join(chars_out)


def entropy_estimate(length: int, alphabet_size: int) -> float:
    """Return the theoretical log2 search-space size, not a quality guarantee."""
    if length <= 0 or alphabet_size <= 1:
        return 0.0
    # log2(alphabet_size ** length) = length * log2(alphabet_size)
    # Use a tiny loop-free integer approximation via bit_length isn't exact;
    # math.log2 is fine for this calculation.
    import math
    return length * math.log2(alphabet_size)


def strength_label(length: int, alphabet_size: int) -> str:
    bits = entropy_estimate(length, alphabet_size)
    if length >= 16 and bits >= 90:
        return "HIGH theoretical search space"
    if length >= 12 and bits >= 60:
        return "MODERATE theoretical search space"
    return "LOWER theoretical search space"


def show_passwords(passwords: list[str], selected: list[str],
                   exclude_ambiguous: bool, ensure_each_type: bool) -> None:
    alphabet = build_alphabet(selected, exclude_ambiguous)
    print("\n" + UI.paint(f"Generated {len(passwords)} password(s):", UI.GREEN + UI.BOLD))
    for index, password in enumerate(passwords, start=1):
        print(f"{index:>3}. {password}")
    if passwords:
        bits = entropy_estimate(len(passwords[0]), len(alphabet))
        print("\n" + UI.paint("Password details", UI.CYAN))
        print(f"Length: {len(passwords[0])}")
        print(f"Available character count: {len(alphabet)}")
        print(f"Estimated search-space size: {bits:.1f} bits (theoretical)")
        print(f"Indicator: {strength_label(len(passwords[0]), len(alphabet))}")
        if ensure_each_type:
            print("Selected character types are each represented at least once.")
        print(UI.paint(
            "Note: This is a mathematical estimate, not a guarantee of real-world security.",
            UI.DIM
        ))


def generate_flow() -> None:
    length = ask_int(f"Password length (1-{MAX_LENGTH}): ", 1, MAX_LENGTH)
    count = ask_int(f"How many passwords (1-{MAX_BATCH})? ", 1, MAX_BATCH)

    selected: list[str] = []
    options = [
        ("uppercase", "Uppercase letters"),
        ("lowercase", "Lowercase letters"),
        ("digits", "Numbers"),
        ("symbols", "Symbols"),
    ]
    print("\nChoose character types (y/n):")
    for key, label in options:
        if ask_yes_no(f"Include {label}?", True):
            selected.append(key)

    if not selected:
        print(UI.paint("Pick at least one character type. Returning to menu.", UI.YELLOW))
        return

    exclude_ambiguous = ask_yes_no("Exclude confusing characters (0, O, 1, l, I, |)?", False)
    ensure_each_type = ask_yes_no("Guarantee at least one character from each selected type?", True)

    try:
        passwords = [
            generate_password(length, selected, exclude_ambiguous, ensure_each_type)
            for _ in range(count)
        ]
    except (ValueError, TypeError) as exc:
        print(UI.paint(f"Could not generate passwords: {exc}", UI.RED))
        return

    show_passwords(passwords, selected, exclude_ambiguous, ensure_each_type)

    if ask_yes_no("Save these passwords to a local text file?", False):
        save_passwords(passwords)


def save_passwords(passwords: list[str]) -> None:
    print(UI.paint(
        "\nWARNING: The export file will contain plaintext passwords. "
        "Anyone with access to it may read them.",
        UI.YELLOW
    ))
    if not ask_yes_no("Continue and save the file?", False):
        print("Export cancelled.")
        return
    try:
        REPORT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Fixed directory + generated filename prevents user-supplied path traversal.
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = REPORT_DIR / f"passwords_{timestamp}_{secrets.token_hex(3)}.txt"
        with filename.open("x", encoding="utf-8") as file:
            file.write(f"{APP_NAME} v{VERSION}\n")
            file.write(f"Created: {datetime.now().isoformat(timespec='seconds')}\n")
            file.write("WARNING: This file contains plaintext passwords.\n\n")
            for index, password in enumerate(passwords, start=1):
                file.write(f"{index}. {password}\n")
        try:
            filename.chmod(0o600)
        except OSError:
            pass  # Some Android filesystems do not support POSIX permissions.
        print(UI.paint(f"Saved locally to: {filename}", UI.GREEN))
        print("Keep this file private and delete it when no longer needed.")
    except OSError as exc:
        print(UI.paint(f"Could not save export: {exc}", UI.RED))


def preset_flow() -> None:
    presets = {
        "1": ("Everyday strong (16 chars)", 16, ["uppercase", "lowercase", "digits", "symbols"]),
        "2": ("Long password (24 chars)", 24, ["uppercase", "lowercase", "digits", "symbols"]),
        "3": ("Letters and numbers (20 chars)", 20, ["uppercase", "lowercase", "digits"]),
        "4": ("Passphrase-style character set (32 chars)", 32, ["uppercase", "lowercase", "digits"]),
    }
    print("\nPresets:")
    for key, (label, _, _) in presets.items():
        print(f" {key}. {label}")
    print(" 0. Back")
    choice = input("Choose preset: ").strip()
    if choice == "0":
        return
    if choice not in presets:
        print(UI.paint("Invalid preset.", UI.YELLOW))
        return
    label, length, selected = presets[choice]
    exclude_ambiguous = ask_yes_no("Exclude confusing characters?", False)
    try:
        password = generate_password(length, selected, exclude_ambiguous, True)
    except ValueError as exc:
        print(UI.paint(str(exc), UI.RED))
        return
    print(f"\n{label}\n{password}")
    if ask_yes_no("Save this password to a local text file?", False):
        save_passwords([password])


def self_tests() -> bool:
    tests: list[tuple[str, object]] = []

    def test_length() -> None:
        pwd = generate_password(32, ["uppercase", "lowercase", "digits", "symbols"])
        assert len(pwd) == 32

    def test_character_sets() -> None:
        pwd = generate_password(100, ["uppercase", "lowercase", "digits", "symbols"])
        assert any(c in SETS["uppercase"] for c in pwd)
        assert any(c in SETS["lowercase"] for c in pwd)
        assert any(c in SETS["digits"] for c in pwd)
        assert any(c in SETS["symbols"] for c in pwd)

    def test_ambiguous_exclusion() -> None:
        pwd = generate_password(500, ["uppercase", "lowercase", "digits"], True)
        assert not any(c in AMBIGUOUS for c in pwd)

    def test_invalid_length() -> None:
        for value in (0, -1, MAX_LENGTH + 1):
            try:
                generate_password(value, ["lowercase"])
            except ValueError:
                continue
            raise AssertionError(f"Length {value} should be rejected")

    def test_no_character_sets() -> None:
        try:
            generate_password(10, [])
        except ValueError:
            return
        raise AssertionError("Empty character set selection should be rejected")

    def test_minimum_for_each_type() -> None:
        try:
            generate_password(2, ["uppercase", "lowercase", "digits"], ensure_each_type=True)
        except ValueError:
            return
        raise AssertionError("Too-short length should be rejected")

    tests.extend([
        ("Requested length", test_length),
        ("Every selected type represented", test_character_sets),
        ("Ambiguous characters excluded", test_ambiguous_exclusion),
        ("Invalid lengths rejected", test_invalid_length),
        ("Empty selection rejected", test_no_character_sets),
        ("Minimum length validation", test_minimum_for_each_type),
    ])

    print("\n" + UI.paint("Running self-tests...", UI.CYAN))
    passed = 0
    for name, test in tests:
        try:
            test()  # type: ignore[operator]
            passed += 1
            print(UI.paint(f"  PASS  {name}", UI.GREEN))
        except Exception as exc:
            print(UI.paint(f"  FAIL  {name}: {exc}", UI.RED))
    print(f"\nResult: {passed}/{len(tests)} tests passed.")
    return passed == len(tests)


def help_screen() -> None:
    print(f"""
{APP_NAME} v{VERSION}

What it does:
  • Generates random passwords with Python's secrets module.
  • Lets you select letters, numbers, and symbols.
  • Can guarantee at least one character from each selected type.
  • Can exclude commonly confused characters.
  • Can generate batches and optional local text exports.
  • Runs offline and sends no passwords anywhere.

Safety:
  • Do not paste generated passwords into public chats.
  • Exported text files contain plaintext passwords.
  • Store important passwords in a reputable password manager.
  • Do not reuse the same password across multiple accounts.
  • The strength indicator estimates search-space size; it cannot
    account for every service's rules, leaks, or account protections.
""")


def main() -> None:
    while True:
        banner()
        print("  1. Generate custom password(s)")
        print("  2. Generate from a preset")
        print("  3. Run self-tests")
        print("  4. Help / security notes")
        print("  5. About")
        print("  0. Exit")
        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            generate_flow()
        elif choice == "2":
            preset_flow()
        elif choice == "3":
            if self_tests():
                print(UI.paint("All tests passed.", UI.GREEN))
            else:
                print(UI.paint("Some tests failed. Review the output.", UI.RED))
        elif choice == "4":
            help_screen()
        elif choice == "5":
            print(f"\n{APP_NAME} v{VERSION}")
            print("A local password generation utility for Python and Pydroid 3.")
            print("Built with Python's standard library.")
            print("License: choose a license before publishing.")
        elif choice == "0":
            print("Stay safe. Goodbye!")
            return
        else:
            print(UI.paint("Invalid option. Choose 0-5.", UI.YELLOW))

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting safely.")
        
