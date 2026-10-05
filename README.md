# SigMaker for Ghidra

A lightweight signature maker for [Ghidra](https://ghidra-sre.org/), inspired by [A200K/IDA-Pro-SigMaker](https://github.com/A200K/IDA-Pro-SigMaker).

Generates unique signatures from the current cursor or selection and outputs them in:

* IDA
* Cheat Engine / x64Dbg
* Pattern + Mask
* C Array

It also supports automatic wildcards for addresses, relative operands and references.

## Installation

1. Download `SigMaker.java`.
2. Copy it to your Ghidra user scripts folder:

   | OS | Path |
   |---|---|
   | Windows | `C:\Users\<your-user>\ghidra_scripts\SigMaker.java` |
   | Linux / macOS | `~/ghidra_scripts/SigMaker.java` |

   > The folder name is `ghidra_scripts` (with an **s**). It lives in your user
   > home directory, **not** inside the Ghidra installation folder. Ghidra
   > creates it automatically the first time you open the Script Manager; you
   > can also create it manually.

3. Open Ghidra's Script Manager:

   ```text
   Window → Script Manager
   ```

4. Click **Refresh Script List** (the circular arrow icon in the toolbar).
   Scripts in `ghidra_scripts` are detected automatically.

   If you prefer to keep the script in a different folder, click
   **Manage Script Directories** (the list icon in the toolbar), add that
   folder, and refresh the list.

5. Search for **SigMaker** in the list and run it.

6. *(Optional)* Tick the **In Tool** checkbox next to SigMaker to enable the
   shortcut and the menu entry described below.

## Shortcut

```text
Ctrl + Alt + S
```

## Menu

```text
Tools → SigMaker → Create Signature
```

## Output

Example:

```text
==================== SigMaker ====================
Unique signature
Address  : 00401234  (RVA 0x1234)
Length   : 12 bytes
Matches  : 1  (unique)
--------------------------------------------------
IDA              : 48 8B 05 ? ? ? ? 48 85 C0 74 05
Cheat Engine/x64 : 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 05
Pattern          : "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x05"
Mask             : "xxx????xxxxx"
C array          : { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x05 }
==================================================
```

The generated signature is automatically copied to the clipboard.

If a unique signature cannot be found at the selected address, SigMaker can also try signatures from the instruction's XREFs.

## Requirements

* [Ghidra](https://ghidra-sre.org/) 11.x or newer
* Java (included with Ghidra)

## License

See the repository for license information.
