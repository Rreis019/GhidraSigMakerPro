SigMaker for Ghidra

A lightweight signature maker for Ghidra, inspired by A200K/IDA-Pro-SigMaker.

Generates unique signatures from the current cursor or selection and supports IDA, Cheat Engine/x64Dbg, Pattern + Mask, and C Array formats.

Installation

Download SigMaker.java.

Open Ghidra → Window → Script Manager.

Add the folder containing SigMaker.java to your Script Directories.

Run SigMaker from the Script Manager.

Default shortcut:

Ctrl + Alt + S


Menu:

Tools → SigMaker → Create Signature

Output

Example output:

==================== SigMaker ====================
Unique signature
Address  : 00401234  (RVA 0x1234)
Length   : 15 bytes
Matches  : 1  (unique)
--------------------------------------------------
IDA              : 48 8B 05 ? ? ? ? 48 85 C0 74 05
Cheat Engine/x64 : 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 05
Pattern          : "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x05"
Mask             : "xxx????xxxxx"
C array          : { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x05 }
==================================================


The generated signature is automatically copied to the clipboard.

If the signature is not unique, SigMaker can also try signatures from the instruction's XREFs.