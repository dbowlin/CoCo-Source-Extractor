# CoCo Source Extractor

**CoCo Source Extractor** is a Windows GUI and CLI tool that extracts classic TRS-80 / Tandy Color Computer (CoCo 1/2/3) disk images, cartridges, cassettes, and binary files and converts them into readable, runnable source code you can study, edit, and run. 

**Note:** the created BASIC code is not a one-to-one clone, as some things are lost in the translation from machine code to BASIC.

- **`.asm` (6809 Assembly)** is disassembled using [`f9dasm`](https://github.com/Arakula/f9dasm) with CoCo 3 hardware/ROM symbols (`coco3.info`) and [`decb` (ToolShed)](https://github.com/nitros9project/toolshed).
- **`.bas` (Super Extended Color BASIC 2.1)** is generated directly from the disassembled 6809 control-flow graph, subroutines, ROM calls, GIME palettes, strings, and data tables—producing pure BASIC source code without `POKE`/`EXEC` machine-language stubs. Because pure BASIC is interpreted, the `.bas` output runs slower than native 6809 machine code and is designed for learning, inspection, and tinkering on CoCo 3 emulators and hardware.

---

## What It Does

When you open a CoCo file, the app automatically creates a `<filename>_source` folder next to your file containing:

- **`.asm` (6809 Disassembly)** — Multi-block DECB binaries, unpacked self-extracting cartridge ROMs, and raw binaries disassembled with CoCo hardware (`$FF00–$FFFF`) and ROM (`$A000–$FEFF`) labels.
- **`.bas` (Extended Color BASIC 2.1)** — Pure BASIC source code reconstructed from the binary:
  - **6809 Control-Flow & Data Separation:** Traces reachable code from the execution entry address (`DECB Execution Address`), subroutine calls (`BSR`/`LBSR`/`JSR`), and conditional branches so strings and data tables are cleanly separated from code.
  - **Multi-File / Data Block Linking:** Automatically links companion data files on the same disk or folder (such as `CELLDATA.DAT` loaded at `$7B00` by `2048.BIN`) into a unified 64 KB memory map, and generates interactive `HSCREEN 2` visual data/grid inspectors for standalone data binaries (`.DAT`, `.CHR`, `.PIC`, `.MAP`).
  - **CoCo 3 ROM & Hardware Lifting:** Translates CoCo ROM routines (`POLCAT`/`INKEY$`, `CHROUT`, `HSCREEN`, `HPRINT`, `HLINE`, `SOUND`) and GIME/SAM hardware registers (1.78 MHz speed pokes, 16-color RGB/Composite palettes, border colors) plus 6809 instructions and addressing modes into valid Extended Color BASIC 2.1.
  - **Built-in BASIC Linter:** Verifies line numbers, branch targets (`GOTO`/`GOSUB`/`THEN`/`RESTORE`), line length limits ($\le 248$ chars), and Color BASIC 2-character variable rules.
  - **Preserve Native BASIC:** Tokenized BASIC files on disks or tapes are detokenized directly via `decb` and never overwritten by binary decompilations on the same disk.

### Supported File Types
- Disk Images (`.dsk`)
- Cartridge ROMs (`.ccc`, `.cco`, `.rom` — including compressed self-extracting cartridges)
- DECB Binaries & Cassette Images (`.bin`, `.cas`)
- Tokenized BASIC Programs (`.bas`)
- Existing Disassembled 6809 Files (`.asm`)

---

## How to Use

### GUI Mode
1. **Double-click `CoCoSourceExtractor.exe`** (or drag and drop a CoCo file onto it).
2. **Choose your CoCo file** in the file picker window.
3. **Wait a moment** while extraction and decompilation finish.
4. **Open the `<filename>_source` folder** created next to your original file to view the `.asm` and `.bas` files.

### CLI / Headless Batch Mode
Run from PowerShell or Command Prompt with `--cli` (or `--headless`):
```powershell
Start-Process -FilePath ".\CoCoSourceExtractor.exe" -ArgumentList @("--cli", "`"path\to\game.dsk`"") -Wait
```

### Optional Cloud LLM Decompilation
The extractor works completely offline out of the box using its built-in deterministic 6809 decompiler. If you want to enable cloud LLM decompilation for custom binaries, set `GEMINI_API_KEY` (or `GOOGLE_API_KEY` / `XAI_API_KEY`) in your environment or place your key in `api_key.txt` in the application folder.

---

## Screenshots

### Extracted Extended Color BASIC Source (`.bas`)
![Extracted BASIC Source](screenshot.png)

### Extracted 6809 Assembly Source (`.asm`)
![Extracted ASM Source](screenshot2.png)

---

## Necessary Tools

Keep these tools in the `CoCoSourceExtractor` root folder (the app checks both its own directory and parent directory automatically):
- **[f9dasm](https://github.com/Arakula/f9dasm)** (`f9dasm.exe`) — Motorola 6800/6809/6309 disassembler used to generate `.asm` source.
- **[decb (ToolShed)](https://github.com/nitros9project/toolshed)** (`decb.exe`) — Disk Extended Color BASIC utility used to inspect disks, extract files, and detokenize/tokenize BASIC programs.
- **`coco3.info`** — CoCo 3 hardware and ROM symbol definitions passed to `f9dasm`.

---

## Acquiring CoCo Files

Visit the [Color Computer Archive](https://www.colorcomputerarchive.com/) to browse CoCo 1/2/3 games, applications, and utilities. Extract `.zip` archives first before passing `.dsk`, `.ccc`, `.rom`, `.bin`, or `.cas` files to the extractor.

## Disclosure

Agentic AI was used to help write and test some of the code in this app.

## License

This project is released into the public domain under the [UNLICENSE](UNLICENSE).
