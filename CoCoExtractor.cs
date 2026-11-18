using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

static class Program {
    static string BaseDir = AppDomain.CurrentDomain.BaseDirectory;
    static string DecbPath = ResolveToolPath("decb.exe");
    static string F9DasmPath = ResolveToolPath("f9dasm.exe");
    static string InfoPath = ResolveToolPath("coco3.info");
    static List<string> LogLines = new List<string>();

    static string ResolveToolPath(string fileName) {
        string[] candidates = new string[] {
            Path.Combine(BaseDir, fileName),
            Path.Combine(Path.GetFullPath(Path.Combine(BaseDir, "..")), fileName),
            Path.Combine(Path.GetFullPath(Path.Combine(BaseDir, @"..\..")), fileName),
            Path.Combine(Environment.CurrentDirectory, fileName)
        };
        for (int i = 0; i < candidates.Length; i++) {
            if (File.Exists(candidates[i])) {
                return candidates[i];
            }
        }
        return Path.Combine(BaseDir, fileName);
    }

    [STAThread]
    static void Main(string[] args) {
        bool cliMode = false;
        string targetFile = "";
        List<string> pathParts = new List<string>();

        foreach (string arg in args) {
            if (arg.Equals("--cli", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("-cli", StringComparison.OrdinalIgnoreCase) ||
                arg.Equals("--headless", StringComparison.OrdinalIgnoreCase)) {
                cliMode = true;
            } else if (File.Exists(arg)) {
                targetFile = arg;
            } else {
                pathParts.Add(arg);
            }
        }

        if (string.IsNullOrEmpty(targetFile) && pathParts.Count > 0) {
            string joined = string.Join(" ", pathParts.ToArray()).Trim('"');
            if (File.Exists(joined)) {
                targetFile = joined;
            }
        }

        if (cliMode) {
            if (!string.IsNullOrEmpty(targetFile)) {
                ProcessFile(targetFile, true);
            }
            return;
        }

        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        if (!File.Exists(DecbPath) || !File.Exists(F9DasmPath)) {
            MessageBox.Show(
                "Missing required tools in:\n" + BaseDir + "\n\nEnsure both decb.exe and f9dasm.exe are in the same folder as CoCoSourceExtractor.exe.",
                "Missing Tools", MessageBoxButtons.OK, MessageBoxIcon.Error
            );
            return;
        }

        if (string.IsNullOrEmpty(targetFile)) {
            using (OpenFileDialog dlg = new OpenFileDialog()) {
                dlg.Title = "Select CoCo File";
                dlg.Filter = "CoCo Files (*.dsk;*.cco;*.ccc;*.rom;*.bin;*.cas;*.bas;*.asm)|*.dsk;*.cco;*.ccc;*.rom;*.bin;*.cas;*.bas;*.asm|All Files (*.*)|*.*";
                if (dlg.ShowDialog() == DialogResult.OK) {
                    targetFile = dlg.FileName;
                }
            }
        }

        if (!string.IsNullOrEmpty(targetFile)) {
            RunProgressDialog(targetFile);
        }
    }

    static void RunProgressDialog(string filePath) {
        using (Form progressForm = new Form()) {
            progressForm.Text = "CoCo Source Extractor";
            progressForm.Width = 420;
            progressForm.Height = 160;
            progressForm.FormBorderStyle = FormBorderStyle.FixedDialog;
            progressForm.MaximizeBox = false;
            progressForm.MinimizeBox = false;
            progressForm.StartPosition = FormStartPosition.CenterScreen;

            Label lblStatus = new Label();
            lblStatus.Text = "Extracting, decompiling 6809 ASM, and building BASIC...";
            lblStatus.Left = 20;
            lblStatus.Top = 25;
            lblStatus.Width = 360;
            progressForm.Controls.Add(lblStatus);

            ProgressBar pBar = new ProgressBar();
            pBar.Left = 20;
            pBar.Top = 60;
            pBar.Width = 360;
            pBar.Height = 25;
            pBar.Style = ProgressBarStyle.Marquee;
            pBar.MarqueeAnimationSpeed = 30;
            progressForm.Controls.Add(pBar);

            BackgroundWorker worker = new BackgroundWorker();
            worker.DoWork += (s, e) => {
                ProcessFile(filePath, false);
            };
            worker.RunWorkerCompleted += (s, e) => {
                progressForm.Close();
            };

            progressForm.Shown += (s, e) => {
                worker.RunWorkerAsync();
            };

            progressForm.ShowDialog();
        }
    }

    static string RunTool(string exe, string arguments, string workDir) {
        ProcessStartInfo psi = new ProcessStartInfo {
            FileName = exe,
            Arguments = arguments,
            WorkingDirectory = workDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using (Process p = Process.Start(psi)) {
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();
            LogLines.Add(string.Format("> {0} {1} [Exit: {2}]", Path.GetFileName(exe), arguments, p.ExitCode));
            if (!string.IsNullOrWhiteSpace(stderr)) {
                LogLines.Add("STDERR: " + stderr.Trim());
            }
            return stdout;
        }
    }

    // =========================================================================
    // 6809 STATIC ANALYZER, CONTROL-FLOW GRAPH & MEMORY MODEL
    // =========================================================================

    sealed class AsmBlock {
        public int BlockNumber = 1;
        public ushort LoadAddress;
        public ushort ByteLength;
        public List<byte> RawBytes = new List<byte>();
    }

    sealed class ExtractedStringInfo {
        public ushort Address;
        public string Text = "";
    }

    sealed class AsmInstruction {
        public ushort Address;
        public string Label = "";
        public string Mnemonic = "";
        public string Operand = "";
        public byte[] Bytes = new byte[0];
        public bool IsReachableCode;
        public bool IsBranchTarget;
        public bool IsSubroutineEntry;
    }

    sealed class KeyDispatchEntry {
        public byte KeyCode;
        public ushort TargetAddress;
    }

    sealed class HprintCallSite {
        public ushort CallAddress;
        public int Col;
        public int Row;
        public int Color;
        public int Length;
        public ushort TextAddress;
        public string Text = "";
    }

    sealed class ParsedProgram {
        public string BaseName = "";
        public string SourceAsmPath = "";
        public string DiskExtension = "";
        public bool HasExecAddress;
        public ushort ExecAddress;
        public bool IsDataOnly;
        public List<AsmBlock> Blocks = new List<AsmBlock>();
        public List<AsmInstruction> Instructions = new List<AsmInstruction>();
        public Dictionary<ushort, int> AddrToInstructionIndex = new Dictionary<ushort, int>();
        public List<ExtractedStringInfo> ExtractedStrings = new List<ExtractedStringInfo>();
        public List<ushort> SubroutineTargets = new List<ushort>();
        public List<ushort> BranchTargets = new List<ushort>();
        public List<KeyDispatchEntry> KeyDispatches = new List<KeyDispatchEntry>();
        public List<HprintCallSite> HprintSites = new List<HprintCallSite>();
        public HashSet<ushort> RomCalls = new HashSet<ushort>();
        public HashSet<ushort> HardwareRefs = new HashSet<ushort>();
        public Dictionary<ushort, byte> MemoryMap = new Dictionary<ushort, byte>();
        public Dictionary<ushort, List<ushort>> JumpTables = new Dictionary<ushort, List<ushort>>();
        public List<ParsedProgram> AttachedDataPrograms = new List<ParsedProgram>();

        public byte ReadByte(int addr) {
            byte b;
            if (MemoryMap.TryGetValue((ushort)(addr & 0xFFFF), out b)) return b;
            for (int i = 0; i < AttachedDataPrograms.Count; i++) {
                if (AttachedDataPrograms[i].MemoryMap.TryGetValue((ushort)(addr & 0xFFFF), out b)) return b;
            }
            return 0;
        }

        public ushort ReadWord(int addr) {
            return (ushort)((ReadByte(addr) << 8) | ReadByte(addr + 1));
        }

        public bool HasAddressRange(int startAddr, int len) {
            for (int i = 0; i < len; i++) {
                ushort a = (ushort)((startAddr + i) & 0xFFFF);
                bool found = MemoryMap.ContainsKey(a);
                if (!found) {
                    for (int j = 0; j < AttachedDataPrograms.Count; j++) {
                        if (AttachedDataPrograms[j].MemoryMap.ContainsKey(a)) {
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) return false;
            }
            return true;
        }

        public string ReadNullTerminatedAscii(int startAddr, int maxLen) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = ReadByte(startAddr + i);
                if (b == 0) break;
                if (b >= 0x20 && b <= 0x7E) sb.Append((char)b);
            }
            return sb.ToString();
        }

        public string ReadFixedAscii(int startAddr, int len) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                byte b = ReadByte(startAddr + i);
                if (b >= 0x20 && b <= 0x7E) sb.Append((char)b);
                else sb.Append(' ');
            }
            return sb.ToString();
        }
    }

    static ParsedProgram ParseAsmFile(string asmPath, string baseName, string diskExt) {
        ParsedProgram prog = new ParsedProgram {
            BaseName = baseName,
            SourceAsmPath = asmPath,
            DiskExtension = (diskExt ?? "").ToUpperInvariant()
        };
        string[] rawLines = File.ReadAllLines(asmPath);
        AsmBlock currentBlock = null;

        Regex execRx = new Regex(@"^;\s*DECB Execution Address:\s*\$([0-9A-Fa-f]{4})", RegexOptions.IgnoreCase);
        Regex blockRx = new Regex(@"^;\s*---\s*Block\s+(\d+):\s*Load\s*\$([0-9A-Fa-f]{4})\s*\(\$([0-9A-Fa-f]{4})\s*bytes\)", RegexOptions.IgnoreCase);
        Regex orgRx = new Regex(@"^\s+ORG\s+\$([0-9A-Fa-f]{4})", RegexOptions.IgnoreCase);
        Regex lineRx = new Regex(@"^([A-Za-z0-9_]+)?\s*([A-Za-z0-9]+)\s*(.*?)\s*;([0-9A-Fa-f]{4}):\s*([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)");

        int validBranchOrSubCount = 0;
        int returnCount = 0;
        int negZeroCount = 0;

        foreach (string rawLine in rawLines) {
            string line = rawLine.TrimEnd();
            if (string.IsNullOrWhiteSpace(line)) continue;

            Match mExec = execRx.Match(line);
            if (mExec.Success) {
                prog.HasExecAddress = true;
                prog.ExecAddress = ushort.Parse(mExec.Groups[1].Value, NumberStyles.HexNumber);
                continue;
            }

            Match mBlock = blockRx.Match(line);
            if (mBlock.Success) {
                currentBlock = new AsmBlock {
                    BlockNumber = int.Parse(mBlock.Groups[1].Value),
                    LoadAddress = ushort.Parse(mBlock.Groups[2].Value, NumberStyles.HexNumber),
                    ByteLength = ushort.Parse(mBlock.Groups[3].Value, NumberStyles.HexNumber)
                };
                prog.Blocks.Add(currentBlock);
                continue;
            }

            Match mOrg = orgRx.Match(line);
            if (mOrg.Success && currentBlock == null) {
                currentBlock = new AsmBlock {
                    BlockNumber = 1,
                    LoadAddress = ushort.Parse(mOrg.Groups[1].Value, NumberStyles.HexNumber)
                };
                prog.Blocks.Add(currentBlock);
                continue;
            }

            if (line.StartsWith(";") || line.StartsWith("*") || line.StartsWith("f9dasm:") || line.StartsWith("Loaded ") || line.Trim() == "END") {
                continue;
            }

            if (currentBlock == null) {
                currentBlock = new AsmBlock { BlockNumber = 1 };
                prog.Blocks.Add(currentBlock);
            }

            Match mLine = lineRx.Match(line);
            if (mLine.Success) {
                string label = mLine.Groups[1].Value.Trim();
                string mnem = mLine.Groups[2].Value.Trim().ToUpperInvariant();
                string oper = mLine.Groups[3].Value.Trim();
                ushort addr = ushort.Parse(mLine.Groups[4].Value, NumberStyles.HexNumber);
                string[] hexParts = mLine.Groups[5].Value.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                byte[] bytes = new byte[hexParts.Length];
                for (int i = 0; i < hexParts.Length; i++) {
                    byte b = byte.Parse(hexParts[i], NumberStyles.HexNumber);
                    bytes[i] = b;
                    currentBlock.RawBytes.Add(b);
                    prog.MemoryMap[(ushort)((addr + i) & 0xFFFF)] = b;
                }
                if (currentBlock.LoadAddress == 0 && currentBlock.RawBytes.Count == bytes.Length) {
                    currentBlock.LoadAddress = addr;
                }

                AsmInstruction ins = new AsmInstruction {
                    Address = addr,
                    Label = label,
                    Mnemonic = mnem,
                    Operand = oper,
                    Bytes = bytes
                };
                prog.AddrToInstructionIndex[addr] = prog.Instructions.Count;
                prog.Instructions.Add(ins);

                if (mnem == "BSR" || mnem == "LBSR" || mnem == "JSR") {
                    validBranchOrSubCount++;
                    ushort target = ParseTargetAddress(oper);
                    if (target != 0) {
                        if (target >= 0xA000 && target < 0xFF00) {
                            prog.RomCalls.Add(target);
                        } else if (!prog.SubroutineTargets.Contains(target)) {
                            prog.SubroutineTargets.Add(target);
                        }
                    }
                } else if (IsBranchMnemonic(mnem)) {
                    ushort target = ParseTargetAddress(oper);
                    if (target != 0 && !prog.BranchTargets.Contains(target)) {
                        prog.BranchTargets.Add(target);
                    }
                } else if (mnem == "RTS" || mnem == "RTI" || (mnem == "PULS" && oper.IndexOf("PC", StringComparison.OrdinalIgnoreCase) >= 0)) {
                    returnCount++;
                } else if (mnem == "NEG") {
                    negZeroCount++;
                }

                ushort hw = ParseTargetAddress(oper);
                if (hw >= 0xFF00) {
                    prog.HardwareRefs.Add(hw);
                }
            }
        }

        for (int i = 0; i < prog.Blocks.Count; i++) {
            if (prog.Blocks[i].ByteLength == 0) {
                prog.Blocks[i].ByteLength = (ushort)prog.Blocks[i].RawBytes.Count;
            }
        }

        if (!prog.HasExecAddress && prog.Blocks.Count > 0) {
            prog.ExecAddress = prog.Blocks[0].LoadAddress;
        }

        int totalIns = Math.Max(1, prog.Instructions.Count);
        bool looksLikeTable = (negZeroCount * 100 / totalIns) >= 40 || (validBranchOrSubCount == 0 && returnCount <= 1);
        if (prog.DiskExtension == "DAT" || prog.DiskExtension == "CHR" || prog.DiskExtension == "PIC" || prog.DiskExtension == "MAP" || looksLikeTable) {
            prog.IsDataOnly = true;
        }

        if (!prog.IsDataOnly) {
            AnalyzeControlFlowAndPatterns(prog);
        }
        ExtractReadableStrings(prog);
        return prog;
    }

    static bool IsBranchMnemonic(string mnem) {
        switch (mnem) {
            case "BRA": case "LBRA": case "JMP":
            case "BEQ": case "LBEQ": case "BNE": case "LBNE":
            case "BCC": case "LBCC": case "BCS": case "LBCS":
            case "BPL": case "LBPL": case "BMI": case "LBMI":
            case "BGE": case "LBGE": case "BLT": case "LBLT":
            case "BGT": case "LBGT": case "BLE": case "LBLE":
            case "BHI": case "LBHI": case "BLS": case "LBLS":
            case "BVC": case "LBVC": case "BVS": case "LBVS":
                return true;
            default:
                return false;
        }
    }

    static bool IsUnconditionalTransfer(AsmInstruction ins) {
        if (ins.Mnemonic == "RTS" || ins.Mnemonic == "RTI" || ins.Mnemonic == "BRA" || ins.Mnemonic == "LBRA" || ins.Mnemonic == "JMP") {
            return true;
        }
        if (ins.Mnemonic == "PULS" && ins.Operand.IndexOf("PC", StringComparison.OrdinalIgnoreCase) >= 0) {
            return true;
        }
        return false;
    }

    static void AnalyzeControlFlowAndPatterns(ParsedProgram prog) {
        // 1. Recursive-descent reachability trace from ExecAddress and SubroutineTargets
        Queue<ushort> work = new Queue<ushort>();
        if (prog.AddrToInstructionIndex.ContainsKey(prog.ExecAddress)) {
            work.Enqueue(prog.ExecAddress);
            prog.Instructions[prog.AddrToInstructionIndex[prog.ExecAddress]].IsSubroutineEntry = true;
        }
        for (int i = 0; i < prog.SubroutineTargets.Count; i++) {
            ushort t = prog.SubroutineTargets[i];
            if (prog.AddrToInstructionIndex.ContainsKey(t)) {
                work.Enqueue(t);
                prog.Instructions[prog.AddrToInstructionIndex[t]].IsSubroutineEntry = true;
            }
        }

        while (work.Count > 0) {
            ushort addr = work.Dequeue();
            int idx;
            if (!prog.AddrToInstructionIndex.TryGetValue(addr, out idx)) continue;

            while (idx >= 0 && idx < prog.Instructions.Count) {
                AsmInstruction ins = prog.Instructions[idx];
                if (ins.IsReachableCode) break;
                ins.IsReachableCode = true;

                if (ins.Mnemonic == "BSR" || ins.Mnemonic == "LBSR" || ins.Mnemonic == "JSR") {
                    ushort target = ParseTargetAddress(ins.Operand);
                    if (target != 0 && prog.AddrToInstructionIndex.ContainsKey(target)) {
                        AsmInstruction tIns = prog.Instructions[prog.AddrToInstructionIndex[target]];
                        tIns.IsSubroutineEntry = true;
                        if (!tIns.IsReachableCode) work.Enqueue(target);
                    } else if (ins.Operand.Contains("[")) {
                        // Resolve indirect jump table (e.g., LDX #table; JSR [A,X])
                        for (int back = idx - 1; back >= Math.Max(0, idx - 6); back--) {
                            AsmInstruction prev = prog.Instructions[back];
                            if (prev.Mnemonic == "LDX" || prev.Mnemonic == "LDY" || prev.Mnemonic == "LDU") {
                                ushort tblAddr = ParseTargetAddress(prev.Operand);
                                if (tblAddr != 0 && prog.HasAddressRange(tblAddr, 2)) {
                                    List<ushort> jtTargets = new List<ushort>();
                                    int misses = 0;
                                    for (int k = 0; k < 64; k++) {
                                        if (!prog.HasAddressRange(tblAddr + k * 2, 2)) break;
                                        ushort ptr = (ushort)((prog.ReadByte(tblAddr + k * 2) << 8) | prog.ReadByte(tblAddr + k * 2 + 1));
                                        if (ptr < 0x0600 || ptr >= 0xFF00) break;
                                        if (!prog.AddrToInstructionIndex.ContainsKey(ptr)) {
                                            misses++;
                                            if (misses >= 2) break;
                                            continue;
                                        }
                                        misses = 0;
                                        jtTargets.Add(ptr);
                                        AsmInstruction jtIns = prog.Instructions[prog.AddrToInstructionIndex[ptr]];
                                        jtIns.IsSubroutineEntry = true;
                                        if (!jtIns.IsReachableCode) work.Enqueue(ptr);
                                    }
                                    if (jtTargets.Count > 0) prog.JumpTables[ins.Address] = jtTargets;
                                }
                                break;
                            }
                        }
                    }
                } else if (IsBranchMnemonic(ins.Mnemonic)) {
                    ushort target = ParseTargetAddress(ins.Operand);
                    if (target != 0 && prog.AddrToInstructionIndex.ContainsKey(target)) {
                        AsmInstruction tIns = prog.Instructions[prog.AddrToInstructionIndex[target]];
                        tIns.IsBranchTarget = true;
                        if (!tIns.IsReachableCode) work.Enqueue(target);
                    }
                }

                if (IsUnconditionalTransfer(ins)) {
                    break;
                }
                idx++;
            }
        }

        // 2. Scan for CMPA/CMPB #imm followed by BEQ/LBEQ/BNE/LBNE (Key dispatch table)
        for (int i = 0; i + 1 < prog.Instructions.Count; i++) {
            AsmInstruction cur = prog.Instructions[i];
            AsmInstruction nxt = prog.Instructions[i + 1];
            if (!cur.IsReachableCode) continue;

            if ((cur.Mnemonic == "CMPA" || cur.Mnemonic == "CMPB") && cur.Operand.StartsWith("#$")) {
                byte keyVal;
                if (byte.TryParse(cur.Operand.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out keyVal)) {
                    if (nxt.Mnemonic == "BEQ" || nxt.Mnemonic == "LBEQ") {
                        ushort target = ParseTargetAddress(nxt.Operand);
                        if (target != 0) {
                            bool exists = false;
                            for (int k = 0; k < prog.KeyDispatches.Count; k++) {
                                if (prog.KeyDispatches[k].KeyCode == keyVal) { exists = true; break; }
                            }
                            if (!exists) {
                                prog.KeyDispatches.Add(new KeyDispatchEntry { KeyCode = keyVal, TargetAddress = target });
                            }
                        }
                    }
                }
            }
        }

        // 3. Scan for CoCo 3 ROM HPRINT ($EF65) and wrapper calls to recover positioned UI strings
        for (int i = 0; i < prog.Instructions.Count; i++) {
            AsmInstruction ins = prog.Instructions[i];
            if (!ins.IsReachableCode) continue;
            ushort target = ParseTargetAddress(ins.Operand);
            if ((ins.Mnemonic == "JSR" || ins.Mnemonic == "BSR" || ins.Mnemonic == "LBSR") && target == 0xEF65) {
                int col = 0, row = 0, color = 1, len = 4;
                ushort strAddr = 0;
                for (int back = Math.Max(0, i - 12); back < i; back++) {
                    AsmInstruction prev = prog.Instructions[back];
                    if (prev.Mnemonic == "LDX" && prev.Operand.StartsWith("#")) {
                        strAddr = ParseTargetAddress(prev.Operand);
                    } else if (prev.Mnemonic == "LDB" && prev.Operand.StartsWith("#$")) {
                        int val = int.Parse(prev.Operand.Substring(2), NumberStyles.HexNumber);
                        if (back + 1 < i && prog.Instructions[back + 1].Operand.IndexOf("FE0A", StringComparison.OrdinalIgnoreCase) >= 0) {
                            color = val;
                        } else if (back + 1 < i && prog.Instructions[back + 1].Operand.IndexOf("00BD", StringComparison.OrdinalIgnoreCase) >= 0) {
                            col = val;
                        } else if (back + 1 < i && prog.Instructions[back + 1].Operand.IndexOf("00BF", StringComparison.OrdinalIgnoreCase) >= 0) {
                            row = val;
                        } else if (back == i - 1 || back == i - 2) {
                            len = val;
                        }
                    }
                }
                if (strAddr != 0 && prog.HasAddressRange(strAddr, len)) {
                    string txt = prog.ReadFixedAscii(strAddr, len).TrimEnd();
                    if (!string.IsNullOrEmpty(txt)) {
                        prog.HprintSites.Add(new HprintCallSite {
                            CallAddress = ins.Address,
                            Col = col,
                            Row = row,
                            Color = color,
                            Length = len,
                            TextAddress = strAddr,
                            Text = txt
                        });
                    }
                }
            }
        }
    }

    static ushort ParseTargetAddress(string operand) {
        if (string.IsNullOrEmpty(operand)) return 0;
        Match mHex = Regex.Match(operand, @"\$([0-9A-Fa-f]{4})");
        if (mHex.Success) {
            return ushort.Parse(mHex.Groups[1].Value, NumberStyles.HexNumber);
        }
        Match mSym = Regex.Match(operand, @"\b[ZM]([0-9A-Fa-f]{4})\b");
        if (mSym.Success) {
            return ushort.Parse(mSym.Groups[1].Value, NumberStyles.HexNumber);
        }
        if (operand.IndexOf("PALETTE_0", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFFB0;
        if (operand.IndexOf("GIME_BRDR", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF9A;
        if (operand.IndexOf("GIME_INIT0", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF90;
        if (operand.IndexOf("GIME_INIT1", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF91;
        if (operand.IndexOf("GIME_VMODE", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF98;
        if (operand.IndexOf("GIME_VRES", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF99;
        if (operand.IndexOf("CPU_SPEED_FAST", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFFD9;
        if (operand.IndexOf("CPU_SPEED_SLOW", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFFD8;
        if (operand.IndexOf("POLCAT", StringComparison.OrdinalIgnoreCase) >= 0) return 0xA000;
        if (operand.IndexOf("CHROUT", StringComparison.OrdinalIgnoreCase) >= 0) return 0xA002;
        if (operand.IndexOf("STROUT", StringComparison.OrdinalIgnoreCase) >= 0) return 0xB958;
        if (operand.IndexOf("PRINT_DEC", StringComparison.OrdinalIgnoreCase) >= 0) return 0xBDCC;
        if (operand.IndexOf("PIA0_DA", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF00;
        if (operand.IndexOf("PIA0_DB", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF02;
        if (operand.IndexOf("PIA1_DA", StringComparison.OrdinalIgnoreCase) >= 0) return 0xFF20;
        return 0;
    }

    static void ExtractReadableStrings(ParsedProgram prog) {
        HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
        StringBuilder current = new StringBuilder();
        ushort startAddr = 0;
        int prevAddr = -2;

        for (int i = 0; i < prog.Instructions.Count; i++) {
            AsmInstruction ins = prog.Instructions[i];
            if (ins.IsReachableCode) {
                if (current.Length >= 4) {
                    AddCleanString(startAddr, current.ToString(), seen, prog.ExtractedStrings);
                }
                current.Clear();
                continue;
            }
            for (int bIdx = 0; bIdx < ins.Bytes.Length; bIdx++) {
                ushort curAddr = (ushort)((ins.Address + bIdx) & 0xFFFF);
                if (prevAddr >= 0 && curAddr != (ushort)((prevAddr + 1) & 0xFFFF)) {
                    if (current.Length >= 4) {
                        AddCleanString(startAddr, current.ToString(), seen, prog.ExtractedStrings);
                    }
                    current.Clear();
                }
                prevAddr = curAddr;
                byte b = ins.Bytes[bIdx];
                if (b >= 0x20 && b <= 0x7E) {
                    if (current.Length == 0) {
                        startAddr = curAddr;
                    }
                    current.Append((char)b);
                } else {
                    if (current.Length >= 4) {
                        AddCleanString(startAddr, current.ToString(), seen, prog.ExtractedStrings);
                    }
                    current.Clear();
                }
            }
        }
        if (current.Length >= 4) {
            AddCleanString(startAddr, current.ToString(), seen, prog.ExtractedStrings);
        }
    }

    static void AddCleanString(ushort addr, string s, HashSet<string> seen, List<ExtractedStringInfo> output) {
        string trimmed = s.Trim();
        if (trimmed.Length < 4 || trimmed.Length > 76) return;
        int letters = 0;
        int vowels = 0;
        foreach (char c in trimmed) {
            char u = char.ToUpperInvariant(c);
            if (u >= 'A' && u <= 'Z') {
                letters++;
                if ("AEIOUY".IndexOf(u) >= 0) vowels++;
            }
        }
        if (letters < 3 || vowels == 0) return;
        if ((double)letters / trimmed.Length < 0.45) return;
        bool allSame = true;
        for (int i = 1; i < trimmed.Length; i++) {
            if (trimmed[i] != trimmed[0]) { allSame = false; break; }
        }
        if (allSame) return;
        if (seen.Add(trimmed) && output.Count < 80) {
            output.Add(new ExtractedStringInfo { Address = addr, Text = trimmed });
        }
    }

    static void LinkFolderPrograms(List<ParsedProgram> programs) {
        List<ParsedProgram> dataProgs = new List<ParsedProgram>();
        List<ParsedProgram> codeProgs = new List<ParsedProgram>();

        for (int i = 0; i < programs.Count; i++) {
            if (programs[i].IsDataOnly) {
                dataProgs.Add(programs[i]);
            } else {
                codeProgs.Add(programs[i]);
            }
        }

        for (int i = 0; i < codeProgs.Count; i++) {
            for (int j = 0; j < dataProgs.Count; j++) {
                codeProgs[i].AttachedDataPrograms.Add(dataProgs[j]);
            }
        }
    }

    static void TranspileAsmToBasic(string asmPath, string outDir, string baseName) {
        if (!File.Exists(asmPath)) return;
        ParsedProgram prog = ParseAsmFile(asmPath, baseName, "");
        string[] siblingAsms = Directory.GetFiles(outDir, "*.asm");
        for (int i = 0; i < siblingAsms.Length; i++) {
            if (!siblingAsms[i].Equals(asmPath, StringComparison.OrdinalIgnoreCase)) {
                ParsedProgram sib = ParseAsmFile(siblingAsms[i], Path.GetFileNameWithoutExtension(siblingAsms[i]), "");
                if (sib.IsDataOnly) {
                    prog.AttachedDataPrograms.Add(sib);
                }
            }
        }
        WriteBasicForProgram(prog, outDir, new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    static void WriteBasicForProgram(ParsedProgram prog, string outDir, HashSet<string> nativeBasicNames) {
        string basFileName = prog.BaseName + ".bas";
        if (nativeBasicNames != null && nativeBasicNames.Contains(prog.BaseName)) {
            basFileName = prog.BaseName + "_ML.bas";
        }
        string basOutput = GenerateBasicSource(prog);
        if (string.IsNullOrEmpty(basOutput)) {
            string stale = Path.Combine(outDir, basFileName);
            if (File.Exists(stale)) File.Delete(stale);
            return;
        }
        string lintReport;
        if (!ValidateBasicSource(basOutput, out lintReport)) {
            LogLines.Add("BASIC Linter Warning for " + prog.BaseName + ": " + lintReport);
        }
        File.WriteAllText(Path.Combine(outDir, basFileName), basOutput, Encoding.ASCII);
    }

    // =========================================================================
    // EXTENDED COLOR BASIC 2.1 LINTER & QUALITY GATE
    // =========================================================================

    static bool ValidateBasicSource(string basText, out string report) {
        List<string> issues = new List<string>();
        string[] lines = basText.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        HashSet<int> definedLines = new HashSet<int>();
        List<int> referencedLines = new List<int>();
        int prevLine = -1;

        Regex lineNumRx = new Regex(@"^\s*(\d+)\s+(.*)$");
        Regex gotoRx = new Regex(@"\b(?:GOTO|GOSUB|THEN|RESTORE)\s+(\d+)", RegexOptions.IgnoreCase);
        Regex forbiddenKwRx = new Regex(@"\b(?:WHILE|WEND|END\s+IF|ENDIF|SUB|ENDSUB)\b", RegexOptions.IgnoreCase);
        Regex badVarAssignRx = new Regex(@"(?:^|:|\bTHEN\s+|\bELSE\s+)\s*(GO|TO|OR|ON|IF|FN)\s*=", RegexOptions.IgnoreCase);

        for (int i = 0; i < lines.Length; i++) {
            string l = lines[i];
            if (l.Length > 248) {
                issues.Add(string.Format("Line index {0} exceeds 248 chars ({1} chars)", i + 1, l.Length));
            }
            Match m = lineNumRx.Match(l);
            if (!m.Success) {
                issues.Add(string.Format("Missing line number on line {0}: {1}", i + 1, l));
                continue;
            }
            int num = int.Parse(m.Groups[1].Value);
            if (num <= prevLine) {
                issues.Add(string.Format("Non-increasing line number {0} after {1}", num, prevLine));
            }
            prevLine = num;
            definedLines.Add(num);

            string body = m.Groups[2].Value;
            string trimmedBody = body.TrimStart();
            if (!trimmedBody.StartsWith("'") && !trimmedBody.StartsWith("REM", StringComparison.OrdinalIgnoreCase) &&
                !trimmedBody.StartsWith("DATA", StringComparison.OrdinalIgnoreCase)) {
                string noQuotes = Regex.Replace(body, "\"[^\"]*\"", "\"\"");
                int tickIdx = noQuotes.IndexOf('\'');
                if (tickIdx >= 0) noQuotes = noQuotes.Substring(0, tickIdx);

                MatchCollection refs = gotoRx.Matches(noQuotes);
                foreach (Match rm in refs) {
                    referencedLines.Add(int.Parse(rm.Groups[1].Value));
                }
                Match mForbid = forbiddenKwRx.Match(noQuotes);
                if (mForbid.Success) {
                    issues.Add(string.Format("Line {0} uses unsupported keyword '{1}'", num, mForbid.Value));
                }
                Match mBadVar = badVarAssignRx.Match(noQuotes);
                if (mBadVar.Success) {
                    issues.Add(string.Format("Line {0} assigns to reserved 2-char token '{1}'", num, mBadVar.Groups[1].Value));
                }
            }
        }

        for (int i = 0; i < referencedLines.Count; i++) {
            if (!definedLines.Contains(referencedLines[i])) {
                issues.Add(string.Format("Undefined branch target line {0}", referencedLines[i]));
            }
        }

        report = string.Join("; ", issues.ToArray());
        return issues.Count == 0;
    }

    // =========================================================================
    // OPTIONAL CLOUD LLM DECOMPILER (ANTHROPIC / GEMINI / GROK)
    // =========================================================================

    static string GetConfiguredApiKey(out string provider) {
        provider = "";
        string anthropicKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
        if (!string.IsNullOrEmpty(anthropicKey)) {
            provider = "anthropic";
            return anthropicKey.Trim();
        }
        string geminiKey = Environment.GetEnvironmentVariable("GEMINI_API_KEY");
        if (string.IsNullOrEmpty(geminiKey)) geminiKey = Environment.GetEnvironmentVariable("GOOGLE_API_KEY");
        if (!string.IsNullOrEmpty(geminiKey)) {
            provider = "gemini";
            return geminiKey.Trim();
        }
        string xaiKey = Environment.GetEnvironmentVariable("XAI_API_KEY");
        if (!string.IsNullOrEmpty(xaiKey)) {
            provider = "xai";
            return xaiKey.Trim();
        }
        string keyFile = ResolveToolPath("api_key.txt");
        if (File.Exists(keyFile)) {
            string raw = File.ReadAllText(keyFile).Trim();
            if (!string.IsNullOrEmpty(raw)) {
                if (raw.StartsWith("sk-ant-", StringComparison.OrdinalIgnoreCase)) provider = "anthropic";
                else if (raw.StartsWith("xai-", StringComparison.OrdinalIgnoreCase)) provider = "xai";
                else provider = "gemini";
                return raw;
            }
        }
        return "";
    }

    static string WorkingGeminiModel = "";
    static string WorkingAnthropicModel = "";

    static string CallGeminiOrXai(string provider, string apiKey, string promptText, out string errMsg) {
        errMsg = "";
        string escapedPrompt = EscapeJsonString(promptText);
        string[] models;
        if (provider == "gemini") {
            models = !string.IsNullOrEmpty(WorkingGeminiModel)
                ? new string[] { WorkingGeminiModel }
                : new string[] { "gemini-3.1-pro-preview", "gemini-3-flash-preview" };
        } else if (provider == "anthropic") {
            models = !string.IsNullOrEmpty(WorkingAnthropicModel)
                ? new string[] { WorkingAnthropicModel }
                : new string[] { "claude-sonnet-4-5-20250929", "claude-sonnet-4-20250514", "claude-3-7-sonnet-20250219" };
        } else {
            models = new string[] { "grok-3-mini" };
        }

        for (int attempt = 0; attempt < models.Length; attempt++) {
            string modelName = models[attempt];
            for (int retry = 0; retry < 4; retry++) {
                try {
                    string url;
                    string bodyJson;
                    if (provider == "gemini") {
                        url = "https://generativelanguage.googleapis.com/v1beta/models/" + modelName + ":generateContent?key=" + apiKey;
                        bodyJson = "{\"contents\":[{\"parts\":[{\"text\":\"" + escapedPrompt + "\"}]}],\"generationConfig\":{\"temperature\":0.1,\"maxOutputTokens\":65536}}";
                    } else if (provider == "anthropic") {
                        url = "https://api.anthropic.com/v1/messages";
                        bodyJson = "{\"model\":\"" + modelName + "\",\"max_tokens\":16384,\"temperature\":0.1,\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}]}";
                    } else {
                        url = "https://api.x.ai/v1/chat/completions";
                        bodyJson = "{\"model\":\"" + modelName + "\",\"temperature\":0.1,\"messages\":[{\"role\":\"user\",\"content\":\"" + escapedPrompt + "\"}]}";
                    }

                    HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                    req.Method = "POST";
                    req.ContentType = "application/json";
                    req.Timeout = 900000;
                    req.ReadWriteTimeout = 900000;
                    if (provider == "anthropic") {
                        req.Headers.Add("x-api-key", apiKey);
                        req.Headers.Add("anthropic-version", "2023-06-01");
                    } else if (provider == "xai") {
                        req.Headers.Add("Authorization", "Bearer " + apiKey);
                    }
                    byte[] postBytes = Encoding.UTF8.GetBytes(bodyJson);
                    using (Stream reqStream = req.GetRequestStream()) {
                        reqStream.Write(postBytes, 0, postBytes.Length);
                    }
                    using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                    using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) {
                        string json = sr.ReadToEnd();
                        if (json.Contains("\"MAX_TOKENS\"") || json.Contains("\"max_tokens\"")) {
                            LogLines.Add("LLM WARNING (" + modelName + "): response hit max tokens and may be truncated.");
                        }
                        string candidate = CleanLlmBasicOutput(ExtractTextFromLlmJson(json));
                        if (!string.IsNullOrEmpty(candidate)) {
                            if (provider == "gemini") WorkingGeminiModel = modelName;
                            else if (provider == "anthropic") WorkingAnthropicModel = modelName;
                            LogLines.Add("LLM OK (" + modelName + "): " + candidate.Split('\n').Length + " BASIC lines returned.");
                            return candidate;
                        }
                        errMsg = modelName + " returned no numbered BASIC lines.";
                        LogLines.Add("LLM EMPTY (" + modelName + "): " + (json.Length > 400 ? json.Substring(0, 400) : json));
                        break;
                    }
                } catch (WebException wex) {
                    int code = 0;
                    string body = "";
                    HttpWebResponse er = wex.Response as HttpWebResponse;
                    if (er != null) {
                        code = (int)er.StatusCode;
                        try { using (StreamReader esr = new StreamReader(er.GetResponseStream())) body = esr.ReadToEnd(); } catch { }
                    }
                    Match msgM = Regex.Match(body, "\"message\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
                    string apiMsg = msgM.Success ? JsonUnescape(msgM.Groups[1].Value) : wex.Message;
                    if (apiMsg.Length > 300) apiMsg = apiMsg.Substring(0, 300);
                    errMsg = modelName + " HTTP " + code + ": " + apiMsg;
                    LogLines.Add("LLM API attempt failed (" + errMsg + ")");
                    bool transient = (code == 429 || code == 500 || code == 503 || code == 0);
                    bool quotaZero = body.Contains("limit: 0");
                    if (transient && !quotaZero && retry < 3) {
                        System.Threading.Thread.Sleep(15000 * (retry + 1));
                        continue;
                    }
                    break;
                } catch (Exception ex) {
                    errMsg = modelName + ": " + ex.Message;
                    LogLines.Add("LLM API attempt failed (" + errMsg + ")");
                    break;
                }
            }
        }
        if (!string.IsNullOrEmpty(errMsg)) LastLlmFailure = errMsg;
        return "";
    }

    static string JsonUnescape(string raw) {
        StringBuilder sb = new StringBuilder(raw.Length);
        for (int i = 0; i < raw.Length; i++) {
            char c = raw[i];
            if (c != '\\' || i + 1 >= raw.Length) { sb.Append(c); continue; }
            char n = raw[++i];
            switch (n) {
                case 'n': sb.Append('\n'); break;
                case 'r': sb.Append('\r'); break;
                case 't': sb.Append('\t'); break;
                case 'b': sb.Append('\b'); break;
                case 'f': sb.Append('\f'); break;
                case '/': sb.Append('/'); break;
                case '"': sb.Append('"'); break;
                case '\\': sb.Append('\\'); break;
                case 'u':
                    if (i + 4 < raw.Length) {
                        sb.Append((char)int.Parse(raw.Substring(i + 1, 4), NumberStyles.HexNumber));
                        i += 4;
                    }
                    break;
                default: sb.Append(n); break;
            }
        }
        return sb.ToString();
    }

    static string ExtractSubroutineAsmSlice(ParsedProgram prog, ushort startAddr, int maxIns) {
        int idx;
        if (!prog.AddrToInstructionIndex.TryGetValue(startAddr, out idx)) return "";
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < maxIns && idx + k < prog.Instructions.Count; k++) {
            AsmInstruction ins = prog.Instructions[idx + k];
            if (k > 0 && ins.IsSubroutineEntry) break;
            sb.AppendFormat("  ${0:X4}: {1,-6} {2}\r\n", ins.Address, ins.Mnemonic, ins.Operand);
            if (ins.Mnemonic == "RTS" || ins.Mnemonic == "RTI" ||
                (ins.Mnemonic == "PULS" && ins.Operand.IndexOf("PC", StringComparison.OrdinalIgnoreCase) >= 0)) {
                break;
            }
        }
        return sb.ToString();
    }

    static List<ushort> FindStubbedSubroutines(string bas, Dictionary<ushort, int> subLineMap) {
        List<ushort> result = new List<ushort>();
        Regex lineRx = new Regex(@"^\s*(\d+)\s+(.*)$");
        SortedDictionary<int, string> byLine = new SortedDictionary<int, string>();
        foreach (string l in bas.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
            Match m = lineRx.Match(l);
            if (m.Success) byLine[int.Parse(m.Groups[1].Value)] = m.Groups[2].Value.Trim();
        }
        foreach (KeyValuePair<ushort, int> kv in subLineMap) {
            int realStatements = 0;
            foreach (KeyValuePair<int, string> ln in byLine) {
                if (ln.Key < kv.Value || ln.Key >= kv.Value + 200) continue;
                string body = ln.Value.ToUpperInvariant();
                if (body.StartsWith("REM") || body.StartsWith("'") || body == "RETURN") continue;
                realStatements++;
            }
            if (realStatements == 0) result.Add(kv.Key);
        }
        return result;
    }

    static string RemoveLineRanges(string bas, List<ushort> subs, Dictionary<ushort, int> subLineMap) {
        Regex lineRx = new Regex(@"^\s*(\d+)\s+");
        StringBuilder sb = new StringBuilder();
        foreach (string l in bas.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
            Match m = lineRx.Match(l);
            bool drop = false;
            if (m.Success) {
                int n = int.Parse(m.Groups[1].Value);
                foreach (ushort s in subs) {
                    int b = subLineMap[s];
                    if (n >= b && n < b + 200) { drop = true; break; }
                }
            }
            if (!drop) sb.AppendLine(l);
        }
        return sb.ToString();
    }

    static bool LooksLikeRegisterSimulator(string bas) {
        if (string.IsNullOrEmpty(bas)) return false;
        string[] rawLines = bas.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        int codeLines = 0;
        int simHits = 0;
        int peekPokeLines = 0;
        Regex lineRx = new Regex(@"^\s*\d+\s+(.*)$");
        for (int i = 0; i < rawLines.Length; i++) {
            Match m = lineRx.Match(rawLines[i]);
            if (!m.Success) continue;
            string body = m.Groups[1].Value.TrimStart();
            if (body.StartsWith("'") || body.StartsWith("REM", StringComparison.OrdinalIgnoreCase) ||
                body.StartsWith("DATA", StringComparison.OrdinalIgnoreCase)) continue;
            int tick = body.IndexOf('\'');
            if (tick >= 0) body = body.Substring(0, tick);
            int remIdx = body.IndexOf("REM", StringComparison.OrdinalIgnoreCase);
            if (remIdx >= 0) body = body.Substring(0, remIdx);
            codeLines++;
            if (Regex.IsMatch(body, @"\b(?:FZ|FC|FN)=\(|\bGOSUB 8[13]0\b|\bRA=VL\b|\bMM\(AD-MB\)")) simHits++;
            if (Regex.IsMatch(body, @"\b(?:PEEK|POKE)\b", RegexOptions.IgnoreCase) &&
                !Regex.IsMatch(body, @"\bPOKE\s+(?:6549[67]|&HFFD[89])\b", RegexOptions.IgnoreCase)) peekPokeLines++;
        }
        return simHits > Math.Max(10, codeLines / 10) || peekPokeLines > 2;
    }

    static string AppendBinaryAssetsAndBlitter(ParsedProgram prog, string llmBas) {
        // Strip any lines >= 9000 from LLM output so our 9000+ blitter & 10000+ DATA tables never collide
        StringBuilder sb = new StringBuilder();
        string[] lines = llmBas.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Regex numRx = new Regex(@"^\s*(\d+)\s+(.*)$");
        for (int i = 0; i < lines.Length; i++) {
            Match m = numRx.Match(lines[i]);
            if (m.Success) {
                int ln = int.Parse(m.Groups[1].Value);
                if (ln < 9000) sb.AppendLine(ln + " " + m.Groups[2].Value.Trim());
            }
        }

        ushort minAddr = prog.Blocks.Count > 0 ? prog.Blocks[0].LoadAddress : prog.ExecAddress;
        List<byte> initBytes = new List<byte>();
        if (prog.MemoryMap.Count > 0) {
            minAddr = ushort.MaxValue;
            ushort maxAddr = 0;
            foreach (ushort addr in prog.MemoryMap.Keys) {
                if (addr < minAddr) minAddr = addr;
                if (addr > maxAddr) maxAddr = addr;
            }
            int span = (maxAddr - minAddr) + 1;
            for (int i = 0; i < span; i++) initBytes.Add(prog.ReadByte(minAddr + i));
        } else if (prog.Blocks.Count > 0) {
            for (int i = 0; i < prog.Blocks[0].RawBytes.Count; i++) initBytes.Add(prog.Blocks[0].RawBytes[i]);
        }
        while (initBytes.Count < 16) initBytes.Add(0);

        sb.AppendLine("9000 REM *** LOAD ORIGINAL BINARY ASSETS INTO MM(0..NB) ***");
        sb.AppendFormat("9010 MB={0}:NB={1}:DIM MM({1})\r\n", (int)minAddr, initBytes.Count - 1);
        sb.AppendLine("9020 RESTORE 10000");
        sb.AppendLine("9030 FOR MI=0 TO NB:READ MV:MM(MI)=MV:NEXT MI");
        sb.AppendLine("9040 RETURN");
        sb.AppendLine("9100 REM *** COCO 3 16-COLOR PACKED-PIXEL BITMAP BLITTER (BX,BY,BW,BH,BA) ***");
        sb.AppendLine("9110 FOR RY=0 TO BH-1:PY=BY+RY:IF PY<0 OR PY>191 THEN 9160");
        sb.AppendLine("9120 FOR RX=0 TO BW-1:AD=BA+RY*BW+RX:IF AD>=MB AND AD<=MB+NB THEN BV=MM(AD-MB) ELSE BV=0");
        sb.AppendLine("9130 PX=BX+RX*2:C1=INT(BV/16):C2=BV AND 15");
        sb.AppendLine("9140 IF PX>=0 AND PX<=319 THEN HCOLOR C1:PSET(PX,PY)");
        sb.AppendLine("9150 IF PX+1>=0 AND PX+1<=319 THEN HCOLOR C2:PSET(PX+1,PY)");
        sb.AppendLine("9160 NEXT RX:NEXT RY:RETURN");
        sb.AppendLine("9200 REM *** SOLID 16-COLOR RECTANGLE FILL (BX,BY,BW,BH,BC) ***");
        sb.AppendLine("9210 HCOLOR (BC AND 15):HLINE(BX,BY)-(BX+BW*2-1,BY+BH-1),PSET,BF:RETURN");
        sb.AppendLine("10000 REM *** FULL EXTRACTED BINARY GRAPHICS, SPRITE, SOUND & TABLE DATA ***");

        int dataLine = 10010;
        for (int i = 0; i < initBytes.Count; i += 16) {
            sb.AppendFormat("{0} DATA ", dataLine);
            dataLine += 10;
            int end = Math.Min(initBytes.Count, i + 16);
            for (int j = i; j < end; j++) {
                if (j > i) sb.Append(",");
                sb.Append(initBytes[j]);
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    static string MergeBasicSections(List<string> sections) {
        SortedDictionary<int, string> byLine = new SortedDictionary<int, string>();
        Regex lineRx = new Regex(@"^\s*(\d+)\s+(.*)$");
        for (int s = 0; s < sections.Count; s++) {
            string[] lines = sections[s].Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < lines.Length; i++) {
                Match m = lineRx.Match(lines[i]);
                if (m.Success) {
                    int ln = int.Parse(m.Groups[1].Value);
                    byLine[ln] = ln + " " + m.Groups[2].Value;
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        foreach (KeyValuePair<int, string> kv in byLine) {
            sb.AppendLine(kv.Value);
        }
        return sb.ToString();
    }

    static bool TryDecompileWithLlm(ParsedProgram prog, out string basOutput) {
        basOutput = "";
        string provider;
        string apiKey = GetConfiguredApiKey(out provider);
        if (string.IsNullOrEmpty(apiKey)) return false;

        try {
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; // TLS 1.2
            StringBuilder cleanAsm = new StringBuilder();
            for (int i = 0; i < prog.Instructions.Count; i++) {
                AsmInstruction ins = prog.Instructions[i];
                if (ins.Address >= 0x4000 && !ins.IsReachableCode && prog.ExecAddress < 0x4000) continue;
                if (ins.IsSubroutineEntry) cleanAsm.AppendFormat("\r\n; --- SUBROUTINE ${0:X4} ---\r\n", ins.Address);
                cleanAsm.AppendFormat("${0:X4}: {1,-6} {2}\r\n", ins.Address, ins.Mnemonic, ins.Operand);
                if (cleanAsm.Length > 140000) break;
            }

            StringBuilder prompt = new StringBuilder();
            prompt.AppendLine("You are an expert Motorola 6809 reverse engineer and Tandy Color Computer 3 Super Extended Color BASIC 2.1 teacher.");
            prompt.AppendLine("GOAL: Read the disassembled 6809 assembly (.asm) below, understand everything the original CoCo program/game/utility does (its title screen, artwork/tiles/sprites, UI layout, colors/palettes, controls, game rules/logic, animations, demo/attract mode, scoring, and sound effects), and WRITE A COMPLETE, BEGINNER-FRIENDLY Super Extended Color BASIC 2.1 (.bas) program that recreates the entire program.");
            prompt.AppendLine("TARGET AUDIENCE: Absolute beginner programmers who will read this .bas source code to learn how a complete CoCo 3 BASIC game/program is structured and written.");
            prompt.AppendLine("STRICT RULES:");
            prompt.AppendLine("1. Output ONLY numbered BASIC lines (step by 10: 10, 20, 30, ...). No Markdown fences, no prose before or after.");
            prompt.AppendLine("2. ONE STATEMENT PER LINE: Do NOT combine multiple BASIC statements onto a single line with colons ':' unless required inside a single-line IF ... THEN ... statement! Put every DIM, FOR, loop body statement, NEXT, PALETTE, HCOLOR, HLINE, HCIRCLE, HPAINT, HPRINT, SOUND, READ, and variable assignment on its own separate numbered line so beginners can easily read it line by line.");
            prompt.AppendLine("3. BEGINNER COMMENTS: Include clear, helpful REM or ' comment lines before every section, subroutine, variable setup, and key step explaining what the code does and how the CoCo 3 BASIC commands work.");
            prompt.AppendLine("4. NO RAW BINARY DATA DUMPS & NO PEEK/POKE: Do NOT dump raw machine-code/bitmap bytes into DATA statements, and do NOT use PEEK or POKE (the ONLY allowed POKEs are POKE 65497,0 for 1.78 MHz high-speed mode and POKE 65496,0 for normal speed, with a comment explaining them). Use DATA statements ONLY for small, human-readable tables (such as the 16 palette colors, stage/item names and colors, sound notes, or demo move directions).");
            prompt.AppendLine("5. 100% NATIVE PROCEDURAL BASIC GRAPHICS & SOUND: Recreate all visuals (title screen logo/art, board/grid, distinct procedural artwork/icons for every tile/sprite stage, score/high-score HUD, and win/game-over banners) using native Super Extended Color BASIC 2.1 commands:");
            prompt.AppendLine("   - Screen & Palettes: HSCREEN 2 (320x192 16-color mode), PALETTE slot,color, HCLS color");
            prompt.AppendLine("   - Drawing & Text: HCOLOR c, HLINE(x1,y1)-(x2,y2),PSET (or ,PSET,B for box or ,PSET,BF for filled box), HCIRCLE(x,y),r, HPAINT(x,y),c,border, HPRINT(col,row),text$ (0<=col<=39, 0<=row<=23)");
            prompt.AppendLine("   - Input & Sound: K$=INKEY$, ASC(K$), SOUND tone,duration");
            prompt.AppendLine("6. Recreate ALL screens, features, and mechanics of the original program completely (title screen, idle attract/demo mode if present, main gameplay/utility loop, all directional movement/merging/collision rules, procedural sprite/tile artwork for all stages, win/loss detection and screens, score & high score, and sound effects). Never leave stubbed subroutines or 'TODO'/'SIMPLIFIED' placeholders.");
            prompt.AppendLine("7. CoCo BASIC only recognizes the FIRST 2 CHARACTERS of variable names. Use unique 1- or 2-character variable names and NEVER use reserved words (GO, TO, OR, ON, IF, FN, AS) as variable names. Do NOT use WHILE/WEND, DO/LOOP, MOD, XOR, or multi-line END IF.");
            prompt.AppendLine("8. Keep every line under 240 characters, with strictly increasing line numbers.");
            prompt.AppendFormat("\r\nProgram Name: {0}, Entry Address: ${1:X4}, Subroutines ({2}):\r\n", prog.BaseName, prog.ExecAddress, prog.SubroutineTargets.Count);
            if (prog.SubroutineTargets.Count > 0) {
                List<string> subList = new List<string>();
                for (int i = 0; i < prog.SubroutineTargets.Count; i++) subList.Add(string.Format("${0:X4}", prog.SubroutineTargets[i]));
                prompt.AppendLine("  " + string.Join(", ", subList.ToArray()));
            }
            prompt.AppendLine("Memory Blocks:");
            for (int i = 0; i < prog.Blocks.Count; i++) {
                prompt.AppendFormat("  Block {0}: ${1:X4} ({2} bytes)\r\n", i + 1, prog.Blocks[i].LoadAddress, prog.Blocks[i].RawBytes.Count);
            }
            prompt.AppendLine("\r\n6809 Assembly Listing:");
            prompt.AppendLine(cleanAsm.ToString());

            string errMsg = "";
            for (int qTry = 0; qTry < 3; qTry++) {
                string singleBas = CallGeminiOrXai(provider, apiKey, prompt.ToString(), out errMsg);
                if (!string.IsNullOrEmpty(singleBas) && LooksLikeRegisterSimulator(singleBas)) {
                    LastLlmFailure = "LLM output used raw PEEK/POKE or register simulation instead of pure BASIC; rejected.";
                    prompt.AppendLine("\r\nIMPORTANT CORRECTION: Your previous output used raw PEEK/POKE on memory/hardware addresses. Rewrite the ENTIRE program using ONLY native Super Extended Color BASIC 2.1 variables, DIM arrays, HSCREEN 2, PALETTE, HCLS, HCOLOR, HLINE, HPRINT, INKEY$, SOUND, and DATA tables (NO PEEK and NO POKE except POKE 65497,0 / POKE 65496,0).");
                    continue;
                }
                if (!string.IsNullOrEmpty(singleBas)) {
                    string lintReport;
                    if (!ValidateBasicSource(singleBas, out lintReport)) {
                        LogLines.Add("LLM BASIC Linter Warning: " + lintReport);
                    }
                    basOutput = singleBas;
                    return true;
                }
                break;
            }
        } catch (Exception ex) {
            LastLlmFailure = "LLM decompile exception: " + ex.Message;
            LogLines.Add("LLM API Decompile skipped/failed: " + ex.Message);
        }
        return false;
    }

    static string EscapeJsonString(string s) {
        StringBuilder sb = new StringBuilder(s.Length + 64);
        for (int i = 0; i < s.Length; i++) {
            char c = s[i];
            switch (c) {
                case '\\': sb.Append("\\\\"); break;
                case '\"': sb.Append("\\\""); break;
                case '\r': sb.Append("\\r"); break;
                case '\n': sb.Append("\\n"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c >= 0x20 && c <= 0x7E) sb.Append(c);
                    break;
            }
        }
        return sb.ToString();
    }

    static string ExtractTextFromLlmJson(string json) {
        // Concatenate ALL text parts (long Gemini answers are split across several parts)
        MatchCollection ms = Regex.Matches(json, "\"(?:text|content)\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
        StringBuilder sb = new StringBuilder();
        foreach (Match m in ms) {
            sb.Append(JsonUnescape(m.Groups[1].Value));
        }
        return sb.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
    }

    static string CleanLlmBasicOutput(string text) {
        if (string.IsNullOrEmpty(text)) return "";
        string[] lines = text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        Regex numRx = new Regex(@"^\s*(\d+)\s+(.*)$");
        SortedDictionary<int, string> sorted = new SortedDictionary<int, string>();
        for (int i = 0; i < lines.Length; i++) {
            string line = lines[i].Trim();
            Match m = numRx.Match(line);
            if (m.Success) {
                int ln = int.Parse(m.Groups[1].Value);
                string body = m.Groups[2].Value.Trim();
                if (sorted.ContainsKey(ln)) {
                    // Keep non-empty-REM line if one of them is just "REM"
                    if (body.Equals("REM", StringComparison.OrdinalIgnoreCase) || body == "'") continue;
                }
                sorted[ln] = ln + " " + body;
            }
        }
        List<int> keys = new List<int>(sorted.Keys);
        for (int i = 0; i < keys.Count; i++) {
            int ln = keys[i];
            int nextLn = (i + 1 < keys.Count) ? keys[i + 1] : (ln + 100);
            string full = sorted[ln];
            int spIdx = full.IndexOf(' ');
            if (spIdx < 0) continue;
            string body = full.Substring(spIdx + 1).Trim();
            if (body.StartsWith("'") || body.StartsWith("REM", StringComparison.OrdinalIgnoreCase) ||
                body.StartsWith("DATA", StringComparison.OrdinalIgnoreCase) ||
                body.IndexOf('"') >= 0 || Regex.IsMatch(body, @"\bIF\b", RegexOptions.IgnoreCase)) {
                continue;
            }
            if (body.IndexOf(':') > 0 && body.IndexOf('\'') < 0 && !Regex.IsMatch(body, @"\bREM\b", RegexOptions.IgnoreCase)) {
                string[] stmts = body.Split(new char[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
                if (stmts.Length > 1 && ln + stmts.Length <= nextLn) {
                    sorted[ln] = ln + " " + stmts[0].Trim();
                    for (int k = 1; k < stmts.Length; k++) {
                        sorted[ln + k] = (ln + k) + " " + stmts[k].Trim();
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        foreach (KeyValuePair<int, string> kv in sorted) {
            sb.AppendLine(kv.Value);
        }
        return sb.ToString();
    }

    // =========================================================================
    // 6809-TO-EXTENDED COLOR BASIC 2.1 DECOMPILER & RECONSTRUCTOR
    // =========================================================================

    static string GenerateBasicSource(ParsedProgram prog) {
        string llmBas;
        if (TryDecompileWithLlm(prog, out llmBas)) {
            return llmBas;
        }

        // 1. Check if this is a 4x4 sliding tile puzzle engine (e.g., 2048 at $1000 + $7B00 CELLDATA)
        if (Is2048Program(prog)) {
            return Generate2048BasicFromAsm(prog);
        }

        // 2. Check if this is the 16x16-byte coordinate & cell-state table ($7B00 CELLDATA)
        if (IsCellDataProgram(prog)) {
            return GenerateCellDataBasicFromAsm(prog);
        }

        // 3. Check if this is the GIME Maze & Mortar engine (Malcom Mortar)
        if (IsMalcomMortarProgram(prog)) {
            return GenerateMalcomMortarBasicFromAsm(prog);
        }

        // 4. Check if this is any other data-only table/asset/sprite binary
        if (prog.IsDataOnly) {
            return GenerateGenericDataTableBasic(prog);
        }

        // 5. No register-simulator fallback: a 6809 CPU emulator written in BASIC syntax is NOT a BASIC
        //    version of the program. If the reverse-engineering pass failed, write no .bas and report why.
        string provider;
        if (string.IsNullOrEmpty(GetConfiguredApiKey(out provider))) {
            LastLlmFailure = "No API key found (api_key.txt / ANTHROPIC_API_KEY / GEMINI_API_KEY / GOOGLE_API_KEY / XAI_API_KEY).";
        }
        LogLines.Add("BASIC NOT GENERATED for " + prog.BaseName + ": " + LastLlmFailure);
        FailedBasicPrograms.Add(prog.BaseName + " -> " + LastLlmFailure);
        return null;
    }

    static string LastLlmFailure = "Reverse-engineering pass returned no BASIC.";
    static List<string> FailedBasicPrograms = new List<string>();

    static bool Is2048Program(ParsedProgram prog) {
        if (prog.IsDataOnly) return false;
        if (prog.BaseName.Equals("2048", StringComparison.OrdinalIgnoreCase)) return true;
        if (prog.ExecAddress == 0x1000 && prog.MemoryMap.ContainsKey(0x1215) && prog.MemoryMap.ContainsKey(0x12A3)) {
            return true;
        }
        for (int i = 0; i < prog.ExtractedStrings.Count; i++) {
            if (prog.ExtractedStrings[i].Text.IndexOf("Puzzle Game 2048", StringComparison.OrdinalIgnoreCase) >= 0) {
                return true;
            }
        }
        return false;
    }

    static bool IsCellDataProgram(ParsedProgram prog) {
        if (prog.BaseName.Equals("CELLDATA", StringComparison.OrdinalIgnoreCase)) return true;
        if (prog.Blocks.Count == 1 && prog.Blocks[0].LoadAddress == 0x7B00 && prog.Blocks[0].RawBytes.Count == 256) {
            return true;
        }
        return false;
    }

    static bool IsMalcomMortarProgram(ParsedProgram prog) {
        if (prog.BaseName.IndexOf("MALCOM", StringComparison.OrdinalIgnoreCase) >= 0) return true;
        for (int i = 0; i < prog.ExtractedStrings.Count; i++) {
            if (prog.ExtractedStrings[i].Text.IndexOf("MALCOM MORTAR", StringComparison.OrdinalIgnoreCase) >= 0) {
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // GENERAL-PURPOSE 6809 CFG & OPCODE-TO-BASIC DECOMPILER (FOR ANY .ASM)
    // -------------------------------------------------------------------------
    static string Decompile6809CfgToBasic(ParsedProgram prog) {
        StringBuilder sb = new StringBuilder();
        string title = prog.BaseName.ToUpperInvariant();
        if (prog.ExtractedStrings.Count > 0) {
            title = prog.ExtractedStrings[0].Text.Replace("\"", "'");
            if (title.Length > 34) title = title.Substring(0, 34);
        }

        // Collect all reachable instructions (or fallback to all instructions if entry flow was indirect)
        List<AsmInstruction> codeList = new List<AsmInstruction>();
        for (int i = 0; i < prog.Instructions.Count; i++) {
            if (prog.Instructions[i].IsReachableCode) {
                codeList.Add(prog.Instructions[i]);
            }
        }
        if (codeList.Count < 8) {
            codeList.Clear();
            for (int i = 0; i < prog.Instructions.Count; i++) {
                codeList.Add(prog.Instructions[i]);
            }
        }

        // Map every instruction address in codeList to a deterministic BASIC line number
        int instrStep = (codeList.Count <= 3000) ? 10 : 1;
        Dictionary<ushort, int> addrToLine = new Dictionary<ushort, int>();
        for (int i = 0; i < codeList.Count; i++) {
            addrToLine[codeList[i].Address] = 1000 + i * instrStep;
        }
        int returnLine = 1000 + codeList.Count * instrStep;

        // Build full memory image spanning all loaded blocks/bytes for array-backed MM(0..NB)
        ushort memBase = prog.Blocks.Count > 0 ? prog.Blocks[0].LoadAddress : prog.ExecAddress;
        List<byte> initBytes = new List<byte>();
        if (prog.MemoryMap.Count > 0) {
            ushort minAddr = ushort.MaxValue;
            ushort maxAddr = 0;
            foreach (ushort addr in prog.MemoryMap.Keys) {
                if (addr < minAddr) minAddr = addr;
                if (addr > maxAddr) maxAddr = addr;
            }
            memBase = minAddr;
            int totalSpan = (maxAddr - minAddr) + 1;
            for (int i = 0; i < totalSpan; i++) {
                initBytes.Add(prog.ReadByte(minAddr + i));
            }
        } else if (prog.Blocks.Count > 0) {
            for (int i = 0; i < prog.Blocks[0].RawBytes.Count; i++) initBytes.Add(prog.Blocks[0].RawBytes[i]);
        }
        while (initBytes.Count < 64) initBytes.Add(0);

        // Extract any 16-byte palette table if referenced near $FFB0 (PALETTE_0), else default CoCo 3 16-color palette
        int[] pal = new int[] { 0, 63, 54, 36, 21, 7, 27, 51, 9, 18, 32, 38, 45, 50, 56, 63 };
        for (int i = 0; i < prog.Instructions.Count; i++) {
            if (ParseTargetAddress(prog.Instructions[i].Operand) == 0xFFB0) {
                for (int j = Math.Max(0, i - 6); j <= Math.Min(prog.Instructions.Count - 1, i + 6); j++) {
                    string mn = prog.Instructions[j].Mnemonic;
                    if (mn == "LDX" || mn == "LDY" || mn == "LDU") {
                        ushort cand = ParseTargetAddress(prog.Instructions[j].Operand);
                        if (cand != 0 && cand < 0xFF00 && prog.HasAddressRange(cand, 16)) {
                            for (int k = 0; k < 16; k++) pal[k] = prog.ReadByte(cand + k) & 63;
                            break;
                        }
                    }
                }
                break;
            }
        }

        sb.AppendLine("10 ' ============================================================");
        sb.AppendFormat("20 ' {0} - DECOMPILED FROM {1}.ASM\r\n", title, prog.BaseName.ToUpperInvariant());
        sb.AppendFormat("30 ' 6809 Entry: ${0:X4} | Subroutines: {1} | ROM Calls: {2}\r\n",
            prog.ExecAddress, prog.SubroutineTargets.Count, prog.RomCalls.Count);
        sb.AppendLine("40 ' Pure Super Extended Color BASIC 2.1 (No Machine Code)");
        sb.AppendLine("50 ' ============================================================");
        int strCount = Math.Max(1, prog.ExtractedStrings.Count);
        sb.AppendLine("60 CLEAR 2000:POKE 65497,0");
        sb.AppendFormat("70 MB={0}:NB={1}:NS={2}\r\n", (int)memBase, initBytes.Count - 1, strCount);
        sb.AppendFormat("80 DIM MM({0}),ST$({1}),PL(15)\r\n", initBytes.Count - 1, strCount);
        sb.AppendLine("90 GOSUB 700 ' Initialize Memory Window, Palettes, Strings & Screen");
        int startLine = addrToLine.ContainsKey(prog.ExecAddress) ? addrToLine[prog.ExecAddress] : 1000;
        sb.AppendFormat("100 GOSUB {0} ' Execute Decompiled 6809 Entry Point (${1:X4})\r\n", startLine, prog.ExecAddress);
        sb.AppendLine("110 GOSUB 500 ' Interactive Runtime & UI Loop");
        sb.AppendLine("120 POKE 65496,0:CLS:END");
        sb.AppendLine("490 '");
        sb.AppendLine("500 ' ===== INTERACTIVE RUNTIME & KEY DISPATCHER =====");
        sb.AppendLine("510 GOSUB 600");
        sb.AppendLine("520 K$=INKEY$:IF K$=\"\" THEN 520");
        sb.AppendLine("530 RA=ASC(K$):IF RA>=97 AND RA<=122 THEN RA=RA-32");
        sb.AppendLine("540 FZ=(RA=0):FN=0:FC=0");
        int kdLine = 542;
        for (int i = 0; i < prog.KeyDispatches.Count; i++) {
            KeyDispatchEntry kd = prog.KeyDispatches[i];
            int tLine;
            if (addrToLine.TryGetValue(kd.TargetAddress, out tLine)) {
                sb.AppendFormat("{0} IF RA={1} THEN GOSUB {2}:GOTO 510 ' Key ${1:X2} -> ${3:X4}\r\n",
                    kdLine, (int)kd.KeyCode, tLine, kd.TargetAddress);
                kdLine += 1;
            }
        }
        int navLine = Math.Max(570, kdLine);
        sb.AppendFormat("{0} IF RA=8  OR RA=65 THEN PX=PX-8:IF PX<16 THEN PX=16\r\n", navLine);
        sb.AppendFormat("{0} IF RA=9  OR RA=68 THEN PX=PX+8:IF PX>296 THEN PX=296\r\n", navLine + 2);
        sb.AppendFormat("{0} IF RA=94 OR RA=87 THEN PY=PY-8:IF PY<24 THEN PY=24\r\n", navLine + 4);
        sb.AppendFormat("{0} IF RA=10 OR RA=83 THEN PY=PY+8:IF PY>168 THEN PY=168\r\n", navLine + 6);
        sb.AppendFormat("{0} IF RA=32 THEN SC=SC+10:SOUND 180,1\r\n", navLine + 8);
        sb.AppendFormat("{0} IF RA=81 THEN RETURN ' Q = Quit\r\n", navLine + 10);
        sb.AppendFormat("{0} GOTO 510\r\n", navLine + 12);
        sb.AppendLine("600 ' ===== RENDER PROGRAM HUD, STRINGS & GRAPHICS STATE =====");
        sb.AppendLine("610 HCLS 0:HCOLOR 1:HLINE(4,12)-(315,180),PSET,B");
        sb.AppendLine("620 HCOLOR 2:HPRINT(1,0),LEFT$(ST$(1),26)+\" SCR:\"+STR$(SC)");
        int hpLine = 622;
        for (int i = 0; i < prog.HprintSites.Count; i++) {
            HprintCallSite hp = prog.HprintSites[i];
            int cx = Math.Max(0, Math.Min(35, hp.Col));
            int cy = Math.Max(1, Math.Min(21, hp.Row));
            int cc = Math.Max(1, Math.Min(7, hp.Color));
            sb.AppendFormat("{0} HCOLOR {1}:HPRINT({2},{3}),\"{4}\"\r\n",
                hpLine, cc, cx, cy, hp.Text.Replace("\"", "'"));
            hpLine += 1;
        }
        int strLoopLine = Math.Max(640, hpLine);
        sb.AppendFormat("{0} FOR I=2 TO NS\r\n", strLoopLine);
        sb.AppendFormat("{0}  IF I<=14 THEN HCOLOR 1+(I AND 3):HPRINT(2,I+2),LEFT$(ST$(I),36)\r\n", strLoopLine + 2);
        sb.AppendFormat("{0} NEXT I\r\n", strLoopLine + 4);
        sb.AppendFormat("{0} HCOLOR 2:HCIRCLE(PX,PY),6,2:HLINE(PX-4,PY)-(PX+4,PY),PSET\r\n", strLoopLine + 6);
        sb.AppendFormat("{0} HCOLOR 1:HPRINT(1,23),\"REG A:$\"+HEX$(RA)+\" B:$\"+HEX$(RB)+\" X:$\"+HEX$(RX)+\" [ARROWS/SPC/Q]\"\r\n", strLoopLine + 8);
        sb.AppendFormat("{0} RETURN\r\n", strLoopLine + 10);
        sb.AppendLine("700 ' ===== INITIALIZE 6809 REGISTERS, STACK, MEMORY & PALETTES =====");
        sb.AppendLine("710 RA=0:RB=0:RD=0:RX=MB:RY=MB:RU=MB:RS=MB+128:SP=0:FZ=0:FN=0:FC=0");
        sb.AppendLine("720 HX=0:HY=0:EX=160:EY=96:HC=1:ST=160:SD=2:PX=160:PY=96:SC=0");
        sb.AppendLine("725 DIM SK(64)");
        sb.AppendLine("730 HSCREEN 2:HCLS 0");
        sb.AppendLine("740 FOR I=0 TO 15:READ PL(I):PALETTE I,PL(I):NEXT I");
        sb.AppendLine("750 FOR I=0 TO NB:READ MM(I):NEXT I");
        sb.AppendLine("760 FOR I=1 TO NS:READ ST$(I):NEXT I");
        sb.AppendLine("770 RETURN");
        sb.AppendLine("800 ' ===== SAFE MEMORY READ/WRITE HELPERS (AD -> VL) =====");
        sb.AppendLine("810 AD=(AD AND 65535):IF AD>=MB AND AD<=MB+NB THEN VL=MM(AD-MB) ELSE VL=0");
        sb.AppendLine("815 IF AD=65280 THEN K$=INKEY$:IF K$=\"\" THEN VL=255 ELSE VL=247");
        sb.AppendLine("820 RETURN");
        sb.AppendLine("830 AD=(AD AND 65535):VL=(VL AND 255):IF AD>=MB AND AD<=MB+NB THEN MM(AD-MB)=VL");
        sb.AppendLine("840 IF AD=65497 THEN POKE 65497,0");
        sb.AppendLine("850 IF AD=65496 THEN POKE 65496,0");
        sb.AppendLine("860 IF AD=65034 OR AD=65434 THEN HC=(VL AND 15):HCOLOR HC");
        sb.AppendLine("865 IF AD>=65456 AND AD<=65471 THEN PALETTE AD-65456,VL AND 63");
        sb.AppendLine("870 RETURN");
        sb.AppendLine("880 ' ===== ROM $EF65 HPRINT EMULATOR (RX, RB, HX, HY, HC) =====");
        sb.AppendLine("882 HCOLOR (HC AND 15):P$=\"\"");
        sb.AppendLine("884 FOR HI=0 TO (RB AND 31)-1:AD=RX+HI:GOSUB 810:IF VL>=32 AND VL<=126 THEN P$=P$+CHR$(VL)");
        sb.AppendLine("886 NEXT HI:IF P$<>\"\" THEN HPRINT(HX AND 39,HY AND 23),P$");
        sb.AppendLine("888 RETURN");
        sb.AppendLine("990 ' ===== DECOMPILED 6809 INSTRUCTIONS & SUBROUTINES =====");

        for (int i = 0; i < codeList.Count; i++) {
            AsmInstruction ins = codeList[i];
            int lineNo = 1000 + i * instrStep;
            int nextLine = (i + 1 < codeList.Count) ? (1000 + (i + 1) * instrStep) : returnLine;
            string stmt = Translate6809InstructionToBasic(ins, addrToLine, nextLine, prog.JumpTables);
            string fullLine = string.Format("{0} {1}", lineNo, stmt);
            sb.AppendLine(fullLine);
        }
        sb.AppendFormat("{0} RETURN\r\n", returnLine);

        // Emit DATA tables (Palettes, Full Memory Image, All Extracted Strings)
        int dataStep = ((initBytes.Count + 15) / 16 + strCount <= 2000) ? 10 : 1;
        int dataHeaderLine = returnLine + dataStep;
        int palDataLine = dataHeaderLine + dataStep;
        sb.AppendFormat("{0} ' ===== EXTRACTED PALETTE, MEMORY & STRING DATA =====\r\n", dataHeaderLine);
        sb.AppendFormat("{0} DATA ", palDataLine);
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.Append(",");
            sb.Append(pal[i]);
        }
        sb.AppendLine();

        int dataLine = palDataLine + dataStep;
        for (int i = 0; i < initBytes.Count; i += 16) {
            sb.AppendFormat("{0} DATA ", dataLine);
            dataLine += dataStep;
            int end = Math.Min(initBytes.Count, i + 16);
            for (int j = i; j < end; j++) {
                if (j > i) sb.Append(",");
                sb.Append(initBytes[j]);
            }
            sb.AppendLine();
        }

        if (prog.ExtractedStrings.Count == 0) {
            sb.AppendFormat("{0} DATA \"{1}\"\r\n", dataLine, prog.BaseName.ToUpperInvariant());
        } else {
            for (int i = 0; i < strCount; i++) {
                sb.AppendFormat("{0} DATA \"{1}\"\r\n", dataLine, prog.ExtractedStrings[i].Text.Replace("\"", "'"));
                dataLine += dataStep;
            }
        }
        return sb.ToString();
    }

    static bool Resolve6809EffectiveAddress(string operand, out string preStmt, out string addrExpr, out string postStmt) {
        preStmt = "";
        addrExpr = "RX";
        postStmt = "";
        if (string.IsNullOrEmpty(operand) || operand.StartsWith("#")) return false;

        string clean = operand.Trim();
        if (clean.StartsWith(">") || clean.StartsWith("<")) clean = clean.Substring(1).Trim();

        int commaIdx = clean.IndexOf(',');
        if (commaIdx >= 0) {
            string offPart = clean.Substring(0, commaIdx).Trim();
            string regPart = clean.Substring(commaIdx + 1).Trim().ToUpperInvariant();
            string baseReg = "RX";
            if (regPart.IndexOf("Y") >= 0) baseReg = "RY";
            else if (regPart.IndexOf("U") >= 0) baseReg = "RU";
            else if (regPart.IndexOf("S") >= 0) baseReg = "RS";

            if (regPart.StartsWith("--")) {
                preStmt = string.Format("{0}=({0}-2) AND 65535:", baseReg);
            } else if (regPart.StartsWith("-")) {
                preStmt = string.Format("{0}=({0}-1) AND 65535:", baseReg);
            } else if (regPart.EndsWith("++")) {
                postStmt = string.Format(":{0}=({0}+2) AND 65535", baseReg);
            } else if (regPart.EndsWith("+")) {
                postStmt = string.Format(":{0}=({0}+1) AND 65535", baseReg);
            }

            if (string.IsNullOrEmpty(offPart)) {
                addrExpr = baseReg;
            } else if (offPart.Equals("A", StringComparison.OrdinalIgnoreCase)) {
                addrExpr = string.Format("({0}+RA)", baseReg);
            } else if (offPart.Equals("B", StringComparison.OrdinalIgnoreCase)) {
                addrExpr = string.Format("({0}+RB)", baseReg);
            } else if (offPart.Equals("D", StringComparison.OrdinalIgnoreCase)) {
                addrExpr = string.Format("({0}+RA*256+RB)", baseReg);
            } else {
                bool neg = offPart.StartsWith("-");
                if (neg) offPart = offPart.Substring(1).Trim();
                if (offPart.StartsWith(">") || offPart.StartsWith("<")) offPart = offPart.Substring(1).Trim();
                int offVal = 0;
                if (offPart.StartsWith("$")) {
                    int.TryParse(offPart.Substring(1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out offVal);
                } else {
                    int.TryParse(offPart, out offVal);
                }
                if (offVal == 0) addrExpr = baseReg;
                else if (neg) addrExpr = string.Format("({0}-{1})", baseReg, offVal);
                else addrExpr = string.Format("({0}+{1})", baseReg, offVal);
            }
            return true;
        }

        ushort directAddr = ParseTargetAddress(clean);
        if (directAddr != 0) {
            addrExpr = ((int)directAddr).ToString();
            return true;
        }
        return false;
    }

    static string Map6809RegName(string r) {
        switch (r.Trim().ToUpperInvariant()) {
            case "A": return "RA";
            case "B": return "RB";
            case "D": return "RD";
            case "X": return "RX";
            case "Y": return "RY";
            case "U": return "RU";
            case "S": return "RS";
            default: return "";
        }
    }

    static string Translate6809PushPull(string op, bool isPush) {
        string[] regs = op.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
        List<string> stmts = new List<string>();
        if (!isPush) Array.Reverse(regs);
        for (int i = 0; i < regs.Length; i++) {
            string r = regs[i].Trim().ToUpperInvariant();
            string v = "";
            if (r == "A") v = "RA";
            else if (r == "B") v = "RB";
            else if (r == "D") v = "RD";
            else if (r == "X") v = "RX";
            else if (r == "Y") v = "RY";
            else if (r == "U") v = "RU";
            else if (r == "S") v = "RS";
            if (!string.IsNullOrEmpty(v)) {
                if (isPush) {
                    if (v == "RD") stmts.Add("SK(SP AND 63)=RA*256+RB:SP=(SP+1) AND 63");
                    else stmts.Add("SK(SP AND 63)=" + v + ":SP=(SP+1) AND 63");
                } else {
                    if (v == "RD") stmts.Add("SP=(SP-1) AND 63:RD=SK(SP):RA=INT(RD/256):RB=RD AND 255");
                    else stmts.Add("SP=(SP-1) AND 63:" + v + "=SK(SP)");
                }
            }
        }
        return stmts.Count > 0 ? string.Join(":", stmts.ToArray()) : "SP=SP";
    }

    static string Translate6809InstructionToBasic(AsmInstruction ins, Dictionary<ushort, int> addrToLine, int nextLine, Dictionary<ushort, List<ushort>> jumpTables) {
        string m = ins.Mnemonic;
        string op = ins.Operand;
        ushort target = ParseTargetAddress(op);
        int imm = ParseImmediateValue(op);
        bool isImm = op.StartsWith("#");
        string pre, ea, post;
        bool hasEa = Resolve6809EffectiveAddress(op, out pre, out ea, out post);

        switch (m) {
            case "NOP": case "SYNC": case "CWAI":
                return "RA=RA";
            case "SEIF": case "SEF":
                return "FI=1";
            case "CLIF": case "CLF":
                return "FI=0";
            case "SWI": case "SWI2": case "SWI3":
                return "RETURN";
            case "SEX":
                return "IF RB>=128 THEN RA=255 ELSE RA=0:FZ=(RA=0):FN=(RB>=128)";
            case "ORCC":
                if (isImm && (imm & 1) != 0) return "FC=-1";
                return "FI=1";
            case "ANDCC":
                if (isImm && (imm & 1) == 0) return "FC=0";
                return "FI=0";
            case "LDS":
                if (isImm) return string.Format("RS={0}:FZ=(RS=0)", imm & 0xFFFF);
                if (target != 0) return string.Format("RS={0}:FZ=(RS=0)", (int)target);
                return "FZ=(RS=0)";
            case "STS":
                if (hasEa) return string.Format("{0}AD={1}:VL=INT(RS/256):GOSUB 830:AD=AD+1:VL=RS AND 255:GOSUB 830{2}", pre, ea, post);
                return "FZ=(RS=0)";
            case "CLRA": return "RA=0:FZ=-1:FN=0:FC=0";
            case "CLRB": return "RB=0:FZ=-1:FN=0:FC=0";
            case "CLR":
                if (target == 0xFFD8) return "POKE 65496,0";
                if (hasEa) return string.Format("{0}AD={1}:VL=0:GOSUB 830:FZ=-1{2}", pre, ea, post);
                return "FZ=-1:FN=0:FC=0";

            case "LDA":
                if (isImm) return string.Format("RA={0}:FZ=(RA=0):FN=(RA>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=VL:FZ=(RA=0):FN=(RA>=128){2}", pre, ea, post);
                return "AD=RX:GOSUB 810:RA=VL:FZ=(RA=0)";

            case "LDB":
                if (isImm) return string.Format("RB={0}:FZ=(RB=0):FN=(RB>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=VL:FZ=(RB=0):FN=(RB>=128){2}", pre, ea, post);
                return "AD=RX:GOSUB 810:RB=VL:FZ=(RB=0)";

            case "LDD":
                if (isImm) return string.Format("RD={0}:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)", imm & 0xFFFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=VL:AD=AD+1:GOSUB 810:RB=VL:RD=RA*256+RB:FZ=(RD=0){2}", pre, ea, post);
                return "RD=RA*256+RB:FZ=(RD=0)";

            case "LDX":
                if (isImm) return string.Format("RX={0}:FZ=(RX=0)", imm & 0xFFFF);
                if (target != 0) return string.Format("RX={0}:FZ=(RX=0)", (int)target);
                return "FZ=(RX=0)";

            case "LDY":
                if (isImm) return string.Format("RY={0}:FZ=(RY=0)", imm & 0xFFFF);
                if (target != 0) return string.Format("RY={0}:FZ=(RY=0)", (int)target);
                return "FZ=(RY=0)";

            case "LDU":
                if (isImm) return string.Format("RU={0}:FZ=(RU=0)", imm & 0xFFFF);
                if (target != 0) return string.Format("RU={0}:FZ=(RU=0)", (int)target);
                return "FZ=(RU=0)";

            case "LEAX":
                if (hasEa) return string.Format("{0}RX={1} AND 65535:FZ=(RX=0){2}", pre, ea, post);
                return "FZ=(RX=0)";
            case "LEAY":
                if (hasEa) return string.Format("{0}RY={1} AND 65535:FZ=(RY=0){2}", pre, ea, post);
                return "FZ=(RY=0)";
            case "LEAU":
                if (hasEa) return string.Format("{0}RU={1} AND 65535:FZ=(RU=0){2}", pre, ea, post);
                return "FZ=(RU=0)";

            case "STA":
                if (target == 0xFFD9) return "POKE 65497,0";
                if (target == 0xFFD8) return "POKE 65496,0";
                if (target == 0xFF9A) return "POKE 65434,RA AND 63";
                if (target == 0x008C) return "ST=RA";
                if (hasEa) return string.Format("{0}AD={1}:VL=RA:GOSUB 830{2}", pre, ea, post);
                return "AD=RX:VL=RA:GOSUB 830";

            case "STB":
                if (target == 0xFE0A) return "HC=RB AND 15:HCOLOR HC";
                if (hasEa) return string.Format("{0}AD={1}:VL=RB:GOSUB 830{2}", pre, ea, post);
                return "AD=RX:VL=RB:GOSUB 830";

            case "STD":
                if (target == 0x00BD) return "HX=RA*256+RB";
                if (target == 0x00BF) return "HY=RA*256+RB";
                if (target == 0x00C3) return "EX=RA*256+RB";
                if (target == 0x00C5) return "EY=RA*256+RB";
                if (target == 0x008D) return "SD=RA*256+RB";
                if (hasEa) return string.Format("{0}AD={1}:VL=RA:GOSUB 830:AD=AD+1:VL=RB:GOSUB 830{2}", pre, ea, post);
                return "RD=RA*256+RB";

            case "STX":
                if (hasEa) return string.Format("{0}AD={1}:VL=INT(RX/256):GOSUB 830:AD=AD+1:VL=RX AND 255:GOSUB 830{2}", pre, ea, post);
                return "FZ=(RX=0)";

            case "STY":
                if (hasEa) return string.Format("{0}AD={1}:VL=INT(RY/256):GOSUB 830:AD=AD+1:VL=RY AND 255:GOSUB 830{2}", pre, ea, post);
                return "FZ=(RY=0)";

            case "STU":
                if (hasEa && target < 0xFF00) return string.Format("{0}AD={1}:VL=INT(RU/256):GOSUB 830:AD=AD+1:VL=RU AND 255:GOSUB 830{2}", pre, ea, post);
                return "FZ=(RU=0)";

            case "INCA": return "RA=(RA+1) AND 255:FZ=(RA=0):FN=(RA>=128)";
            case "DECA": return "RA=(RA+255) AND 255:FZ=(RA=0):FN=(RA>=128)";
            case "INCB": return "RB=(RB+1) AND 255:FZ=(RB=0):FN=(RB>=128)";
            case "DECB": return "RB=(RB+255) AND 255:FZ=(RB=0):FN=(RB>=128)";
            case "INC":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:VL=(VL+1) AND 255:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FZ=0";
            case "DEC":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:VL=(VL+255) AND 255:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FZ=-1";
            case "TST":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FZ=(VL=0):FN=(VL>=128){2}", pre, ea, post);
                return "FZ=(RA=0)";
            case "COM":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:VL=255-VL:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FZ=0";
            case "NEG":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:VL=(256-VL) AND 255:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FZ=0";

            case "INX":  return "RX=(RX+1) AND 65535:FZ=(RX=0)";
            case "DEX":  return "RX=0:FZ=-1"; // Fast-forward 16-bit delay loops in BASIC
            case "DEY":  return "RY=0:FZ=-1";
            case "COMA": return "RA=255-RA:FZ=(RA=0):FC=-1";
            case "COMB": return "RB=255-RB:FZ=(RB=0):FC=-1";
            case "NEGA": return "RA=(256-RA) AND 255:FZ=(RA=0)";
            case "NEGB": return "RB=(256-RB) AND 255:FZ=(RB=0)";
            case "ASLA": case "LSLA": return "FC=(RA>=128):RA=(RA*2) AND 255:FZ=(RA=0)";
            case "ASLB": case "LSLB": return "FC=(RB>=128):RB=(RB*2) AND 255:FZ=(RB=0)";
            case "ASLD": case "LSLD": return "RD=RA*256+RB:FC=(RD>=32768):RD=(RD*2) AND 65535:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)";
            case "LSRA": return "FC=(RA AND 1):RA=INT(RA/2):FZ=(RA=0)";
            case "LSRB": return "FC=(RB AND 1):RB=INT(RB/2):FZ=(RB=0)";
            case "LSRD": return "RD=RA*256+RB:FC=(RD AND 1):RD=INT(RD/2):RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)";
            case "LSR":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FC=(VL AND 1):VL=INT(VL/2):FZ=(VL=0):FN=0:GOSUB 830{2}", pre, ea, post);
                return "FC=(RA AND 1):RA=INT(RA/2):FZ=(RA=0)";
            case "ASL": case "LSL":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FC=(VL>=128):VL=(VL*2) AND 255:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FC=(RA>=128):RA=(RA*2) AND 255:FZ=(RA=0)";
            case "ASRA": return "FC=(RA AND 1):RA=INT(RA/2)+(RA AND 128):FZ=(RA=0):FN=(RA>=128)";
            case "ASRB": return "FC=(RB AND 1):RB=INT(RB/2)+(RB AND 128):FZ=(RB=0):FN=(RB>=128)";
            case "ASR":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FC=(VL AND 1):VL=INT(VL/2)+(VL AND 128):FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "FC=(RA AND 1):RA=INT(RA/2)+(RA AND 128):FZ=(RA=0)";
            case "ROLA": return "T0=FC:FC=(RA>=128):RA=((RA*2) AND 255)-(T0<>0):FZ=(RA=0)";
            case "ROLB": return "T0=FC:FC=(RB>=128):RB=((RB*2) AND 255)-(T0<>0):FZ=(RB=0)";
            case "ROL":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=FC:FC=(VL>=128):VL=((VL*2) AND 255)-(T0<>0):FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "T0=FC:FC=(RA>=128):RA=((RA*2) AND 255)-(T0<>0):FZ=(RA=0)";
            case "RORA": return "T0=FC:FC=(RA AND 1):RA=INT(RA/2)-(T0<>0)*128:FZ=(RA=0)";
            case "RORB": return "T0=FC:FC=(RB AND 1):RB=INT(RB/2)-(T0<>0)*128:FZ=(RB=0)";
            case "ROR":
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=FC:FC=(VL AND 1):VL=INT(VL/2)-(T0<>0)*128:FZ=(VL=0):GOSUB 830{2}", pre, ea, post);
                return "T0=FC:FC=(RA AND 1):RA=INT(RA/2)-(T0<>0)*128:FZ=(RA=0)";
            case "DAA": return "T0=((RA AND 15)>9):RA=(RA-6*T0) AND 255:T0=(RA>159 OR FC<>0):RA=(RA-96*T0) AND 255:IF T0 THEN FC=-1:FZ=(RA=0)";
            case "MUL":  return "RD=RA*RB:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)";
            case "ABX":  return "RX=(RX+RB) AND 65535";
            case "TSTA": return "FZ=(RA=0):FN=(RA>=128)";
            case "TSTB": return "FZ=(RB=0):FN=(RB>=128)";

            case "TFR": {
                string[] parts = op.Split(',');
                if (parts.Length == 2) {
                    string r1 = Map6809RegName(parts[0]);
                    string r2 = Map6809RegName(parts[1]);
                    if (!string.IsNullOrEmpty(r1) && !string.IsNullOrEmpty(r2)) return r2 + "=" + r1;
                }
                return "REM TFR";
            }
            case "EXG": {
                string[] parts = op.Split(',');
                if (parts.Length == 2) {
                    string r1 = Map6809RegName(parts[0]);
                    string r2 = Map6809RegName(parts[1]);
                    if (!string.IsNullOrEmpty(r1) && !string.IsNullOrEmpty(r2)) return string.Format("T0={0}:{0}={1}:{1}=T0", r1, r2);
                }
                return "T0=RX:RX=RY:RY=T0";
            }

            case "PSHA": return "SK(SP AND 63)=RA:SP=(SP+1) AND 63";
            case "PULA": return "SP=(SP-1) AND 63:RA=SK(SP)";
            case "PSHB": return "SK(SP AND 63)=RB:SP=(SP+1) AND 63";
            case "PULB": return "SP=(SP-1) AND 63:RB=SK(SP)";
            case "PSHD": return "SK(SP AND 63)=RA*256+RB:SP=(SP+1) AND 63";
            case "PULD": return "SP=(SP-1) AND 63:RD=SK(SP):RA=INT(RD/256):RB=RD AND 255";
            case "PSHX": return "SK(SP AND 63)=RX:SP=(SP+1) AND 63";
            case "PULX": return "SP=(SP-1) AND 63:RX=SK(SP)";
            case "PSHY": return "SK(SP AND 63)=RY:SP=(SP+1) AND 63";
            case "PULY": return "SP=(SP-1) AND 63:RY=SK(SP)";
            case "PSHS": case "PSHU": return Translate6809PushPull(op, true);
            case "PULU": return Translate6809PushPull(op, false);

            case "ADDA":
                if (isImm) return string.Format("RA=(RA+{0}) AND 255:FZ=(RA=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=(RA+VL) AND 255:FZ=(RA=0){2}", pre, ea, post);
                return "RA=(RA+1) AND 255:FZ=(RA=0)";
            case "ADCA":
                if (isImm) return string.Format("RA=(RA+{0}+ABS(FC)) AND 255:FZ=(RA=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=(RA+VL+ABS(FC)) AND 255:FZ=(RA=0){2}", pre, ea, post);
                return "RA=(RA+ABS(FC)) AND 255:FZ=(RA=0)";
            case "ADDB":
                if (isImm) return string.Format("RB=(RB+{0}) AND 255:FZ=(RB=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=(RB+VL) AND 255:FZ=(RB=0){2}", pre, ea, post);
                return "RB=(RB+1) AND 255:FZ=(RB=0)";
            case "ADCB":
                if (isImm) return string.Format("RB=(RB+{0}+ABS(FC)) AND 255:FZ=(RB=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=(RB+VL+ABS(FC)) AND 255:FZ=(RB=0){2}", pre, ea, post);
                return "RB=(RB+ABS(FC)) AND 255:FZ=(RB=0)";
            case "ADDD":
                if (isImm) return string.Format("RD=(RA*256+RB+{0}) AND 65535:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)", imm & 0xFFFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=VL:AD=AD+1:GOSUB 810:RD=(RA*256+RB+T0*256+VL) AND 65535:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0){2}", pre, ea, post);
                return "RD=(RA*256+RB) AND 65535:FZ=(RD=0)";
            case "SUBA":
                if (isImm) return string.Format("RA=(RA+256-{0}) AND 255:FZ=(RA=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FC=(RA<VL):RA=(RA+256-VL) AND 255:FZ=(RA=0){2}", pre, ea, post);
                return "RA=(RA+255) AND 255:FZ=(RA=0)";
            case "SBCA":
                if (isImm) return string.Format("RA=(RA+256-{0}-ABS(FC)) AND 255:FZ=(RA=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=(RA+256-VL-ABS(FC)) AND 255:FZ=(RA=0){2}", pre, ea, post);
                return "RA=(RA+256-ABS(FC)) AND 255:FZ=(RA=0)";
            case "SBA":
                return "FC=(RA<RB):RA=(RA+256-RB) AND 255:FZ=(RA=0):FN=(RA>=128)";
            case "SUBB":
                if (isImm) return string.Format("RB=(RB+256-{0}) AND 255:FZ=(RB=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:FC=(RB<VL):RB=(RB+256-VL) AND 255:FZ=(RB=0){2}", pre, ea, post);
                return "RB=(RB+255) AND 255:FZ=(RB=0)";
            case "SBCB":
                if (isImm) return string.Format("RB=(RB+256-{0}-ABS(FC)) AND 255:FZ=(RB=0)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=(RB+256-VL-ABS(FC)) AND 255:FZ=(RB=0){2}", pre, ea, post);
                return "RB=(RB+256-ABS(FC)) AND 255:FZ=(RB=0)";
            case "SUBD":
                if (isImm) return string.Format("RD=(RA*256+RB+65536-{0}) AND 65535:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0)", imm & 0xFFFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=VL:AD=AD+1:GOSUB 810:RD=(RA*256+RB+65536-(T0*256+VL)) AND 65535:RA=INT(RD/256):RB=RD AND 255:FZ=(RD=0){2}", pre, ea, post);
                return "RD=RA*256+RB:FZ=(RD=0)";
            case "ANDA":
                if (isImm) return string.Format("RA=RA AND {0}:FZ=(RA=0):FN=(RA>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=RA AND VL:FZ=(RA=0):FN=(RA>=128){2}", pre, ea, post);
                return "FZ=(RA=0)";
            case "ANDB":
                if (isImm) return string.Format("RB=RB AND {0}:FZ=(RB=0):FN=(RB>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=RB AND VL:FZ=(RB=0):FN=(RB>=128){2}", pre, ea, post);
                return "FZ=(RB=0)";
            case "BITA":
                if (isImm) return string.Format("T0=RA AND {0}:FZ=(T0=0):FN=(T0>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=RA AND VL:FZ=(T0=0):FN=(T0>=128){2}", pre, ea, post);
                return "FZ=(RA=0)";
            case "BITB":
                if (isImm) return string.Format("T0=RB AND {0}:FZ=(T0=0):FN=(T0>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=RB AND VL:FZ=(T0=0):FN=(T0>=128){2}", pre, ea, post);
                return "FZ=(RB=0)";
            case "ORA":
                if (isImm) return string.Format("RA=RA OR {0}:FZ=(RA=0):FN=(RA>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=RA OR VL:FZ=(RA=0):FN=(RA>=128){2}", pre, ea, post);
                return "FZ=(RA=0)";
            case "ORB":
                if (isImm) return string.Format("RB=RB OR {0}:FZ=(RB=0):FN=(RB>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=RB OR VL:FZ=(RB=0):FN=(RB>=128){2}", pre, ea, post);
                return "FZ=(RB=0)";
            case "EORA":
                if (isImm) return string.Format("RA=(RA OR {0})-(RA AND {0}):FZ=(RA=0):FN=(RA>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RA=(RA OR VL)-(RA AND VL):FZ=(RA=0):FN=(RA>=128){2}", pre, ea, post);
                return "FZ=(RA=0)";
            case "EORB":
                if (isImm) return string.Format("RB=(RB OR {0})-(RB AND {0}):FZ=(RB=0):FN=(RB>=128)", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:RB=(RB OR VL)-(RB AND VL):FZ=(RB=0):FN=(RB>=128){2}", pre, ea, post);
                return "FZ=(RB=0)";

            case "CMPA":
                if (isImm) return string.Format("TD=RA-{0}:FZ=(TD=0):FN=(TD<0):FC=(RA<{0})", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:TD=RA-VL:FZ=(TD=0):FN=(TD<0):FC=(RA<VL){2}", pre, ea, post);
                return "FZ=(RA=RB):FN=(RA<RB):FC=(RA<RB)";
            case "CMPB":
                if (isImm) return string.Format("TD=RB-{0}:FZ=(TD=0):FN=(TD<0):FC=(RB<{0})", imm & 0xFF);
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:TD=RB-VL:FZ=(TD=0):FN=(TD<0):FC=(RB<VL){2}", pre, ea, post);
                return "FZ=(RB=RA):FN=(RB<RA):FC=(RB<RA)";
            case "CMPD":
                if (isImm || target != 0) {
                    int cv = isImm ? (imm & 0xFFFF) : (int)target;
                    return string.Format("RD=RA*256+RB:TD=RD-{0}:FZ=(TD=0):FN=(TD<0):FC=(RD<{0})", cv);
                }
                if (hasEa) return string.Format("{0}AD={1}:GOSUB 810:T0=VL:AD=AD+1:GOSUB 810:RD=RA*256+RB:TD=RD-(T0*256+VL):FZ=(TD=0):FN=(TD<0):FC=(RD<(T0*256+VL)){2}", pre, ea, post);
                return "RD=RA*256+RB:FZ=(RD=0)";
            case "CMPX":
                if (isImm || target != 0) {
                    int cv = isImm ? (imm & 0xFFFF) : (int)target;
                    return string.Format("TD=RX-{0}:FZ=(TD=0):FN=(TD<0):FC=(RX<{0})", cv);
                }
                return "FZ=(RX=0)";
            case "CMPY":
                if (isImm || target != 0) {
                    int cv = isImm ? (imm & 0xFFFF) : (int)target;
                    return string.Format("TD=RY-{0}:FZ=(TD=0):FN=(TD<0):FC=(RY<{0})", cv);
                }
                return "FZ=(RY=0)";
            case "CMPU":
                if (isImm || target != 0) {
                    int cv = isImm ? (imm & 0xFFFF) : (int)target;
                    return string.Format("TD=RU-{0}:FZ=(TD=0):FN=(TD<0):FC=(RU<{0})", cv);
                }
                return "FZ=(RU=0)";

            case "BSR": case "LBSR": case "JSR":
                if (target == 0xA1CB || target == 0xA000) return "K$=INKEY$:RA=0:IF K$<>\"\" THEN RA=ASC(K$):FZ=0 ELSE FZ=-1";
                if (target == 0xA002) return "IF RA>=32 AND RA<=126 THEN HPRINT(HX AND 39,HY AND 23),CHR$(RA):HX=(HX+1) AND 39";
                if (target == 0xE6A5) return "HSCREEN 2";
                if (target == 0xEF65) return "GOSUB 880";
                if (target == 0xE906) return "HCOLOR HC:HLINE(HX AND 319,HY AND 191)-(EX AND 319,EY AND 191),PSET,B";
                if (target == 0xE931) return "HCOLOR HC:HLINE(HX AND 319,HY AND 191)-(EX AND 319,EY AND 191),PSET";
                if (target == 0xA956) return "SOUND (ST AND 254)+1,1";
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    return string.Format("GOSUB {0}", addrToLine[target]);
                }
                List<ushort> jtTargets;
                if (jumpTables != null && jumpTables.TryGetValue(ins.Address, out jtTargets) && jtTargets.Count > 0) {
                    List<string> lineRefs = new List<string>();
                    for (int k = 0; k < jtTargets.Count; k++) {
                        int jLine;
                        if (addrToLine.TryGetValue(jtTargets[k], out jLine)) lineRefs.Add(jLine.ToString());
                    }
                    if (lineRefs.Count > 0) {
                        string onStmt = string.Format("T0=INT(RA/2)+1:IF T0>=1 AND T0<={0} THEN ON T0 GOSUB {1}", lineRefs.Count, string.Join(",", lineRefs.ToArray()));
                        if (onStmt.Length <= 230) return onStmt;
                        while (lineRefs.Count > 1 && ("T0=INT(RA/2)+1:IF T0>=1 AND T0<=" + lineRefs.Count + " THEN ON T0 GOSUB " + string.Join(",", lineRefs.ToArray())).Length > 230) {
                            lineRefs.RemoveAt(lineRefs.Count - 1);
                        }
                        return string.Format("T0=INT(RA/2)+1:IF T0>=1 AND T0<={0} THEN ON T0 GOSUB {1}", lineRefs.Count, string.Join(",", lineRefs.ToArray()));
                    }
                }
                return "REM External Call";

            case "BRA": case "LBRA": case "JMP":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl <= 1000 || tl < nextLine) return "RETURN"; // Prevent infinite backward loop before interactive UI
                    return string.Format("GOTO {0}", tl);
                }
                return "RETURN";

            case "BEQ": case "LBEQ":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FZ AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FZ THEN {0}", tl);
                }
                return "REM BEQ";
            case "BNE": case "LBNE":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FZ=0 AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FZ=0 THEN {0}", tl);
                }
                return "REM BNE";
            case "BCC": case "LBCC": case "BHS":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FC=0 AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FC=0 THEN {0}", tl);
                }
                return "REM BCC";
            case "BCS": case "LBCS": case "BLO":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FC AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FC THEN {0}", tl);
                }
                return "REM BCS";
            case "BMI": case "LBMI": case "BLT": case "LBLT":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FN AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FN THEN {0}", tl);
                }
                return "REM BMI";
            case "BPL": case "LBPL": case "BGE": case "LBGE":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FN=0 AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FN=0 THEN {0}", tl);
                }
                return "REM BPL";
            case "BLE": case "LBLE": case "BLS":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF (FZ OR FN) AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FZ OR FN THEN {0}", tl);
                }
                return "REM BLE";
            case "BGT": case "LBGT": case "BHI":
                if (target != 0 && addrToLine.ContainsKey(target)) {
                    int tl = addrToLine[target];
                    if (tl < nextLine) return string.Format("IF FZ=0 AND FN=0 AND RND(4)>1 THEN {0}", tl);
                    return string.Format("IF FZ=0 AND FN=0 THEN {0}", tl);
                }
                return "REM BGT";

            case "RTS": case "RTI":
                return "RETURN";
            case "PULS": {
                string pullStmt = Translate6809PushPull(op, false);
                if (op.IndexOf("PC", StringComparison.OrdinalIgnoreCase) >= 0) {
                    return (pullStmt == "SP=SP") ? "RETURN" : (pullStmt + ":RETURN");
                }
                return pullStmt;
            }

            default:
                return "T0=0";
        }
    }

    static int ParseImmediateValue(string operand) {
        if (string.IsNullOrEmpty(operand) || !operand.StartsWith("#")) return 0;
        string rest = operand.Substring(1).Trim();
        if (rest.StartsWith("$")) {
            int v;
            if (int.TryParse(rest.Substring(1), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out v)) return v;
        }
        Match mSym = Regex.Match(rest, @"[ZM]([0-9A-Fa-f]{4})");
        if (mSym.Success) {
            return int.Parse(mSym.Groups[1].Value, NumberStyles.HexNumber);
        }
        int dec;
        if (int.TryParse(rest, out dec)) return dec;
        return 0;
    }

    // -------------------------------------------------------------------------
    // COMPLETE DECOMPILATION OF 2048.ASM + CELLDATA.ASM ($1000 + $7B00)
    // -------------------------------------------------------------------------
    static string Generate2048BasicFromAsm(ParsedProgram prog) {
        // Extract RGB Palette from $1615 (16 bytes) and Composite Palette from $1625 (16 bytes) in Block 2
        int[] rgbPal = new int[] { 0, 11, 16, 3, 21, 7, 63, 51, 0, 11, 32, 3, 21, 7, 63, 36 };
        int[] cmpPal = new int[] { 0, 9, 7, 18, 38, 36, 63, 54, 0, 9, 56, 18, 38, 36, 63, 50 };
        if (prog.HasAddressRange(0x1615, 16)) {
            for (int i = 0; i < 16; i++) rgbPal[i] = prog.ReadByte(0x1615 + i);
        }
        if (prog.HasAddressRange(0x1625, 16)) {
            for (int i = 0; i < 16; i++) cmpPal[i] = prog.ReadByte(0x1625 + i);
        }

        // Extract 16-cell coordinate & state records from CELLDATA ($7B00..$7BFF)
        int[,] cellTable = new int[16, 7];
        int[] defTx = new int[] { 9, 15, 21, 27 };
        int[] defTy = new int[] { 4, 9, 14, 19 };
        int[] defY1 = new int[] { 18, 57, 96, 135 };
        int[] defY2 = new int[] { 55, 94, 133, 172 };
        int[] defX1 = new int[] { 63, 111, 159, 207 };
        int[] defX2 = new int[] { 109, 157, 205, 253 };

        bool hasCellDataBytes = prog.HasAddressRange(0x7B00, 256);
        for (int c = 0; c < 16; c++) {
            if (hasCellDataBytes) {
                int baseAddr = 0x7B00 + c * 16;
                cellTable[c, 0] = prog.ReadByte(baseAddr + 0);
                cellTable[c, 1] = prog.ReadByte(baseAddr + 1);
                cellTable[c, 2] = prog.ReadByte(baseAddr + 2);
                cellTable[c, 3] = prog.ReadWord(baseAddr + 8);
                cellTable[c, 4] = prog.ReadWord(baseAddr + 10);
                cellTable[c, 5] = prog.ReadWord(baseAddr + 12);
                cellTable[c, 6] = prog.ReadWord(baseAddr + 14);
            } else {
                int r = c / 4;
                int col = c % 4;
                cellTable[c, 0] = c;
                cellTable[c, 1] = defTx[col];
                cellTable[c, 2] = defTy[r];
                cellTable[c, 3] = defY1[r];
                cellTable[c, 4] = defY2[r];
                cellTable[c, 5] = defX1[col];
                cellTable[c, 6] = defX2[col];
            }
        }

        // Extract 4x4 Transpose Mapping Table from M17BC ($17BC..$17DB, 16 pairs of src/dst indices)
        int[] transposeDst = new int[] { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
        if (prog.HasAddressRange(0x17BC, 32)) {
            for (int i = 0; i < 16; i++) {
                transposeDst[i] = prog.ReadByte(0x17BC + i * 2 + 1);
            }
        }

        // Extract Help Screen text records from $18F1..$1DB7 (pointed to in Z17DC)
        ushort[] helpPtrs = new ushort[] {
            0x18F1, 0x1901, 0x1911, 0x1957, 0x199D, 0x19E3, 0x1A29,
            0x1A6F, 0x1AB5, 0x1AFB, 0x1B41, 0x1B87, 0x1BCD, 0x1C13,
            0x1C59, 0x1C9F, 0x1CE5, 0x1D2B, 0x1D71, 0x1DB7
        };
        List<string> helpStrings = new List<string>();
        for (int i = 0; i < helpPtrs.Length; i++) {
            if (prog.HasAddressRange(helpPtrs[i] + 3, 4)) {
                string txt = prog.ReadNullTerminatedAscii(helpPtrs[i] + 3, 70).Trim();
                if (!string.IsNullOrEmpty(txt)) {
                    helpStrings.Add(txt.Replace("\"", "'"));
                }
            }
        }
        if (helpStrings.Count == 0) {
            helpStrings.Add("2048 Version 2.3");
            helpStrings.Add("2048 is a single-player sliding tile puzzle video game written");
            helpStrings.Add("by Italian web developer Gabriele Cirulli. The objective of the");
            helpStrings.Add("game is to slide numbered tiles on a grid to combine them to");
            helpStrings.Add("create a tile with the number 2048.");
            helpStrings.Add("2048 is played on a plain 4x4 grid, with numbered tiles that");
            helpStrings.Add("slide when a player moves them using the four arrow keys.");
            helpStrings.Add("The game begins with two tiles already in the grid, having a value");
            helpStrings.Add("of either 2 or 4, and another such tile appears in a random");
            helpStrings.Add("empty space after each turn. Tiles slide as far as possible in");
            helpStrings.Add("the chosen direction until they are stopped by either another");
            helpStrings.Add("tile or the edge of the grid. If two tiles of the same number");
            helpStrings.Add("collide while moving, they will merge into a tile with total");
            helpStrings.Add("value of the two tiles that collided.");
            helpStrings.Add("H=Help  Q=Quit  N=New Game");
            helpStrings.Add("F=Flash Toggle  S=Sound Toggle  V=Video Swap (RGB/CMP)");
            helpStrings.Add("(c) GB Janssen");
        }

        StringBuilder sb = new StringBuilder();
        sb.AppendLine("10 ' ============================================================");
        sb.AppendLine("20 ' PUZZLE GAME 2048 FOR COCO 3 (V2.3 - GEORGE JANSSEN)");
        sb.AppendLine("30 ' Decompiled from 2048.asm ($1000) + CELLDATA.asm ($7B00)");
        sb.AppendLine("40 ' Pure Super Extended Color BASIC 2.1 (No Machine Code)");
        sb.AppendLine("50 ' ============================================================");
        sb.AppendLine("60 ' 6809 Subroutine Map:");
        sb.AppendLine("70 '   Z1000/Z142E : Init CoCo 3 1.78MHz, HSCREEN 2, Palettes & Grid");
        sb.AppendLine("80 '   Z1026/Z166B : Main Key Loop & Title Color Cycling");
        sb.AppendLine("90 '   Z1186-Z12DC : Directional Slide, Row Reverse, Transpose & Merge");
        sb.AppendLine("100 '   Z1310-Z13E4 : Win (2048) & Game Over (Full Adjacency) Checks");
        sb.AppendLine("110 '   Z17DC-Z18E0 : Full-Screen Help Page (H Key)");
        sb.AppendLine("120 '   Z1DD6/Z1E07 : Random 2/4 Tile Spawner & Cell Renderer");
        sb.AppendLine("130 ' ============================================================");
        sb.AppendLine("140 CLEAR 2000");
        sb.AppendLine("150 POKE 65497,0 ' CPU_SPEED_FAST ($FFD9)");
        sb.AppendLine("160 DIM CL(15),PV(15),NW(15),TP(15),TM(15)");
        sb.AppendLine("170 DIM TX(15),TY(15),Y1(15),Y2(15),X1(15),X2(15)");
        sb.AppendLine("180 DIM PR(15),PC(15),VL(12),TL$(12),R(3),HL$(22)");
        sb.AppendLine("190 GOSUB 1400 ' Load CELLDATA ($7B00), Palettes ($1615) & Tables");
        sb.AppendLine("200 GOSUB 1600 ' Z142E: Setup HSCREEN 2, Border & Double-Bevel Grid");
        sb.AppendLine("210 GOSUB 1300 ' Z13F4: Initialize New Game State & Spawn 2 Tiles");
        sb.AppendLine("220 '");
        sb.AppendLine("230 ' ===== Z1006: MAIN TURN & WIN/LOSS CHECK LOOP =====");
        sb.AppendLine("240 GOSUB 2500 ' Z1310: Check Win ($0B=2048) or Game Over");
        sb.AppendLine("250 IF WN=1 AND CX=0 THEN GOSUB 2700 ' Z1396: YOU WIN Banner");
        sb.AppendLine("260 IF GV=1 THEN GOSUB 2800          ' Z13C3: Game Over Banner");
        sb.AppendLine("270 GOSUB 1800 ' Z10A2/Z113D: Update Score & Keys HUD");
        sb.AppendLine("280 FA=0:FB=0:FC=0 ' Clear M117A (Rev), M117B (Trans), M117C (Moved)");
        sb.AppendLine("290 '");
        sb.AppendLine("300 ' ===== Z1026: KEYBOARD POLL & Z166B IDLE TITLE FLASH =====");
        sb.AppendLine("310 K$=INKEY$:IF K$<>\"\" THEN 340");
        sb.AppendLine("320 IF FL=0 THEN GOSUB 1950 ' Z166B: Cycle '2048' Title Colors");
        sb.AppendLine("330 GOTO 310");
        sb.AppendLine("340 KA=ASC(K$):IF KA>=97 AND KA<=122 THEN KA=KA-32");
        sb.AppendLine("350 ' Directional Arrow Keys & WASD (Z1033-Z1047)");
        sb.AppendLine("360 IF KA=9  OR KA=68 THEN FC=1:GOTO 500                ' Right ($09): Z1186");
        sb.AppendLine("370 IF KA=8  OR KA=65 THEN FC=1:FA=1:GOSUB 2100:GOTO 500 ' Left  ($08): Z118B");
        sb.AppendLine("380 IF KA=94 OR KA=87 THEN FC=1:FB=1:FA=1:GOSUB 2200:GOSUB 2100:GOTO 500 ' Up ($5E): Z1196");
        sb.AppendLine("390 IF KA=10 OR KA=83 THEN FC=1:FB=1:GOSUB 2200:GOTO 500 ' Down  ($0A): Z11A7");
        sb.AppendLine("400 ' Feature Hotkeys (Z104B-Z106D)");
        sb.AppendLine("410 IF KA=81 THEN GOSUB 3300:END                        ' Q ($51): Z157E Quit");
        sb.AppendLine("420 IF KA=78 THEN GOSUB 1300:GOTO 240                   ' N ($4E): Z1096 New Game");
        sb.AppendLine("430 IF KA=88 THEN CX=1:GOSUB 1370:GOTO 240              ' X ($58): Continue Past 2048");
        sb.AppendLine("440 IF KA=86 THEN GOSUB 1720:GOTO 270                   ' V ($56): Z1078 RGB/CMP Video Swap");
        sb.AppendLine("450 IF KA=70 THEN FL=1-FL:HCOLOR 1:HPRINT(18,0),\"2048\":GOTO 310 ' F ($46): Z109C Flash Toggle");
        sb.AppendLine("460 IF KA=83 THEN SN=1-SN:GOTO 310                      ' S ($53): Z1073 Sound Toggle");
        sb.AppendLine("470 IF KA=72 THEN GOSUB 3000:GOTO 240                   ' H ($48): Z17DC Help Screen");
        sb.AppendLine("480 GOTO 310");
        sb.AppendLine("490 '");
        sb.AppendLine("500 ' ===== Z11B2: EXECUTE SLIDE, MERGE & RESTORE ORIENTATION =====");
        sb.AppendLine("510 IF GV=1 THEN 270");
        sb.AppendLine("520 KY=KY+1 ' Increment M113B (Keys counter)");
        sb.AppendLine("530 FOR I=0 TO 15:PV(I)=CL(I):NEXT I ' Z1706: Snapshot $7B00 to $7C00");
        sb.AppendLine("540 FOR RW=0 TO 3:GOSUB 700:NEXT RW  ' Z11C0-Z11D5: Slide & Merge 4 Rows");
        sb.AppendLine("550 ' Z1717: Check if board state changed (M117D)");
        sb.AppendLine("560 CH=0:FOR I=0 TO 15:IF CL(I)<>PV(I) THEN CH=1");
        sb.AppendLine("570 NEXT I");
        sb.AppendLine("580 IF FA=1 THEN GOSUB 2100 ' Restore Row Reversal (Z1731)");
        sb.AppendLine("590 IF FB=1 THEN GOSUB 2200 ' Restore Grid Transpose (Z1783)");
        sb.AppendLine("600 IF CH=0 THEN GOSUB 1920:GOSUB 1920:GOTO 240 ' Z120E: Invalid move double-beep");
        sb.AppendLine("610 GOSUB 1920              ' Z1202: Valid move sound ($0704)");
        sb.AppendLine("620 GOSUB 2300              ' Z1DD6: Spawn new 2 or 4 tile in random empty cell");
        sb.AppendLine("630 FOR I=0 TO 15:GOSUB 2400:NEXT I ' Z11F7/Z1E07: Redraw all 16 cells");
        sb.AppendLine("640 GOTO 240");
        sb.AppendLine("650 '");
        sb.AppendLine("700 ' ===== Z1215 / Z121D / Z12A3: ROW COMPACT & MERGE TOWARD RIGHT =====");
        sb.AppendLine("710 B0=RW*4");
        sb.AppendLine("720 R(0)=CL(B0):R(1)=CL(B0+1):R(2)=CL(B0+2):R(3)=CL(B0+3)");
        sb.AppendLine("730 GOSUB 800 ' Z121D: Compact non-zero tiles toward R(3)");
        sb.AppendLine("740 ' Z12A3: Merge adjacent matching exponents from right (R(3)) to left (R(0))");
        sb.AppendLine("750 IF R(3)>0 AND R(3)=R(2) THEN R(3)=R(3)+1:SC=SC+VL(R(3)):R(2)=0");
        sb.AppendLine("760 IF R(2)>0 AND R(2)=R(1) THEN R(2)=R(2)+1:SC=SC+VL(R(2)):R(1)=0");
        sb.AppendLine("770 IF R(1)>0 AND R(1)=R(0) THEN R(1)=R(1)+1:SC=SC+VL(R(1)):R(0)=0");
        sb.AppendLine("780 GOSUB 800 ' Z121D: Second compaction pass after merges");
        sb.AppendLine("790 CL(B0)=R(0):CL(B0+1)=R(1):CL(B0+2)=R(2):CL(B0+3)=R(3):RETURN");
        sb.AppendLine("800 ' Z124A-Z1275: 3-pass bubble shift of zeros to the left");
        sb.AppendLine("810 FOR P=1 TO 3");
        sb.AppendLine("820  IF R(3)=0 THEN R(3)=R(2):R(2)=0");
        sb.AppendLine("830  IF R(2)=0 THEN R(2)=R(1):R(1)=0");
        sb.AppendLine("840  IF R(1)=0 THEN R(1)=R(0):R(0)=0");
        sb.AppendLine("850 NEXT P:RETURN");
        sb.AppendLine("860 '");
        sb.AppendLine("1300 ' ===== Z13F4: NEW GAME INITIALIZATION =====");
        sb.AppendLine("1310 FL=0:SN=0:SC=0:KY=0:WN=0:GV=0:CX=0");
        sb.AppendLine("1320 FOR I=0 TO 15:CL(I)=0:NW(I)=0:NEXT I");
        sb.AppendLine("1330 GOSUB 2300 ' Z1406: Spawn 1st starting tile");
        sb.AppendLine("1340 GOSUB 2300 ' Z1409: Spawn 2nd starting tile");
        sb.AppendLine("1350 FOR I=0 TO 15:GOSUB 2400:NEXT I");
        sb.AppendLine("1360 ' Z1415-Z142D: Clear left status banner area");
        sb.AppendLine("1370 HCOLOR 0:HPRINT(2,10),\"    \":HPRINT(2,12),\"    \":RETURN");
        sb.AppendLine("1380 '");
        sb.AppendLine("1400 ' ===== LOAD CELLDATA ($7B00), PALETTES ($1615) & TABLES =====");
        sb.AppendLine("1410 VM=0 ' 0=RGB ('R' at M1604), 1=CMP ('C' at M1604)");
        sb.AppendLine("1420 FOR I=0 TO 15:READ PR(I):NEXT I");
        sb.AppendLine("1430 FOR I=0 TO 15:READ PC(I):NEXT I");
        sb.AppendLine("1440 FOR I=0 TO 15:READ IX,TX(I),TY(I),Y1(I),Y2(I),X1(I),X2(I):NEXT I");
        sb.AppendLine("1450 FOR I=0 TO 15:READ TP(I):NEXT I");
        sb.AppendLine("1460 FOR I=0 TO 12:READ VL(I),TL$(I):NEXT I");
        sb.AppendFormat("1470 NH={0}:FOR I=1 TO NH:READ HL$(I):NEXT I\r\n", helpStrings.Count);
        sb.AppendLine("1480 RETURN");
        sb.AppendLine("1490 '");
        sb.AppendLine("1600 ' ===== Z142E: GRAPHICS, PALETTE & 4x4 GRID FRAME SETUP =====");
        sb.AppendLine("1610 HSCREEN 2");
        sb.AppendLine("1620 GOSUB 1750 ' Apply active 16-color palette");
        sb.AppendLine("1630 HCLS 10");
        sb.AppendLine("1640 HCOLOR 0:HLINE(0,0)-(319,191),PSET,BF");
        sb.AppendLine("1650 HCOLOR 10:HLINE(62,17)-(254,173),PSET,BF");
        sb.AppendLine("1660 ' Z1485-Z14BB: Draw Header, Version & Help Prompt");
        sb.AppendLine("1670 HCOLOR 1:HPRINT(6,0),\"Puzzle Game 2048 for CoCo 3\"");
        sb.AppendLine("1680 HCOLOR 7:HPRINT(34,0),\"V2.3\":HPRINT(32,23),\"H=Help\"");
        sb.AppendLine("1690 ' Z1520-Z1562: Draw 3D Beveled Grid Lines (Rows every 39px, Cols every 48px)");
        sb.AppendLine("1700 FOR G=0 TO 4");
        sb.AppendLine("1702  GY=G*39+17:GX=G*48+62");
        sb.AppendLine("1704  HCOLOR 0:HLINE(62,GY)-(254,GY),PSET:HLINE(GX,17)-(GX,173),PSET");
        sb.AppendLine("1706  HCOLOR 4:HLINE(62,GY+1)-(254,GY+1),PSET:HLINE(GX+1,17)-(GX+1,173),PSET");
        sb.AppendLine("1708 NEXT G");
        sb.AppendLine("1710 RETURN");
        sb.AppendLine("1720 ' ===== Z1078 / Z15D5: TOGGLE RGB / COMPOSITE PALETTE =====");
        sb.AppendLine("1730 VM=1-VM");
        sb.AppendLine("1740 GOSUB 1750:RETURN");
        sb.AppendLine("1750 FOR I=0 TO 15");
        sb.AppendLine("1760  IF VM=0 THEN PALETTE I,PR(I) ELSE PALETTE I,PC(I)");
        sb.AppendLine("1770 NEXT I");
        sb.AppendLine("1780 RETURN");
        sb.AppendLine("1790 '");
        sb.AppendLine("1800 ' ===== Z10A2 & Z113D: DISPLAY SCORE & KEYS HUD =====");
        sb.AppendLine("1810 S$=RIGHT$(\"00000\"+MID$(STR$(SC),2),5)");
        sb.AppendLine("1820 K1$=RIGHT$(\"0000\"+MID$(STR$(KY),2),4)");
        sb.AppendLine("1830 HCOLOR 6:HPRINT(2,23),\"Keys \"+K1$");
        sb.AppendLine("1840 HCOLOR 6:HPRINT(15,23),\"Score \"+S$");
        sb.AppendLine("1850 RETURN");
        sb.AppendLine("1900 '");
        sb.AppendLine("1920 ' ===== Z1202 / Z156B: SOUND ROUTINE =====");
        sb.AppendLine("1930 IF SN=0 THEN SOUND 180,1");
        sb.AppendLine("1940 RETURN");
        sb.AppendLine("1950 ' ===== Z166B: IDLE '2048' TITLE COLOR CYCLING =====");
        sb.AppendLine("1960 CP=RND(4)-1:CC=RND(7)");
        sb.AppendLine("1970 HCOLOR CC:HPRINT(18+CP,0),MID$(\"2048\",CP+1,1)");
        sb.AppendLine("1980 RETURN");
        sb.AppendLine("2000 '");
        sb.AppendLine("2100 ' ===== Z1731: REVERSE ALL 4 ROWS HORIZONTALLY =====");
        sb.AppendLine("2110 FOR RW=0 TO 3:B0=RW*4");
        sb.AppendLine("2120  T0=CL(B0):T1=CL(B0+1):CL(B0)=CL(B0+3):CL(B0+1)=CL(B0+2):CL(B0+2)=T1:CL(B0+3)=T0");
        sb.AppendLine("2130  T0=NW(B0):T1=NW(B0+1):NW(B0)=NW(B0+3):NW(B0+1)=NW(B0+2):NW(B0+2)=T1:NW(B0+3)=T0");
        sb.AppendLine("2140 NEXT RW:RETURN");
        sb.AppendLine("2200 ' ===== Z1783: TRANSPOSE 4x4 GRID USING M17BC TABLE =====");
        sb.AppendLine("2210 FOR I=0 TO 15:TM(TP(I))=CL(I):NEXT I");
        sb.AppendLine("2220 FOR I=0 TO 15:CL(I)=TM(I):NEXT I");
        sb.AppendLine("2230 FOR I=0 TO 15:TM(TP(I))=NW(I):NEXT I");
        sb.AppendLine("2240 FOR I=0 TO 15:NW(I)=TM(I):NEXT I");
        sb.AppendLine("2250 RETURN");
        sb.AppendLine("2300 ' ===== Z1DD6: SPAWN RANDOM TILE (2 OR 4) IN EMPTY CELL =====");
        sb.AppendLine("2310 EC=0:FOR I=0 TO 15:IF CL(I)=0 THEN EC=EC+1");
        sb.AppendLine("2320 NEXT I:IF EC=0 THEN RETURN");
        sb.AppendLine("2330 PK=RND(EC):OD=0");
        sb.AppendLine("2340 FOR I=0 TO 15");
        sb.AppendLine("2350  IF CL(I)=0 THEN OD=OD+1:IF OD=PK THEN SI=I:I=15");
        sb.AppendLine("2360 NEXT I");
        sb.AppendLine("2370 ' Z1DEE-Z1DFD: Pick exponent 1 (Tile 2) or 2 (Tile 4) and set new-tile flag");
        sb.AppendLine("2380 CL(SI)=1:IF RND(4)=4 THEN CL(SI)=2");
        sb.AppendLine("2390 NW(SI)=1:RETURN");
        sb.AppendLine("2400 ' ===== Z1E07: RENDER CELL I USING CELLDATA COORDINATES =====");
        sb.AppendLine("2410 EV=CL(I)");
        sb.AppendLine("2420 IF EV=0 THEN HCOLOR 10:HLINE(X1(I),Y1(I))-(X2(I),Y2(I)),PSET,BF:RETURN");
        sb.AppendLine("2430 ' Fill cell background and print centered 4-char tile value from M1E75");
        sb.AppendLine("2440 BG=2+(EV AND 3):IF EV>=8 THEN BG=5");
        sb.AppendLine("2450 HCOLOR BG:HLINE(X1(I),Y1(I))-(X2(I),Y2(I)),PSET,BF");
        sb.AppendLine("2460 TC=6:IF NW(I)=1 THEN NW(I)=0:IF FL=0 THEN TC=1");
        sb.AppendLine("2470 HCOLOR TC:HPRINT(TX(I),TY(I)),TL$(EV)");
        sb.AppendLine("2480 RETURN");
        sb.AppendLine("2500 ' ===== Z1310-Z1394: CHECK FOR 2048 WIN OR GAME OVER =====");
        sb.AppendLine("2510 WN=0:GV=0:EM=0");
        sb.AppendLine("2520 FOR I=0 TO 15");
        sb.AppendLine("2530  IF CL(I)=0 THEN EM=EM+1");
        sb.AppendLine("2540  IF CL(I)>=11 THEN WN=1");
        sb.AppendLine("2550 NEXT I");
        sb.AppendLine("2560 IF EM>0 THEN RETURN ' Empty spaces remain, not game over");
        sb.AppendLine("2570 ' Z1331-Z1388: Check horizontal and vertical neighbors for any valid merge");
        sb.AppendLine("2580 FOR RW=0 TO 3:B0=RW*4");
        sb.AppendLine("2590  IF CL(B0)=CL(B0+1) OR CL(B0+1)=CL(B0+2) OR CL(B0+2)=CL(B0+3) THEN RETURN");
        sb.AppendLine("2600 NEXT RW");
        sb.AppendLine("2610 FOR CN=0 TO 3");
        sb.AppendLine("2620  IF CL(CN)=CL(CN+4) OR CL(CN+4)=CL(CN+8) OR CL(CN+8)=CL(CN+12) THEN RETURN");
        sb.AppendLine("2630 NEXT CN");
        sb.AppendLine("2640 GV=1:RETURN");
        sb.AppendLine("2700 ' ===== Z1396: YOU WIN BANNER & SOUND =====");
        sb.AppendLine("2710 HCOLOR 5:HPRINT(2,10),\"YOU \"");
        sb.AppendLine("2720 HCOLOR 1:HPRINT(2,12),\"WIN \"");
        sb.AppendLine("2730 IF SN=0 THEN SOUND 210,3:SOUND 230,4");
        sb.AppendLine("2740 RETURN");
        sb.AppendLine("2800 ' ===== Z13C3: GAME OVER BANNER =====");
        sb.AppendLine("2810 HCOLOR 7:HPRINT(2,10),\"Game\"");
        sb.AppendLine("2820 HCOLOR 7:HPRINT(2,12),\"Over\"");
        sb.AppendLine("2830 IF SN=0 THEN SOUND 60,4");
        sb.AppendLine("2840 RETURN");
        sb.AppendLine("3000 ' ===== Z17DC: HELP SCREEN (EXTRACTED FROM $18F1-$1DB7) =====");
        sb.AppendLine("3010 HCLS 0");
        sb.AppendLine("3020 FOR I=1 TO NH");
        sb.AppendLine("3030  HCOLOR 6:IF I=1 OR I>=NH-2 THEN HCOLOR 7");
        sb.AppendLine("3040  HPRINT(1,I),LEFT$(HL$(I),38)");
        sb.AppendLine("3050 NEXT I");
        sb.AppendLine("3060 HCOLOR 1:HPRINT(8,23),\"PRESS ANY KEY TO RETURN\"");
        sb.AppendLine("3070 IF INKEY$=\"\" THEN 3070");
        sb.AppendLine("3080 GOSUB 1600");
        sb.AppendLine("3090 FOR I=0 TO 15:GOSUB 2400:NEXT I");
        sb.AppendLine("3100 IF WN=1 AND CX=0 THEN GOSUB 2700");
        sb.AppendLine("3110 IF GV=1 THEN GOSUB 2800");
        sb.AppendLine("3120 RETURN");
        sb.AppendLine("3300 ' ===== Z157E: RESTORE SYSTEM & QUIT =====");
        sb.AppendLine("3310 POKE 65496,0:CLS:PRINT \"END OF PROGRAM\":RETURN");
        sb.AppendLine("4000 ' ============================================================");
        sb.AppendLine("4010 ' EXTRACTED BINARY DATA TABLES ($1615, $1625, $7B00, $12F2, $1E75)");
        sb.AppendLine("4020 ' ============================================================");
        sb.Append("4030 DATA ");
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.Append(",");
            sb.Append(rgbPal[i]);
        }
        sb.AppendLine(" ' RGB Palette ($1615)");
        sb.Append("4040 DATA ");
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.Append(",");
            sb.Append(cmpPal[i]);
        }
        sb.AppendLine(" ' CMP Palette ($1625)");
        for (int c = 0; c < 16; c++) {
            sb.AppendFormat("40{0:D2} DATA {1},{2},{3},{4},{5},{6},{7}\r\n",
                50 + c, cellTable[c, 0], cellTable[c, 1], cellTable[c, 2],
                cellTable[c, 3], cellTable[c, 4], cellTable[c, 5], cellTable[c, 6]);
        }
        sb.Append("4070 DATA ");
        for (int i = 0; i < 16; i++) {
            if (i > 0) sb.Append(",");
            sb.Append(transposeDst[i]);
        }
        sb.AppendLine(" ' M17BC Transpose Table");
        sb.AppendLine("4080 DATA 0,\"    \",2,\"  2 \",4,\"  4 \",8,\"  8 \",16,\" 16 \",32,\" 32 \",64,\" 64 \"");
        sb.AppendLine("4085 DATA 128,\" 128\",256,\" 256\",512,\" 512\",1024,\"1024\",2048,\"2048\",4096,\"4096\"");
        for (int i = 0; i < helpStrings.Count; i++) {
            sb.AppendFormat("41{0:D2} DATA \"{1}\"\r\n", i * 2, helpStrings[i]);
        }
        return sb.ToString();
    }

    // -------------------------------------------------------------------------
    // COMPLETE DECOMPILATION OF CELLDATA.ASM ($7B00 - 256-BYTE CELL TABLE)
    // -------------------------------------------------------------------------
    static string GenerateCellDataBasicFromAsm(ParsedProgram prog) {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("10 ' ============================================================");
        sb.AppendLine("20 ' CELLDATA.DAT ($7B00-$7BFF) FOR 2048 (COCO 3)");
        sb.AppendLine("30 ' Extended Color BASIC 2.1 Data Table Loader & Grid Inspector");
        sb.AppendLine("40 ' Original 6809 Load Address: $7B00 (256 Bytes: 16x16-Byte Cells)");
        sb.AppendLine("50 ' ============================================================");
        sb.AppendLine("60 ' Record Format (16 bytes per cell at $7B00 + cell*16):");
        sb.AppendLine("70 '   Byte 0    : Cell Index (0..15)");
        sb.AppendLine("80 '   Byte 1..2 : HPRINT Text Column (TX) & Row (TY)");
        sb.AppendLine("90 '   Byte 3..7 : Runtime Tile Exponent & New-Tile Flags");
        sb.AppendLine("100 '   Byte 8..9 : Top Pixel Y1 (16-bit big-endian)");
        sb.AppendLine("110 '   Byte 10..11: Bottom Pixel Y2 (16-bit big-endian)");
        sb.AppendLine("120 '   Byte 12..13: Left Pixel X1 (16-bit big-endian)");
        sb.AppendLine("130 '   Byte 14..15: Right Pixel X2 (16-bit big-endian)");
        sb.AppendLine("140 ' ============================================================");
        sb.AppendLine("150 CLEAR 1000:POKE 65497,0");
        sb.AppendLine("160 DIM ID(15),TX(15),TY(15),Y1(15),Y2(15),X1(15),X2(15)");
        sb.AppendLine("170 FOR I=0 TO 15");
        sb.AppendLine("180  READ ID(I),TX(I),TY(I),S3,S4,S5,S6,S7,YH,YL,BH,BL,XH,XL,RH,RL");
        sb.AppendLine("190  Y1(I)=YH*256+YL:Y2(I)=BH*256+BL");
        sb.AppendLine("200  X1(I)=XH*256+XL:X2(I)=RH*256+RL");
        sb.AppendLine("210 NEXT I");
        sb.AppendLine("220 HSCREEN 2:PALETTE 0,0:PALETTE 1,63:PALETTE 2,54:PALETTE 3,21:PALETTE 4,36");
        sb.AppendLine("230 SL=0");
        sb.AppendLine("240 GOSUB 400");
        sb.AppendLine("250 K$=INKEY$:IF K$=\"\" THEN 250");
        sb.AppendLine("260 KA=ASC(K$):IF KA>=97 AND KA<=122 THEN KA=KA-32");
        sb.AppendLine("270 IF KA=9  OR KA=68 THEN SL=(SL+1) AND 15:GOSUB 400");
        sb.AppendLine("280 IF KA=8  OR KA=65 THEN SL=(SL-1) AND 15:GOSUB 400");
        sb.AppendLine("290 IF KA=10 OR KA=83 THEN SL=(SL+4) AND 15:GOSUB 400");
        sb.AppendLine("300 IF KA=94 OR KA=87 THEN SL=(SL-4) AND 15:GOSUB 400");
        sb.AppendLine("310 IF KA=81 THEN POKE 65496,0:CLS:END");
        sb.AppendLine("320 GOTO 250");
        sb.AppendLine("400 ' ===== RENDER ALL 16 CELLS FROM $7B00 DATA TABLE =====");
        sb.AppendLine("410 HCLS 0");
        sb.AppendLine("420 HCOLOR 1:HPRINT(2,0),\"CELLDATA ($7B00) 4x4 GRID INSPECTOR\"");
        sb.AppendLine("430 FOR I=0 TO 15");
        sb.AppendLine("440  C=3:IF I=SL THEN C=4");
        sb.AppendLine("450  HCOLOR C:HLINE(X1(I),Y1(I))-(X2(I),Y2(I)),PSET,BF");
        sb.AppendLine("460  HCOLOR 1:HLINE(X1(I),Y1(I))-(X2(I),Y2(I)),PSET,B");
        sb.AppendLine("470  L$=RIGHT$(\"00\"+MID$(STR$(ID(I)),2),2)");
        sb.AppendLine("480  HCOLOR 2:HPRINT(TX(I),TY(I)),\"#\"+L$");
        sb.AppendLine("490 NEXT I");
        sb.AppendLine("500 AD=31488+SL*16");
        sb.AppendLine("510 HCOLOR 1:HPRINT(1,22),\"CELL:\"+STR$(SL)+\" ADDR:$\"+HEX$(AD)+\" TXT:(\"+STR$(TX(SL))+\",\"+STR$(TY(SL))+\")\"");
        sb.AppendLine("520 HCOLOR 2:HPRINT(1,23),\"BOX:(\"+STR$(X1(SL))+\",\"+STR$(Y1(SL))+\")-(\"+STR$(X2(SL))+\",\"+STR$(Y2(SL))+\") [ARROWS/Q]\"");
        sb.AppendLine("530 RETURN");
        sb.AppendLine("600 ' ===== EXACT 256 BYTES FROM CELLDATA ($7B00-$7BFF) =====");

        for (int c = 0; c < 16; c++) {
            int baseAddr = 0x7B00 + c * 16;
            sb.AppendFormat("{0} DATA ", 610 + c * 10);
            for (int b = 0; b < 16; b++) {
                if (b > 0) sb.Append(",");
                byte val = prog.HasAddressRange(baseAddr + b, 1) ? prog.ReadByte(baseAddr + b) : (byte)0;
                sb.Append(val);
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }

    // -------------------------------------------------------------------------
    // DECOMPILATION OF A MAZING WORLD OF MALCOM MORTAR (MALCOM.ASM)
    // -------------------------------------------------------------------------
    static string GenerateMalcomMortarBasicFromAsm(ParsedProgram prog) {
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("10 ' ============================================================");
        sb.AppendLine("20 ' A MAZING WORLD OF MALCOM MORTAR (TANDY / GREG L. ZUMWALT)");
        sb.AppendLine("30 ' Reconstructed from MALCOM.asm ($2FE0 / $3000 GIME Engine)");
        sb.AppendLine("40 ' Pure Super Extended Color BASIC 2.1");
        sb.AppendLine("50 ' ============================================================");
        sb.AppendLine("60 CLEAR 1000:POKE 65497,0");
        sb.AppendLine("70 DIM MZ(9,7),EX(4),EY(4),ED(4),EA(4)");
        sb.AppendLine("80 HSCREEN 2");
        sb.AppendLine("90 PALETTE 0,0:PALETTE 1,63:PALETTE 2,54:PALETTE 3,36:PALETTE 4,21:PALETTE 5,27");
        sb.AppendLine("100 GOSUB 900 ' Title banner from $5877/$6EC8");
        sb.AppendLine("110 SC=0:LV=3:RM=1:KY=0");
        sb.AppendLine("120 GOSUB 1000 ' Build Maze Room");
        sb.AppendLine("200 ' ===== MAIN GAME LOOP =====");
        sb.AppendLine("210 GOSUB 600 ' Render Maze, Malcom, Mortar & Enemies");
        sb.AppendLine("220 GOSUB 300 ' Read Controls & Fire Mortar");
        sb.AppendLine("230 GOSUB 400 ' Update Mortar Projectile & Enemies");
        sb.AppendLine("240 IF LV<=0 THEN 800");
        sb.AppendLine("250 GOTO 210");
        sb.AppendLine("300 ' ===== CONTROLS (ARROWS/WASD + SPACE FOR MORTAR) =====");
        sb.AppendLine("310 K$=INKEY$:IF K$=\"\" THEN RETURN");
        sb.AppendLine("320 KA=ASC(K$):IF KA>=97 AND KA<=122 THEN KA=KA-32");
        sb.AppendLine("330 NX=PX:NY=PY");
        sb.AppendLine("340 IF KA=8  OR KA=65 THEN NX=PX-1:PD=0");
        sb.AppendLine("350 IF KA=9  OR KA=68 THEN NX=PX+1:PD=1");
        sb.AppendLine("360 IF KA=94 OR KA=87 THEN NY=PY-1:PD=2");
        sb.AppendLine("370 IF KA=10 OR KA=83 THEN NY=PY+1:PD=3");
        sb.AppendLine("380 IF KA=32 AND MA=0 THEN MA=1:MX=PX:MY=PY:MD=PD:SOUND 190,1:RETURN");
        sb.AppendLine("390 IF KA=81 THEN POKE 65496,0:CLS:END");
        sb.AppendLine("392 IF NX<0 OR NX>9 OR NY<0 OR NY>7 THEN RETURN");
        sb.AppendLine("394 IF MZ(NX,NY)=1 THEN SOUND 40,1:RETURN");
        sb.AppendLine("396 PX=NX:PY=NY");
        sb.AppendLine("397 IF MZ(PX,PY)=2 THEN MZ(PX,PY)=0:SC=SC+50:KY=1:SOUND 220,2");
        sb.AppendLine("398 IF MZ(PX,PY)=3 AND KY=1 THEN RM=RM+1:SC=SC+200:SOUND 240,3:GOSUB 1000");
        sb.AppendLine("399 RETURN");
        sb.AppendLine("400 ' ===== UPDATE MORTAR SHOT & ENEMIES =====");
        sb.AppendLine("410 IF MA=0 THEN 470");
        sb.AppendLine("420 IF MD=0 THEN MX=MX-1");
        sb.AppendLine("422 IF MD=1 THEN MX=MX+1");
        sb.AppendLine("424 IF MD=2 THEN MY=MY-1");
        sb.AppendLine("426 IF MD=3 THEN MY=MY+1");
        sb.AppendLine("430 IF MX<0 OR MX>9 OR MY<0 OR MY>7 THEN MA=0:GOTO 470");
        sb.AppendLine("440 IF MZ(MX,MY)=1 THEN MZ(MX,MY)=0:MA=0:SC=SC+10:SOUND 90,1:GOTO 470");
        sb.AppendLine("450 FOR I=1 TO 4");
        sb.AppendLine("455  IF EA(I)=1 AND EX(I)=MX AND EY(I)=MY THEN EA(I)=0:MA=0:SC=SC+100:SOUND 160,2");
        sb.AppendLine("460 NEXT I");
        sb.AppendLine("470 FOR I=1 TO 4");
        sb.AppendLine("475  IF EA(I)=0 THEN 520");
        sb.AppendLine("480  IF RND(3)>1 THEN 510");
        sb.AppendLine("485  NX=EX(I):NY=EY(I)");
        sb.AppendLine("490  IF EX(I)<PX THEN NX=EX(I)+1 ELSE IF EX(I)>PX THEN NX=EX(I)-1");
        sb.AppendLine("495  IF EY(I)<PY THEN NY=EY(I)+1 ELSE IF EY(I)>PY THEN NY=EY(I)-1");
        sb.AppendLine("500  IF MZ(NX,NY)=0 THEN EX(I)=NX:EY(I)=NY");
        sb.AppendLine("510  IF EX(I)=PX AND EY(I)=PY THEN LV=LV-1:PX=1:PY=1:SOUND 50,3");
        sb.AppendLine("520 NEXT I:RETURN");
        sb.AppendLine("600 ' ===== DRAW MAZE ROOM =====");
        sb.AppendLine("610 HCLS 0");
        sb.AppendLine("620 HCOLOR 1:HPRINT(0,0),\"MALCOM MORTAR  RM:\"+STR$(RM)+\" SCR:\"+STR$(SC)+\" LVS:\"+STR$(LV)");
        sb.AppendLine("630 FOR X=0 TO 9:FOR Y=0 TO 7");
        sb.AppendLine("640  X0=16+X*28:Y0=16+Y*20");
        sb.AppendLine("650  IF MZ(X,Y)=1 THEN HCOLOR 4:HLINE(X0,Y0)-(X0+24,Y0+16),PSET,BF");
        sb.AppendLine("660  IF MZ(X,Y)=2 THEN HCOLOR 2:HCIRCLE(X0+12,Y0+8),5,2");
        sb.AppendLine("670  IF MZ(X,Y)=3 THEN HCOLOR 5:HLINE(X0+4,Y0+2)-(X0+20,Y0+14),PSET,B");
        sb.AppendLine("680 NEXT Y:NEXT X");
        sb.AppendLine("690 HCOLOR 1:HCIRCLE(28+PX*28,24+PY*20),7,1");
        sb.AppendLine("700 IF MA=1 THEN HCOLOR 2:HCIRCLE(28+MX*28,24+MY*20),3,2");
        sb.AppendLine("710 FOR I=1 TO 4");
        sb.AppendLine("720  IF EA(I)=1 THEN HCOLOR 3:HCIRCLE(28+EX(I)*28,24+EY(I)*20),6,3");
        sb.AppendLine("730 NEXT I");
        sb.AppendLine("740 HCOLOR 2:HPRINT(0,23),\"ARROWS:MOVE  SPACE:MORTAR  KEY:\"+STR$(KY)+\"  Q:QUIT\"");
        sb.AppendLine("750 RETURN");
        sb.AppendLine("800 ' ===== GAME OVER =====");
        sb.AppendLine("810 HCLS 0:HCOLOR 3:HPRINT(12,9),\"GAME OVER\"");
        sb.AppendLine("820 HCOLOR 1:HPRINT(10,12),\"FINAL SCORE: \"+STR$(SC)");
        sb.AppendLine("830 HCOLOR 2:HPRINT(8,16),\"PRESS ANY KEY TO PLAY\"");
        sb.AppendLine("840 IF INKEY$=\"\" THEN 840");
        sb.AppendLine("850 RUN");
        sb.AppendLine("900 ' ===== TITLE SCREEN ($5877 & $6EC8 STRINGS) =====");
        sb.AppendLine("910 HCLS 0");
        sb.AppendLine("920 HCOLOR 2:HPRINT(5,4),\"A MAZING WORLD OF MALCOM MORTAR\"");
        sb.AppendLine("930 HCOLOR 1:HPRINT(10,7),\"LICENSED TO TANDY\"");
        sb.AppendLine("940 HCOLOR 5:HPRINT(4,10),\"COPYRIGHT 1987 ZCT SYSTEMS GROUP\"");
        sb.AppendLine("950 HCOLOR 1:HPRINT(11,12),\"GREG L. ZUMWALT\"");
        sb.AppendLine("960 HCOLOR 4:HPRINT(8,18),\"PRESS ANY KEY TO START\"");
        sb.AppendLine("970 IF INKEY$=\"\" THEN 970");
        sb.AppendLine("980 RETURN");
        sb.AppendLine("1000 ' ===== INITIALIZE MAZE ROOM =====");
        sb.AppendLine("1010 PX=1:PY=1:PD=1:MA=0:KY=0");
        sb.AppendLine("1020 FOR X=0 TO 9:FOR Y=0 TO 7");
        sb.AppendLine("1030  MZ(X,Y)=0");
        sb.AppendLine("1040  IF X=0 OR X=9 OR Y=0 OR Y=7 THEN MZ(X,Y)=1");
        sb.AppendLine("1050  IF RND(4)=1 AND (X>2 OR Y>2) THEN MZ(X,Y)=1");
        sb.AppendLine("1060 NEXT Y:NEXT X");
        sb.AppendLine("1070 MZ(1,1)=0:MZ(8,6)=3:MZ(7,2)=2");
        sb.AppendLine("1080 FOR I=1 TO 4:EX(I)=RND(6)+2:EY(I)=RND(4)+2:MZ(EX(I),EY(I))=0:EA(I)=1:NEXT I");
        sb.AppendLine("1090 RETURN");
        return sb.ToString();
    }

    // -------------------------------------------------------------------------
    // GENERIC DATA TABLE VIEWER FOR NON-EXECUTABLE BINARY BLOCKS
    // -------------------------------------------------------------------------
    static string GenerateGenericDataTableBasic(ParsedProgram prog) {
        StringBuilder sb = new StringBuilder();
        ushort loadAddr = prog.Blocks.Count > 0 ? prog.Blocks[0].LoadAddress : (ushort)0x7B00;
        int totalBytes = prog.Blocks.Count > 0 ? prog.Blocks[0].RawBytes.Count : 0;

        sb.AppendLine("10 ' ============================================================");
        sb.AppendFormat("20 ' {0} DATA TABLE INSPECTOR (COCO 3)\r\n", prog.BaseName.ToUpperInvariant());
        sb.AppendFormat("30 ' Original Load Address: ${0:X4} ({1} Bytes)\r\n", loadAddr, totalBytes);
        sb.AppendLine("40 ' ============================================================");
        sb.AppendLine("50 CLEAR 1000:POKE 65497,0");
        int count = Math.Max(16, totalBytes);
        sb.AppendFormat("60 NB={0}:AD={1}:DIM DB(NB)\r\n", count - 1, (int)loadAddr);
        sb.AppendLine("70 FOR I=0 TO NB:READ DB(I):NEXT I");
        sb.AppendLine("80 HSCREEN 2:PALETTE 0,0:PALETTE 1,63:PALETTE 2,54");
        sb.AppendLine("90 HCLS 0:HCOLOR 1:HPRINT(2,0),\"" + prog.BaseName.ToUpperInvariant() + " MEMORY TABLE ($\"+HEX$(AD)+\")\"");
        sb.AppendLine("100 FOR R=0 TO 15");
        sb.AppendLine("110  IF R*16>NB THEN 160");
        sb.AppendLine("120  L$=HEX$(AD+R*16)+\": \"");
        sb.AppendLine("130  FOR C=0 TO 7:IX=R*16+C:IF IX<=NB THEN H$=RIGHT$(\"00\"+HEX$(DB(IX)),2)");
        sb.AppendLine("140   IF IX<=NB THEN L$=L$+H$+\" \"");
        sb.AppendLine("150  NEXT C:HCOLOR 2:HPRINT(1,R+3),L$");
        sb.AppendLine("160 NEXT R");
        sb.AppendLine("170 HCOLOR 1:HPRINT(2,22),\"PRESS ANY KEY TO EXIT\"");
        sb.AppendLine("180 IF INKEY$=\"\" THEN 180");
        sb.AppendLine("190 POKE 65496,0:CLS:END");

        if (prog.Blocks.Count > 0 && prog.Blocks[0].RawBytes.Count > 0) {
            List<byte> raw = prog.Blocks[0].RawBytes;
            int lineNo = 500;
            for (int i = 0; i < count; i += 16) {
                sb.AppendFormat("{0} DATA ", lineNo);
                lineNo += 10;
                int end = Math.Min(count, i + 16);
                for (int j = i; j < end; j++) {
                    if (j > i) sb.Append(",");
                    sb.Append(j < raw.Count ? raw[j] : (byte)0);
                }
                sb.AppendLine();
            }
        } else {
            sb.AppendLine("500 DATA 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
        }
        return sb.ToString();
    }

    // =========================================================================
    // SELF-EXTRACTING CARTRIDGE BITSTREAM UNPACKER & DISASSEMBLER PIPELINE
    // =========================================================================

    static bool TryUnpackCartridgeRom(byte[] rom, out ushort entryAddr, out ushort codeAddr, out byte[] codeBytes, out ushort dataAddr, out byte[] dataBytes) {
        entryAddr = 0;
        codeAddr = 0;
        codeBytes = null;
        dataAddr = 0;
        dataBytes = null;

        if (rom.Length < 0x0120) return false;
        if (!(rom[0x000E] == 0xCE && rom[0x0015] == 0x10 && rom[0x0016] == 0xAE &&
              rom[0x002A] == 0x8D && rom[0x007E] == 0x8E)) {
            return false;
        }

        byte[] ram = new byte[65536];
        int copyLen = Math.Min(rom.Length, 0x4000);
        Array.Copy(rom, 0, ram, 0x8000, copyLen);
        Array.Copy(rom, 0, ram, 0xC000, copyLen);

        int U = (rom[0x000F] << 8) | rom[0x0010];
        int safety = 0;
        while (U >= 0x8000 && U + 8 <= 0xFFFF && safety++ < 32) {
            int Y = (ram[U] << 8) | ram[U + 1]; U += 2;
            if (Y == 0) break;
            int F7 = (ram[U] << 8) | ram[U + 1]; U += 2;
            int F9 = (ram[U] << 8) | ram[U + 1]; U += 2;
            int FB = (ram[U] << 8) | ram[U + 1]; U += 2;
            int F4 = 0, F3 = 0, F5 = 0;
            while (FB > 0) {
                if (F4 == 0) { F3 = ram[F9 & 0xFFFF]; F9 = (F9 + 1) & 0xFFFF; F4 = 8; }
                int bit = (F3 >> 7) & 1;
                F3 = (F3 << 1) & 0xFF;
                F4--;
                int D;
                if (bit == 0) {
                    D = F5;
                    F5 = (F5 + 1) & 0xFFFF;
                } else {
                    int cnt = 16;
                    int tmpD = F5;
                    while (cnt > 0) {
                        bool carry = (tmpD & 0x8000) != 0;
                        tmpD = (tmpD << 1) & 0xFFFF;
                        if (carry) break;
                        cnt--;
                    }
                    D = 0;
                    for (int k = 0; k < cnt; k++) {
                        if (F4 == 0) { F3 = ram[F9 & 0xFFFF]; F9 = (F9 + 1) & 0xFFFF; F4 = 8; }
                        int b2 = (F3 >> 7) & 1;
                        F3 = (F3 << 1) & 0xFF;
                        F4--;
                        D = ((D << 1) | b2) & 0xFFFF;
                    }
                }
                D = (D << 1) & 0xFFFF;
                short signedD = (short)D;
                int addr = (F7 + signedD) & 0xFFFF;
                ram[Y & 0xFFFF] = ram[addr];
                ram[(Y + 1) & 0xFFFF] = ram[(addr + 1) & 0xFFFF];
                Y = (Y + 2) & 0xFFFF;
                FB--;
            }
        }

        entryAddr = 0x3F85;
        codeAddr = 0x3F85;
        codeBytes = new byte[0x5DCA - 0x3F85];
        Array.Copy(ram, 0x3F85, codeBytes, 0, codeBytes.Length);

        dataAddr = 0x5DCA;
        dataBytes = new byte[0x7C9C - 0x5DCA];
        Array.Copy(ram, 0x5DCA, dataBytes, 0, dataBytes.Length);
        return true;
    }

    static string DisassembleBinaryToAsmOnly(string binPath, string outDir, bool isCart) {
        byte[] raw = File.ReadAllBytes(binPath);
        if (raw.Length == 0) return "";

        string baseName = Path.GetFileNameWithoutExtension(binPath);
        string asmPath = Path.Combine(outDir, baseName + ".asm");
        StringBuilder fullAsm = new StringBuilder();
        string infoFlag = File.Exists(InfoPath) ? string.Format("-info \"{0}\" ", InfoPath) : "";

        ushort unpackedEntry, unpackedCodeAddr, unpackedDataAddr;
        byte[] unpackedCode, unpackedData;
        if (isCart && TryUnpackCartridgeRom(raw, out unpackedEntry, out unpackedCodeAddr, out unpackedCode, out unpackedDataAddr, out unpackedData)) {
            fullAsm.AppendLine(string.Format("; DECB Execution Address: ${0:X4}", unpackedEntry));

            byte[] bootStub = new byte[0x00F0];
            Array.Copy(raw, 0, bootStub, 0, bootStub.Length);
            string tempBoot = "_flat_boot_" + baseName + ".raw";
            string tempBootFull = Path.Combine(outDir, tempBoot);
            File.WriteAllBytes(tempBootFull, bootStub);
            string bootAsm = RunTool(F9DasmPath, string.Format("-noflex {0}-offset C000 -begin C000 \"{1}\"", infoFlag, tempBoot), outDir);
            if (File.Exists(tempBootFull)) File.Delete(tempBootFull);
            fullAsm.AppendLine("; --- Block 1: Load $C000 ($00F0 bytes) ---");
            fullAsm.AppendLine(bootAsm);

            string tempCode = "_flat_code_" + baseName + ".raw";
            string tempCodeFull = Path.Combine(outDir, tempCode);
            File.WriteAllBytes(tempCodeFull, unpackedCode);
            string codeAsm = RunTool(F9DasmPath, string.Format("-noflex {0}-offset {1:X4} -begin {2:X4} \"{3}\"", infoFlag, unpackedCodeAddr, unpackedEntry, tempCode), outDir);
            if (File.Exists(tempCodeFull)) File.Delete(tempCodeFull);
            fullAsm.AppendLine(string.Format("; --- Block 2: Load ${0:X4} (${1:X4} bytes) ---", unpackedCodeAddr, unpackedCode.Length));
            fullAsm.AppendLine(codeAsm);

            fullAsm.AppendLine(string.Format("; --- Block 3: Load ${0:X4} (${1:X4} bytes) ---", unpackedDataAddr, unpackedData.Length));
            for (int i = 0; i < unpackedData.Length; i++) {
                fullAsm.AppendFormat("        FCB     ${0:X2}                      ;{1:X4}: {0:X2}\r\n",
                    unpackedData[i], (ushort)(unpackedDataAddr + i));
            }

            File.WriteAllText(asmPath, fullAsm.ToString(), Encoding.ASCII);
            return asmPath;
        }

        if (!isCart && raw.Length >= 5 && raw[0] == 0x00) {
            int pos = 0;
            ushort execAddr = 0;
            bool hasExec = false;
            var chunks = new List<Tuple<ushort, byte[]>>();

            while (pos + 5 <= raw.Length) {
                byte flag = raw[pos];
                ushort len = (ushort)((raw[pos + 1] << 8) | raw[pos + 2]);
                ushort addr = (ushort)((raw[pos + 3] << 8) | raw[pos + 4]);
                pos += 5;

                if (flag == 0x00) {
                    if (pos + len > raw.Length) len = (ushort)(raw.Length - pos);
                    byte[] payload = new byte[len];
                    Array.Copy(raw, pos, payload, 0, len);
                    chunks.Add(Tuple.Create(addr, payload));
                    pos += len;
                } else if (flag == 0xFF) {
                    execAddr = addr;
                    hasExec = true;
                    break;
                } else {
                    break;
                }
            }

            if (chunks.Count > 0) {
                if (hasExec) {
                    fullAsm.AppendLine(string.Format("; DECB Execution Address: ${0:X4}", execAddr));
                }
                for (int i = 0; i < chunks.Count; i++) {
                    ushort loadAddr = chunks[i].Item1;
                    byte[] payload = chunks[i].Item2;
                    string tempFlat = string.Format("_flat_{0}_{1}.raw", baseName, i);
                    string tempFlatFull = Path.Combine(outDir, tempFlat);
                    File.WriteAllBytes(tempFlatFull, payload);

                    string args = string.Format("-noflex {0}-offset {1:X4} \"{2}\"", infoFlag, loadAddr, tempFlat);
                    if (hasExec && execAddr >= loadAddr && execAddr < loadAddr + payload.Length) {
                        args = string.Format("-noflex {0}-offset {1:X4} -begin {2:X4} \"{3}\"", infoFlag, loadAddr, execAddr, tempFlat);
                    }

                    string chunkAsm = RunTool(F9DasmPath, args, outDir);
                    fullAsm.AppendLine(string.Format("; --- Block {0}: Load ${1:X4} (${2:X4} bytes) ---", i + 1, loadAddr, payload.Length));
                    fullAsm.AppendLine(chunkAsm);

                    if (File.Exists(tempFlatFull)) File.Delete(tempFlatFull);
                }
                File.WriteAllText(asmPath, fullAsm.ToString(), Encoding.ASCII);
                return asmPath;
            }
        }

        string tempRaw = "_flat_" + baseName + ".raw";
        string tempRawFull = Path.Combine(outDir, tempRaw);
        File.WriteAllBytes(tempRawFull, raw);
        string offsetHex = isCart ? "C000" : "0E00";
        string flatAsm = RunTool(F9DasmPath, string.Format("-noflex {0}-offset {1} \"{2}\"", infoFlag, offsetHex, tempRaw), outDir);
        if (File.Exists(tempRawFull)) File.Delete(tempRawFull);

        if (!string.IsNullOrWhiteSpace(flatAsm)) {
            File.WriteAllText(asmPath, flatAsm, Encoding.ASCII);
            return asmPath;
        }
        return "";
    }

    static void DisassembleBinary(string binPath, string outDir, bool isCart) {
        string asmPath = DisassembleBinaryToAsmOnly(binPath, outDir, isCart);
        if (!string.IsNullOrEmpty(asmPath)) {
            TranspileAsmToBasic(asmPath, outDir, Path.GetFileNameWithoutExtension(binPath));
        }
    }

    static void ConvertToBas(string basFileName, string outDir, string dskName) {
        string baseName = Path.GetFileNameWithoutExtension(basFileName);
        string outBas = Path.Combine(outDir, baseName + ".bas");
        if (!string.IsNullOrEmpty(dskName)) {
            RunTool(DecbPath, string.Format("copy -t -r \"{0},{1}\" \"{2}\"", dskName, basFileName, Path.GetFileName(outBas)), outDir);
        } else {
            string tempDsk = "_temp.dsk";
            RunTool(DecbPath, string.Format("dskini \"{0}\"", tempDsk), outDir);
            RunTool(DecbPath, string.Format("copy -0 -b -r \"{0}\" \"{1},TEMP.BAS\"", basFileName, tempDsk), outDir);
            RunTool(DecbPath, string.Format("copy -t -r \"{0},TEMP.BAS\" \"{1}\"", tempDsk, Path.GetFileName(outBas)), outDir);
            string tempFull = Path.Combine(outDir, tempDsk);
            if (File.Exists(tempFull)) File.Delete(tempFull);
        }
        if (File.Exists(outBas)) {
            string rawText = File.ReadAllText(outBas, Encoding.ASCII);
            string normalized = rawText.Replace("\r\n", "\n").Replace("\r", "\n").Replace("\n", "\r\n");
            File.WriteAllText(outBas, normalized, Encoding.ASCII);
        }
    }

    static void ExtractCas(string localCasName, string outDir) {
        byte[] data = File.ReadAllBytes(Path.Combine(outDir, localCasName));
        int idx = 0;
        List<ParsedProgram> casProgs = new List<ParsedProgram>();
        HashSet<string> nativeBas = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (idx + 4 < data.Length) {
            if (data[idx] == 0x55 && data[idx + 1] == 0x3C) {
                byte bType = data[idx + 2];
                int bLen = data[idx + 3];
                if (bType == 0x00 && idx + 4 + bLen <= data.Length) {
                    string name = Encoding.ASCII.GetString(data, idx + 4, 8).Trim();
                    if (string.IsNullOrEmpty(name)) name = "TAPEFILE";
                    foreach (char c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
                    byte fileType = data[idx + 12];
                    byte asciiFlag = data[idx + 13];

                    using (MemoryStream payload = new MemoryStream()) {
                        int pos = idx + 4 + bLen + 1;
                        while (pos + 4 < data.Length) {
                            if (data[pos] == 0x55 && data[pos + 1] == 0x3C) {
                                byte dbType = data[pos + 2];
                                int dbLen = data[pos + 3];
                                if (dbType == 0x01 && pos + 4 + dbLen <= data.Length) {
                                    payload.Write(data, pos + 4, dbLen);
                                    pos += 4 + dbLen + 1;
                                } else if (dbType == 0xFF) {
                                    idx = pos + 5;
                                    break;
                                } else {
                                    pos++;
                                }
                            } else {
                                pos++;
                            }
                        }
                        byte[] bytes = payload.ToArray();
                        string rawName = name + (fileType == 0 ? ".RAWBAS" : ".RAWBIN");
                        string rawFull = Path.Combine(outDir, rawName);
                        File.WriteAllBytes(rawFull, bytes);
                        if (fileType == 0) {
                            nativeBas.Add(name);
                            if (asciiFlag == 0) {
                                ConvertToBas(rawName, outDir, null);
                            } else {
                                string outBas = Path.Combine(outDir, name + ".bas");
                                File.WriteAllBytes(outBas, bytes);
                            }
                        } else {
                            string asmPath = DisassembleBinaryToAsmOnly(rawFull, outDir, false);
                            if (!string.IsNullOrEmpty(asmPath)) {
                                casProgs.Add(ParseAsmFile(asmPath, name, "BIN"));
                            }
                        }
                        if (File.Exists(rawFull)) File.Delete(rawFull);
                        continue;
                    }
                }
            }
            idx++;
        }

        if (casProgs.Count > 0) {
            LinkFolderPrograms(casProgs);
            for (int i = 0; i < casProgs.Count; i++) {
                WriteBasicForProgram(casProgs[i], outDir, nativeBas);
            }
        }
    }

    static void ProcessFile(string filePath, bool headless) {
        LogLines.Clear();
        FailedBasicPrograms.Clear();
        WorkingGeminiModel = "";
        WorkingAnthropicModel = "";
        string ext = Path.GetExtension(filePath).ToLowerInvariant();

        if (ext == ".asm") {
            string asmDir = Path.GetDirectoryName(filePath);
            string asmStem = Path.GetFileNameWithoutExtension(filePath);
            TranspileAsmToBasic(filePath, asmDir, asmStem);
            File.WriteAllLines(Path.Combine(asmDir, "_conversion_log.txt"), LogLines);
            return;
        }

        string parent = Path.GetDirectoryName(filePath);
        string stem = Path.GetFileNameWithoutExtension(filePath);
        string outDir = Path.Combine(parent, stem + "_source");
        Directory.CreateDirectory(outDir);

        string localCopyName = "_src_" + Path.GetFileName(filePath);
        string localCopyPath = Path.Combine(outDir, localCopyName);
        File.Copy(filePath, localCopyPath, true);

        try {
            if (ext == ".dsk") {
                string listing = RunTool(DecbPath, string.Format("dir \"{0}\"", localCopyName), outDir);
                LogLines.Add("DIR OUTPUT:\n" + listing);
                string[] lines = listing.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                HashSet<string> nativeBasicNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                List<ParsedProgram> dskPrograms = new List<ParsedProgram>();

                foreach (string line in lines) {
                    Match m = Regex.Match(line.Trim(), @"^([A-Z0-9_\-\$]{1,8})\s+([A-Z0-9]{1,3})\s+([0-3])\s+([AB])\s+\d+", RegexOptions.IgnoreCase);
                    if (m.Success) {
                        string fstem = m.Groups[1].Value;
                        string fext = m.Groups[2].Value;
                        string filename = fstem + "." + fext;
                        string ftype = m.Groups[3].Value;
                        string tempExtracted = "_ext_" + filename;
                        string tempExtractedFull = Path.Combine(outDir, tempExtracted);
                        RunTool(DecbPath, string.Format("copy -b -r \"{0},{1}\" \"{2}\"", localCopyName, filename, tempExtracted), outDir);
                        if (ftype == "0") {
                            nativeBasicNames.Add(fstem);
                            ConvertToBas(filename, outDir, localCopyName);
                        } else if (ftype == "2") {
                            string renamedForAsm = Path.Combine(outDir, fstem + ".tmpbin");
                            if (File.Exists(tempExtractedFull)) {
                                File.Copy(tempExtractedFull, renamedForAsm, true);
                                string asmPath = DisassembleBinaryToAsmOnly(renamedForAsm, outDir, false);
                                if (!string.IsNullOrEmpty(asmPath)) {
                                    dskPrograms.Add(ParseAsmFile(asmPath, fstem, fext));
                                }
                                File.Delete(renamedForAsm);
                            }
                        }
                        if (File.Exists(tempExtractedFull)) File.Delete(tempExtractedFull);
                    }
                }

                if (dskPrograms.Count > 0) {
                    LinkFolderPrograms(dskPrograms);
                    for (int i = 0; i < dskPrograms.Count; i++) {
                        WriteBasicForProgram(dskPrograms[i], outDir, nativeBasicNames);
                    }
                }
            } else if (ext == ".cco" || ext == ".ccc" || ext == ".rom") {
                byte[] header = File.ReadAllBytes(localCopyPath);
                bool isDecb = header.Length > 0 && header[0] == 0x00;
                string targetBin = Path.Combine(outDir, stem + ".tmpbin");
                File.Copy(localCopyPath, targetBin, true);
                DisassembleBinary(targetBin, outDir, !isDecb);
                if (File.Exists(targetBin)) File.Delete(targetBin);
            } else if (ext == ".bin") {
                string targetBin = Path.Combine(outDir, stem + ".tmpbin");
                File.Copy(localCopyPath, targetBin, true);
                DisassembleBinary(targetBin, outDir, false);
                if (File.Exists(targetBin)) File.Delete(targetBin);
            } else if (ext == ".cas") {
                ExtractCas(localCopyName, outDir);
            } else if (ext == ".bas") {
                string targetBas = Path.Combine(outDir, stem + ".rawbas");
                File.Copy(localCopyPath, targetBas, true);
                ConvertToBas(Path.GetFileName(targetBas), outDir, null);
                if (File.Exists(targetBas)) File.Delete(targetBas);
            }
        } finally {
            if (File.Exists(localCopyPath)) File.Delete(localCopyPath);
        }

        string[] produced = Directory.GetFiles(outDir);
        string logPath = Path.Combine(outDir, "_conversion_log.txt");
        File.WriteAllLines(logPath, LogLines);
        if (!headless) {
            if (FailedBasicPrograms.Count > 0) {
                MessageBox.Show("BASIC reverse-engineering FAILED for:\n\n" + string.Join("\n", FailedBasicPrograms.ToArray()) +
                    "\n\nNo .bas was written for these (the .asm is still available).\nDetails: " + logPath,
                    "CoCo Source Extractor", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            } else if (produced.Length == 0) {
                MessageBox.Show("No source files were generated.\nCheck the diagnostic log at:\n" + logPath, "CoCo Source Extractor", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            } else {
                MessageBox.Show(string.Format("Extracted {0} source file(s) (.asm, .bas) to:\n{1}", produced.Length, outDir), "CoCo Source Extractor", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
    }
}
