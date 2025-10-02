// ghidra/scripts/gh_apply_cdl.java
// CDL (Code/Data Log) 適用スクリプト
// - Code bit (0x01): 逆アセンブル
// - Data bit (0x02): byte配列として定義
// - 競合時はCode優先

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class gh_apply_cdl extends GhidraScript {

    private static final byte CDL_CODE = 0x01;
    private static final byte CDL_DATA = 0x02;
    private static final byte CDL_PCM_DATA = 0x04;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: gh_apply_cdl.java <path/to/file.cdl>");
            return;
        }

        Path cdlPath = Paths.get(args[0]);
        if (!Files.exists(cdlPath)) {
            printerr("ERROR: CDL file not found: " + cdlPath);
            return;
        }

        byte[] cdl = Files.readAllBytes(cdlPath);
        Program program = currentProgram;
        Listing listing = program.getListing();
        Memory mem = program.getMemory();
        AddressFactory af = program.getAddressFactory();
        AddressSpace space = af.getDefaultAddressSpace();

        println("[gh_apply_cdl] Loading CDL: " + cdlPath);
        println("  CDL size: " + cdl.length + " bytes");

        // PRGブロックを列挙してCDLをマップ
        MemoryBlock[] blocks = mem.getBlocks();
        int cdlOffset = 0;

        for (MemoryBlock block : blocks) {
            String name = block.getName();
            if (!name.startsWith("PRG") && !name.startsWith("prg")) {
                continue;
            }

            long blockSize = block.getSize();
            Address blockStart = block.getStart();

            println("  Processing " + name + " @ " + blockStart +
                   " (size: 0x" + Long.toHexString(blockSize) + ")");

            if (cdlOffset + blockSize > cdl.length) {
                println("    WARNING: CDL too small for this block, skipping");
                continue;
            }

            // CDLデータを解析して連続領域を特定
            List<CDLRegion> regions = analyzeRegions(cdl, cdlOffset, (int) blockSize);

            println("    Found " + regions.size() + " CDL regions");

            // 各領域を処理
            for (CDLRegion region : regions) {
                Address start = blockStart.add(region.offset);
                Address end = start.add(region.length - 1);

                if (region.isCode) {
                    // Code領域: 逆アセンブル
                    println("      CODE: $" + start.toString() + " - $" + end.toString() +
                           " (0x" + Integer.toHexString(region.length) + " bytes)");
                    disassembleRange(start, end);
                } else if (region.isData) {
                    // Data領域: byte配列として定義
                    println("      DATA: $" + start.toString() + " - $" + end.toString() +
                           " (0x" + Integer.toHexString(region.length) + " bytes)");
                    defineDataRange(start, region.length);
                }
            }

            cdlOffset += (int) blockSize;
        }

        println("[gh_apply_cdl] CDL application complete");
    }

    private List<CDLRegion> analyzeRegions(byte[] cdl, int offset, int length) {
        List<CDLRegion> regions = new ArrayList<>();
        int regionStart = 0;
        byte regionType = 0;

        for (int i = 0; i < length; i++) {
            byte flags = cdl[offset + i];
            boolean isCode = (flags & CDL_CODE) != 0;
            boolean isData = (flags & CDL_DATA) != 0;

            // Code優先（Code & Data の場合は Code として扱う）
            byte currentType = 0;
            if (isCode) {
                currentType = CDL_CODE;
            } else if (isData) {
                currentType = CDL_DATA;
            }

            // 領域の切り替わりを検出
            if (i == 0) {
                regionType = currentType;
                regionStart = 0;
            } else if (currentType != regionType) {
                // 前の領域を保存
                if (regionType != 0) {
                    regions.add(new CDLRegion(
                        regionStart,
                        i - regionStart,
                        (regionType & CDL_CODE) != 0,
                        (regionType & CDL_DATA) != 0
                    ));
                }
                regionStart = i;
                regionType = currentType;
            }
        }

        // 最後の領域を保存
        if (regionType != 0 && regionStart < length) {
            regions.add(new CDLRegion(
                regionStart,
                length - regionStart,
                (regionType & CDL_CODE) != 0,
                (regionType & CDL_DATA) != 0
            ));
        }

        return regions;
    }

    private void disassembleRange(Address start, Address end) {
        try {
            DisassembleCommand cmd = new DisassembleCommand(start, null, true);
            cmd.applyTo(currentProgram, monitor);
        } catch (Exception e) {
            println("      WARNING: Disassembly failed: " + e.getMessage());
        }
    }

    private void defineDataRange(Address start, int length) {
        try {
            Listing listing = currentProgram.getListing();
            DataType byteType = new ByteDataType();

            for (int i = 0; i < length; i++) {
                Address addr = start.add(i);
                // 既存のデータ/コードがあればクリア
                Data existing = listing.getDataAt(addr);
                if (existing != null) {
                    listing.clearCodeUnits(addr, addr, false);
                }
                listing.createData(addr, byteType);
            }
        } catch (Exception e) {
            println("      WARNING: Data definition failed: " + e.getMessage());
        }
    }

    // CDL領域を表す内部クラス
    private static class CDLRegion {
        int offset;
        int length;
        boolean isCode;
        boolean isData;

        CDLRegion(int offset, int length, boolean isCode, boolean isData) {
            this.offset = offset;
            this.length = length;
            this.isCode = isCode;
            this.isData = isData;
        }
    }
}
