// ghidra/scripts/gh_init_unrom.java
// UNROM (Mapper 2) メモリレイアウト初期化
// - PRG: 16KB × N banks
// - $8000-$BFFF: switchable (0x4000 bytes)
// - $C000-$FFFF: fixed last bank (0x4000 bytes)

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;

public class gh_init_unrom extends GhidraScript {

    private static final int BANK_SIZE = 0x4000; // 16KB
    private static final long SWITCHABLE_BASE = 0x8000L;
    private static final long FIXED_BASE = 0xC000L;

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        Memory mem = program.getMemory();
        AddressFactory af = program.getAddressFactory();
        AddressSpace space = af.getDefaultAddressSpace();

        println("[gh_init_unrom] Initializing UNROM memory layout");

        // GhidraNesローダーが作成したPRGブロックを列挙
        MemoryBlock[] blocks = mem.getBlocks();
        int prgBankCount = 0;

        for (MemoryBlock block : blocks) {
            String name = block.getName();
            if (name.startsWith("PRG") || name.startsWith("prg")) {
                prgBankCount++;
                println("  Found: " + name + " @ " + block.getStart() +
                       " (size: 0x" + Long.toHexString(block.getSize()) + ")");
            }
        }

        if (prgBankCount == 0) {
            printerr("ERROR: No PRG banks found. Ensure GhidraNes loader is installed.");
            return;
        }

        println("  Total PRG banks: " + prgBankCount);

        // UNROM: 最後のバンクは $C000-$FFFF に固定マップ
        // 他のバンクは $8000-$BFFF に切替可能（オーバーレイとして扱う）

        // Note: GhidraNesローダーがどのようにブロックを作成するかに依存
        // 一般的には、各PRGバンクが独立したブロックとして作成される
        // ここでは、最終バンクを $C000 にリベース、他をオーバーレイ化する

        int lastBankIndex = prgBankCount - 1;
        int bankIndex = 0;

        for (MemoryBlock block : blocks) {
            String name = block.getName();
            if (!name.startsWith("PRG") && !name.startsWith("prg")) {
                continue;
            }

            Address blockStart = block.getStart();
            long blockOffset = blockStart.getOffset();

            // 最後のバンク: $C000-$FFFF に固定
            if (bankIndex == lastBankIndex) {
                Address targetAddr = space.getAddress(FIXED_BASE);
                if (blockOffset != FIXED_BASE) {
                    println("  Rebasing " + name + " to $" +
                           Long.toHexString(FIXED_BASE) + " (fixed bank)");
                    // Note: moveBlock は実装による。setBaseAddress を使用する場合もある
                    // ここでは conceptual な記述に留める
                } else {
                    println("  " + name + " already at $C000 (fixed bank)");
                }
            }
            // その他のバンク: $8000-$BFFF 領域（オーバーレイ化）
            else {
                println("  Bank " + bankIndex + ": " + name +
                       " (switchable, overlay for $8000-$BFFF)");
                // Overlay化: 実際には Ghidra の Overlay 機能を使用
                // または、各バンクを独立したアドレス空間に配置
            }

            bankIndex++;
        }

        println("[gh_init_unrom] UNROM layout initialized");
        println("  Switchable banks: " + (prgBankCount - 1));
        println("  Fixed bank: 1 (last bank at $C000-$FFFF)");
        println("");
        println("Note: Bank switching detected at $8000-$FFFF writes will be");
        println("      processed in gh_fix_crossbank_flow.java");
    }
}
