// ghidra/scripts/gh_init_unrom.java
// Compile-less Ghidra script (Java) — run via analyzeHeadless -postScript
// Responsibility: Ensure UNROM memory layout: $8000-$BFFF (switchable), $C000-$FFFF (fixed last bank)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;

public class gh_init_unrom extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        Memory mem = program.getMemory();
        // TODO: Detect PRG banks created by GhidraNes loader.
        // Example approach:
        // - Enumerate MemoryBlocks with names like "PRGxx"
        // - Ensure address ranges align to 0x8000-0xBFFF (overlay/switchable) and 0xC000-0xFFFF (fixed)
        // - Optionally create Overlay blocks or rebase blocks to target addresses.
        println("[gh_init_unrom] start");
        for (MemoryBlock b : mem.getBlocks()) {
            println(" block: " + b.getName() + " @" + b.getStart());
        }
        // NOTE: Implementation is project-specific. Keep as placeholder.
        println("[gh_init_unrom] done");
    }
}
