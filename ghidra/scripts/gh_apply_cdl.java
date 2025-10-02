// ghidra/scripts/gh_apply_cdl.java
// Responsibility: Import .cdl (PRG side), mark code/data ranges, disassemble or define bytes accordingly.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class gh_apply_cdl extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: gh_apply_cdl.java <path/to/file.cdl>");
            return;
        }
        Path cdlPath = Paths.get(args[0]);
        byte[] cdl = Files.readAllBytes(cdlPath);
        Program program = currentProgram;
        Listing listing = program.getListing();
        Memory mem = program.getMemory();
        println("[gh_apply_cdl] bytes=" + cdl.length);

        // TODO: Map CDL offsets to PRG memory blocks created by loader.
        //      For each continuous range with Code bit=1 -> disassemble
        //      For Data bit=1 -> createData(byte array) if not already code.
        // NOTE: Precise bit layout may vary per emulator; adapt as needed.
        println("[gh_apply_cdl] marking ranges (placeholder)");
    }
}
