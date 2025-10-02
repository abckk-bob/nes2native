// ghidra/scripts/gh_fix_crossbank_flow.java
// Responsibility: Detect bank-select writes ($8000-$FFFF), infer bank number, and
//                 fix fallthrough/refs to the selected PRG bank block. Then export callgraph.
import ghidra.app.script.GhidraScript;

public class gh_fix_crossbank_flow extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("[gh_fix_crossbank_flow] analyze bank selects and rebuild callgraph (placeholder)");
        // TODO:
        // 1) Scan instructions: STA abs where abs in [$8000,$FFFF]
        // 2) Backtrack previous LDA #imm to infer bank number
        // 3) Redirect subsequent JSR/JMP or next-PC fallthrough to the chosen bank block
        // 4) Emit callgraph.json under out/cfg/
    }
}
