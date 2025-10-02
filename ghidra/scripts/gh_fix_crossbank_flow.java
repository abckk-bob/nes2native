// ghidra/scripts/gh_fix_crossbank_flow.java
// UNROM バンク切替検出・制御フロー補正・callgraph生成
// - $8000-$FFFF への書込み = バンク選択
// - 直後のJSR/JMP、fallthroughを適切なバンクへリダイレクト
// - 最終的にcallgraph.jsonを出力

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import java.io.*;
import java.util.*;
import com.google.gson.*;

public class gh_fix_crossbank_flow extends GhidraScript {

    private static final long BANK_SWITCH_START = 0x8000L;
    private static final long BANK_SWITCH_END = 0xFFFFL;

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        Listing listing = program.getListing();
        AddressFactory af = program.getAddressFactory();

        println("[gh_fix_crossbank_flow] Analyzing bank switches");

        // $8000-$FFFF への書込み命令を検出
        List<BankSwitch> switches = detectBankSwitches();

        println("  Found " + switches.size() + " potential bank switches");

        // 各バンク切替について制御フローを補正
        for (BankSwitch sw : switches) {
            println("  Bank switch at $" + sw.address.toString() +
                   " (bank: " + sw.bankNumber + ")");
            // TODO: 実際の参照補正処理
            // - 直後のJSR/JMP先を補正
            // - fallthroughを補正
        }

        // Callgraph生成
        generateCallGraph();

        println("[gh_fix_crossbank_flow] Complete");
    }

    private List<BankSwitch> detectBankSwitches() {
        List<BankSwitch> switches = new ArrayList<>();
        Program program = currentProgram;
        Listing listing = program.getListing();

        InstructionIterator iter = listing.getInstructions(true);
        while (iter.hasNext() && !monitor.isCancelled()) {
            Instruction inst = iter.next();
            String mnemonic = inst.getMnemonicString().toUpperCase();

            // STA命令を検索
            if (mnemonic.equals("STA")) {
                Object[] objs = inst.getOpObjects(0);
                if (objs.length > 0 && objs[0] instanceof Address) {
                    Address target = (Address) objs[0];
                    long offset = target.getOffset();

                    // $8000-$FFFF への書込みか確認
                    if (offset >= BANK_SWITCH_START && offset <= BANK_SWITCH_END) {
                        // 直前のLDA命令からバンク番号を推定
                        int bankNum = inferBankNumber(inst);
                        switches.add(new BankSwitch(inst.getAddress(), bankNum));
                    }
                }
            }
        }

        return switches;
    }

    private int inferBankNumber(Instruction bankSwitchInst) {
        // 直前のLDA #imm を探す（簡易版）
        try {
            Instruction prev = bankSwitchInst.getPrevious();
            if (prev != null && prev.getMnemonicString().toUpperCase().equals("LDA")) {
                Object[] objs = prev.getOpObjects(0);
                if (objs.length > 0 && objs[0] instanceof Scalar) {
                    Scalar scalar = (Scalar) objs[0];
                    return (int) scalar.getValue();
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return -1; // 不明
    }

    private void generateCallGraph() throws IOException {
        Program program = currentProgram;
        FunctionManager funcMgr = program.getFunctionManager();

        List<CallGraphFunction> functions = new ArrayList<>();
        List<CallGraphEdge> calls = new ArrayList<>();

        // 全関数を列挙
        FunctionIterator funcIter = funcMgr.getFunctions(true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Address entry = func.getEntryPoint();

            functions.add(new CallGraphFunction(
                func.getName(),
                entry.toString(),
                0  // TODO: バンク番号を正確に取得
            ));

            // この関数からの呼び出しを列挙
            Set<Function> calledFuncs = func.getCalledFunctions(monitor);
            for (Function called : calledFuncs) {
                calls.add(new CallGraphEdge(
                    entry.toString(),
                    called.getEntryPoint().toString(),
                    "jsr",
                    0  // TODO: 経由バンク番号
                ));
            }
        }

        // JSON出力
        CallGraph graph = new CallGraph(functions, calls);
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(graph);

        File outFile = new File("out/cfg/callgraph.json");
        outFile.getParentFile().mkdirs();

        try (FileWriter writer = new FileWriter(outFile)) {
            writer.write(json);
        }

        println("  Callgraph written to: " + outFile.getAbsolutePath());
    }

    // 内部クラス
    private static class BankSwitch {
        Address address;
        int bankNumber;

        BankSwitch(Address address, int bankNumber) {
            this.address = address;
            this.bankNumber = bankNumber;
        }
    }

    private static class CallGraphFunction {
        String name;
        String addr;
        int bank;

        CallGraphFunction(String name, String addr, int bank) {
            this.name = name;
            this.addr = addr;
            this.bank = bank;
        }
    }

    private static class CallGraphEdge {
        String from;
        String to;
        String type;
        int via_bank;

        CallGraphEdge(String from, String to, String type, int via_bank) {
            this.from = from;
            this.to = to;
            this.type = type;
            this.via_bank = via_bank;
        }
    }

    private static class CallGraph {
        List<CallGraphFunction> functions;
        List<CallGraphEdge> calls;

        CallGraph(List<CallGraphFunction> functions, List<CallGraphEdge> calls) {
            this.functions = functions;
            this.calls = calls;
        }
    }
}
