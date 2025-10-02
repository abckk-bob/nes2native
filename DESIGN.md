# DESIGN: NES UNROM → Swift/Kotlin ネイティブ移植

## ゴール
- NES(6502) ROM（UNROM/UxROM, Mapper 2）を対象に、**CLIのみ**で以下を自動化。
  1) FCEUX（--nogui + Lua）で CDL（実行・読取のバイト単位ログ）収集
  2) Ghidra（headless）＋ GhidraNes で UNROM のメモリマップを構築
  3) CDL を適用して **コード / データ** を厳密に分離（データは byte[] として定義）
  4) **$8000–$FFFF への書込み = PRG バンク選択**を検出し、**fallthrough/参照**を当該バンクへ補正
  5) **bank-aware callgraph** を JSON/DOT で出力
- 以降工程: 逆アセンとメタ情報（ラベル/HLEタグ/CFG）をもとに Swift/Kotlin の **ネイティブ移植**を段階的に実施。

## 前提
- **FCEUX ≥ 2.6.x**（`--nogui`, `--loadlua` 使用）
- **Ghidra ≥ 10.x**（`support/analyzeHeadless` 使用）
- **GhidraNes ローダ**（iNES 読込、UxROM 対応。各 PRG バンクを独立ブロック化）
- OS: Linux（CI での自動実行を想定）。

## アーキテクチャ概要
```
FCEUX (Lua自動入力)  ──→  *.cdl (PRG/CHRごとのビットマスク)
                               │
                               ▼
Ghidra Headless + GhidraNes  ──→  UNROMメモリ構築（$8000-$BFFF 可変, $C000-$FFFF 固定）
                               │
                               ├─ CDL適用：Code=逆アセン, Data=byte[] 定義, 付帯情報=コメント
                               │
                               ├─ バンク切替（$8000-$FFFF 書込）の検出 → fallthrough/参照補正
                               │
                               └─ bank-aware CallGraph 出力（JSON/DOT）
```

## UNROM（UxROM, Mapper 2）
- PRG: 16KB × N。**$8000–$BFFF** が **選択バンク**、**$C000–$FFFF** は **最終バンク固定**（一般的）。
- バンク選択: **$8000–$FFFF への書込み**で、$8000–$BFFF にマップする PRG バンク番号を選択（UNROM: 3bit が目安）。

## CDL（Code/Data Log）の活用
- `.cdl` は ROM バイトごとのビットマスク。主に **C=コード実行**, **D=データ読取** を使用。
- 複数セッションは **OR 結合**で網羅度を上げる（`tools/merge_cdl.py`）。
- 運用指針: タイトル〜複数ステージまでの **自動入力**で動作領域をカバー → 後続で未踏域を追加走行。

## Ghidra headless スクリプト群（役割）
- `gh_init_unrom.java`: UxROM 前提でメモリブロックを整列（オーバーレイ/リベースの適用）。
- `gh_apply_cdl.java`: `.cdl` を読み、**Code=逆アセン**, **Data=byte[]** を範囲単位で定義。コメントに補助情報を付記。
- `gh_fix_crossbank_flow.java`: **$8000–$FFFF 書込**命令列を検出。直後の `JSR/JMP` / 次命令の **fallthrough/参照**を選択バンク空間へ付替え。最終的に **callgraph.json** を出力。

## 生成物
- `out/cfg/callgraph.json`: bank-aware コールグラフ
- `out/asm/*.asm`: 関数単位の逆アセン（必要に応じて）
- `out/meta/labels.json`: I/O ラベル（$2000–$2007 PPU, $4000–$4017 APU, $4016/$4017）
- `out/meta/cdl_stats.json`: CDL カバレッジの統計
- `out/swift/`: Swift 移植コード（`SWIFT_OUTDIR` で変更可能）
- `out/kotlin/`: Kotlin 移植コード（`KOTLIN_OUTDIR` で変更可能）

## HLE 置換ポリシー（移植先で適用）
- ハード依存 API を抽象化:
  - `ppuWrite(reg,val)`, `ppuDMA(addr)`, `apuWrite(reg,val)`, `controllerRead(port)`, `vblankTick()`
- 逆アセンに **HLEタグ** を付け、Swift/Kotlin 実装へ置換する場所を明確にする。
- データ駆動化: ROM テーブルを抽出し JSON/独自 bin で管理。新ステージ追加を容易化。

## 受け入れ基準（例）
- CDL カバレッジ（PRG C/D 合算） ≥ 95%
- バンク切替直後の参照補正が一貫し、`callgraph.json` が自己矛盾なし
- I/O ラベルと HLE タグの整備完了

## リスクと緩和
- **間接分岐/ジャンプテーブル**: CDL と静的解析の両輪でアドレス候補を洗い出し、補助エッジを追加。
- **自動CFGの限界**: バンク切替はスクリプトで明示補正。ユニットテストで検証。
- **UNROMの実機差**: 書込時のバス特性差異に注意（ROM内容と同値書込想定の系など）。
