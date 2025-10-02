# claude.md — Claude Code 運用手順（ガイド）

この文書は、Claude Code を **CLI またはエディタ連携**で運用する前提の開発ガイドです。

## プロジェクト構成
```
nes2native/
├── DESIGN.md                    # 設計文書（UNROMバンク処理、CDL活用、HLE戦略）
├── README.md                    # 概要（各ドキュメントへの索引）
├── agents.md                    # LLMエージェント役割定義（codex/Claude両対応）
├── CLAUDE.md                    # 本書（Claude Code固有の運用手順）
├── Makefile                     # CDL収集・Ghidra解析の実行雛形
├── fceux/run_inputs.lua         # FCEUX自動入力スクリプト（CDL収集）
├── ghidra/scripts/              # Ghidra headlessスクリプト群
│   ├── gh_init_unrom.java       # UNROMメモリレイアウト初期化
│   ├── gh_apply_cdl.java        # CDL適用（Code/Data分離）
│   └── gh_fix_crossbank_flow.java # バンク切替補正・callgraph生成
├── schemas/callgraph.schema.json # bank-aware callgraphのJSON Schema
├── config/labels.json           # NES I/Oレジスタラベル定義（PPU/APU/INPUT）
└── tools/merge_cdl.py           # 複数CDLのOR結合スクリプト
```

## 推奨ワークフロー
1. **前処理（自動化）**
   - `make cdl`: FCEUX（--nogui）で `fceux/run_inputs.lua` 実行 → CDL収集
   - `make ghidra`: Ghidra headless で UNROM解析 → `out/cfg/callgraph.json` 生成
   - 複数CDLがある場合は `tools/merge_cdl.py` でOR結合し網羅度向上

2. **入力整形（LLMへ）**
   - `out/asm/` に関数単位の逆アセンを保存（長すぎる場合は分割）
   - `config/labels.json`（I/Oラベル）と `out/meta/cdl_stats.json` を併記
   - 必要に応じて `out/cfg/callgraph.json` の抜粋を追加（制御フロー文脈）

3. **タスク指示（Analyzer→Mapper→Porter）**
   - 役割別のプロンプト雛形を `agents.md` から流用
   - 1タスク=1関数を基本単位にし、レビュー→小刻みにマージ
   - HLE API: `ppuWrite(reg,val)`, `ppuDMA(addr)`, `apuWrite(reg,val)`, `controllerRead(port)`, `vblankTick()`

4. **出力検証**
   - 生成コードに対し、静的検査（lint）と単体テストを実行
   - 差分が大きい場合はプロンプトに失敗要因を追記して再実行

## プロンプトの実務指針
- **具体性**: 逆アセン断片に `config/labels.json` の **I/Oラベル** と **HLE API** を例示
- **境界条件**: 範囲外アクセス/オーバーフローの扱いを明示
- **出力形式**: 「コードのみ」「表形式のみ」を指定して**ポスト処理を容易化**
- **バンク情報**: UNROM(Mapper 2)では $8000-$BFFF が可変、$C000-$FFFF が固定最終バンク。バンク切替は $8000-$FFFF への書込で検出（`gh_fix_crossbank_flow.java`）

## 失敗時の切り返し
- **長文化** → 入力を分割し前後文脈を箇条書きで要約して先頭に配置
- **I/O誤解** → `config/labels.json` 全文を追加、該当命令周辺 50〜80行を追補
- **構造不明** → `out/cfg/callgraph.json` の関連部分を抜粋して追記
- **間接分岐** → ジャンプテーブル候補を `gh_fix_crossbank_flow.java` で補助エッジ追加（要手動調整）

## 生成物の受け入れ基準（例）
- CDL カバレッジ（PRG C/D 合算） ≥ 95%
- `callgraph.json` のバンク補正が自己矛盾なし（JSON Schema準拠）
- I/Oラベルと HLEタグの整備完了、移植先コードでの置換箇所が明確

## 関連文書
- 設計詳細・UNROMバンク戦略: `DESIGN.md`
- エージェント役割・プロンプト雛形: `agents.md`
- 全体索引: `README.md`
