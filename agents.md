# agents.md — LLMエージェント運用設計（codex CLI / Claude Code）

この文書は **CLI から LLM を安全に運用**し、NES→Swift/Kotlin 移植を支援するためのエージェント設計です。
ツール前提は曖昧化し、コマンド名やフラグは **環境変数で差し替え**できるようにします。

## 環境変数
- `CODEX_CMD`  … codex CLI の実行コマンド名（例：`codex`）。
- `CLAUDE_CMD` … Claude Code の CLI コマンド名（例：`claude`）。
- `LLM_MODEL`  … 使用モデル（任意）。
- `LLM_OUTDIR` … 生成物の保存先（例：`out/llm`）。

## 役割分担（エージェント群）
1. **Analyzer**  
   - 入力: 関数単位の逆アセン（テキスト）、CDL統計、ラベル表  
   - 出力: 機能要約、入出力、副作用（I/O/HLEタグ）
2. **Mapper**  
   - 入力: Analyzer 出力  
   - 出力: **HLE 置換候補**（抽象APIへの写像表）
3. **Porter-Swift / Porter-Kotlin**  
   - 入力: Analyzer/Mapper 出力、関数逆アセン  
   - 出力: Swift/Kotlin の安全な初期実装（TODOコメント付き）
4. **Refactorer**  
   - 入力: 移植コード一式  
   - 出力: 構造化・命名改善・テスト観点の提示
5. **Tester**  
   - 入力: テスト仕様、同一入力列（将来は自動生成）  
   - 出力: 期待値との乖離レポート（差分ログ）

## プロンプト雛形（最小）
**Analyzer**
```
あなたは6502コード解析のエキスパートです。以下の逆アセンを読み、
(1) 機能要約 (2) 入力/出力/副作用 (3) 想定されるI/Oレジスタアクセス を列挙。
最後に HLE抽象API候補 (ppuWrite, controllerRead など) を提案。
---
{ASM_TEXT}
---
補足: ラベル表は {LABELS_JSON} を参照。
```

**Mapper**
```
以下の関数要約に基づき、HLE抽象APIへの置換点を表で示してください。
各行: {callsiteアドレス, 元命令, 推奨HLE API, 引数, 注意点}
---
{ANALYSIS_TEXT}
```

**Porter-Swift / Porter-Kotlin**
```
次の6502関数をSwift(Kotlin)で移植します。
HLE APIは既存です: ppuWrite, apuWrite, controllerRead, vblankTick。
副作用を伴う処理は上記APIで置換し、残りはロジックを安全に直訳。
---
{ASM_TEXT}
---
出力: 言語のコードブロックのみ。必要なTODO/注意点はコメントで明記。
```

## CLI 統合例（擬似）
- codex CLI 例: `echo "$PROMPT" | ${CODEX_CMD} --model "$LLM_MODEL" > out/llm/X.md`
- Claude CLI 例: `echo "$PROMPT" | ${CLAUDE_CMD} --model "$LLM_MODEL" > out/llm/X.md`

> 具体のフラグやサブコマンドは環境により異なるため、`.env` または CI 変数で設定してください。

## ガードレール
- 生成コードは必ず **人手レビュー**と **差分テスト**を実施。
- ツールが不確実な場合は **TODO** として明示、後続の検証対象に加える。
