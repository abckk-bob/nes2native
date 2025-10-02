# NES (6502, UNROM) → Swift/Kotlin ネイティブ移植ドキュメント

**最終更新:** 2025-10-02 04:00 UTC

このパッケージは、FCEUX（CLI＋Lua）で CDL(Code/Data Log) を収集し、Ghidra（headless）＋ GhidraNes ローダで
UNROM(Mapper 2) のバンク分割・コード/データ分離・制御フロー再構築を自動化するためのドキュメントと雛形スクリプト群です。
目的は **エミュレーションではなくネイティブ移植**（Swift/Kotlin）です。

- 設計文書: `DESIGN.md`
- エージェント運用: `agents.md`（codex CLI / Claude Code 両対応の役割設計）
- Claude Code 個別運用: `claude.md`
- 実行雛形: `fceux/run_inputs.lua`, `ghidra/scripts/*.java`, `Makefile`
- 生成物仕様: `schemas/callgraph.schema.json` ほか
- LLM 連携サンプル: `tools/llm_prompt_template.md`, `tools/merge_cdl.py`
- 移植コード出力先: Swift=`out/swift`、Kotlin=`out/kotlin`（環境変数で上書き可）

> **注意**: 本パッケージは CLI/スクリプトの骨子・テンプレートを提供します。
> 各ツールのインストール・バージョン固定・パス設定は環境に合わせて調整してください。
