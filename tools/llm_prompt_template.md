# LLM Prompt Templates (codex / Claude 共通)

## Analyzer
あなたは6502/NESの逆アセン解析者です。以下の逆アセンから、機能要約・入出力・副作用・HLE置換候補を抽出。

Input:
- ASM: {{ASM_TEXT}}
- Labels: {{LABELS_JSON}}
- CDL: {{CDL_STATS_JSON}}

Output (Markdown):
- Summary
- Inputs/Outputs/Side-effects
- HLE candidates (table)
- Open questions (for human review)

## Porter (Swift/Kotlin)
6502関数を {{LANG}} で実装。HLE API (ppuWrite/apuWrite/controllerRead/vblankTick) を利用し、
I/O部分は抽象APIへ置換。残りはロジックの直訳を優先。コードのみ出力。
