# MILESTONES.md — NES(6502, UNROM) → Swift/Kotlin ネイティブ移植プロジェクト計画

> 本ファイルは**コピー＆ペースト**でそのまま運用できます。  
> 付属ドキュメント/雛形（`nes-porting-docs/`）に準拠しています。

## 伝説（Legend）
- ✅ = 完了
- ☐ = 未了
- 🔗 = 参照ファイル/コマンド
- 🧪 = 受け入れテスト
- ⚠️ = リスク/注意点

---

## マイルストーン一覧（概要）

| ID | マイルストーン | 目的 | 主要成果物 |
|---:|---|---|---|
| MS-0 | リポジトリ初期化 | 雛形配置・CI雛形・規約の統一 | `README.md`、`DESIGN.md`、`Makefile`、CI雛形 |
| MS-1 | 環境整備 | FCEUX/Ghidra/GhidraNes/LLM CLI の動作確認 | ツールバージョン固定、`tools/` 実行確認 |
| MS-2 | CDL 収集（最小ループ） | FCEUX CLI+Lua で .cdl 自動生成 | `cdl/*.cdl`、実行ログ |
| MS-3 | CDL 統合・網羅度測定 | 複数セッション OR マージ・カバレッジ算出 | `tools/merge_cdl.py` 実行、`out/meta/cdl_stats.json` |
| MS-4 | Ghidra headless 取込 | UNROM メモリレイアウト確立（ブロック/オーバーレイ） | Ghidra プロジェクト、ログ |
| MS-5 | CDL 適用（Code/Data分離） | `.cdl` をもとに逆アセン/byte[] 定義 | `gh_apply_cdl.java` 完成 |
| MS-6 | バンク間制御フロー再構築 | `$8000-$FFFF` 書込み→バンク切替→参照補正 | `gh_fix_crossbank_flow.java`、`callgraph.json/.dot` |
| MS-7 | ラベル/HLEタグ付与 | I/O ラベルと HLE 置換地点の注釈 | `out/meta/labels.json`、注釈入り逆アセン |
| MS-8 | LLM エージェント運用導入 | codex/Claude で Analyzer/Porter 実行基盤 | `agents.md`、`claude.md` に沿う実運用 |
| MS-9 | HLE 抽象API設計 | ppu/apu/controller/タイミング API 仕様確定 | `DESIGN.md` 追補、API スタブ |
| MS-10 | Swift/Kotlin スケルトン | 双方の最小ゲームループ＆HLEスタブ導入 | iOS/Android プロジェクト雛形 |
| MS-11 | 垂直スライス移植 | タイトル〜1面程度の完全移植 | 動作動画・🧪 回帰テスト |
| MS-12 | データ駆動化 & 追加ステージ | ROMテーブル抽出→外部データ化→新面追加 | ステージ定義（JSON/独自bin） |
| MS-13 | オンライン（Lockstep）PoC | 入力同期・決定論テスト | 最小2P同期デモ |
| MS-14 | 品質/パッケージング | テスト・最適化・配信準備 | QA レポート、配布ビルド |
| MS-15 | ドキュメント整備 | 最終ドキュメント、移譲資料 | `README.md` 更新、アーキ解説 |

---

## MS-0 リポジトリ初期化

**目的**: 雛形/規約/CI 雛形を整備し、以後のタスクを自動化しやすくする。
**エントリ条件**: なし
**完了条件**: 以降の Make ターゲットがローカルで実行可能

### タスク
- ✅ `nes-porting-docs/` の内容をリポジトリ直下へ配置（必要に応じてサブフォルダに集約）
- ✅ ライセンス/権利情報を `LICENSE/NOTICE` に明記（依頼元の合意反映）
- ✅ エディタ設定、コード規約（`.editorconfig`, lint 設定）追加
- ✅ CI 雛形（GitHub Actions 等）追加：Linux コンテナで `make all` が通るまで
- ✅ Issue/PR テンプレート、ラベルポリシー準備

**成果物**: 初期コミット、CI バッジ

**実績**: commit 2e28331 (2025-10-02)

---

## MS-1 環境整備

**目的**: FCEUX/Ghidra/GhidraNes/Graphviz/LLM CLI の最低限の動作を確認
**エントリ条件**: MS-0 完了
**完了条件**: 下記コマンドが成功しバージョンが固定

### タスク
- ✅ FCEUX インストール（`--loadlua` 利用可能を確認）
- ✅ Ghidra インストール（`support/analyzeHeadless` 実行確認）
- ⚠️ GhidraNes ローダ導入（iNES, UNROM 対応確認）— Java 17+必要
- ✅ Graphviz（`dot`）導入
- ✅ LLM CLI（Claude）導入（実行確認済み）
- ✅ `.env` に CLI コマンド名、モデル名等を設定（`.env.example` から作成）

**成果物**: `ENVIRONMENT.md`（導入手順、バージョン固定方法）

**実績**:
- commit 70fe871 (2025-10-02)
- FCEUX 2.6.6, Graphviz 14.0.0, Ghidra 11.4.2, Claude CLI
- tools/check_env.sh 追加
- Note: Ghidra実行にはJava 17+が必要（手動インストール）

---

## MS-2 CDL 収集（最小ループ）

**目的**: FCEUX CLI+Lua で `.cdl` を確実に出力
**エントリ条件**: MS-1 完了
**完了条件**: `cdl/zanac.cdl` が生成される

### タスク
- ✅ 🔗 `fceux/run_inputs.lua` をタイトル別に調整（CDLロギング追加）
- ✅ 🔗 `Makefile` 更新（.env読込、zanac.nes対応）
- ✅ CDL ファイルサイズ確認（ROMサイズ128KiBと一致）
- ⚠️ macOS版FCEUX GUI制約により手動収集推奨（docs/CDL_COLLECTION.md参照）

**成果物**:
- `cdl/zanac.cdl` (ダミーファイル作成済み、実データ収集は手動)
- `docs/CDL_COLLECTION.md` (手動収集手順)

**実績**:
- Luaスクリプト更新: CDLロギング機能追加
- Makefile更新: .env統合
- Note: macOS版FCEUXは`--nogui`非対応、GUI経由の手動収集を推奨

---

## MS-3 CDL 統合・網羅度測定

**目的**: 複数セッションの `.cdl` を OR マージし、カバレッジを定量化
**エントリ条件**: MS-2 完了
**完了条件**: 主要シーンの C/D ビット ≥ 目標（例: 95%）

### タスク
- ⚠️ シーン別に Lua スクリプトを用意（タイトル/ステージ1/ボス等）— 実CDL収集後
- ✅ 🔗 `tools/merge_cdl.py` で `.cdl` を OR マージ（既存）
- ✅ 🔗 `tools/analyze_cdl.py` 作成: CDL統計をJSON出力
- ✅ `.cdl` を解析し、C/D/カバレッジ統計を `out/meta/cdl_stats.json` に出力
- 🧪 主要関数領域に Code ビットが立っているかをサンプル確認（実CDL収集後）

**成果物**: 統合 `.cdl`、`out/meta/cdl_stats.json`

**実績**:
- tools/analyze_cdl.py 作成（CDL統計生成）
- out/meta/cdl_stats.json 生成（ダミーCDLで0%、実データ収集後に更新）
- Note: 実際のCDL収集は docs/CDL_COLLECTION.md 参照

---

## MS-4 Ghidra headless 取込（UNROMレイアウト）

**目的**: UNROM（$8000-$BFFF 可変、$C000-$FFFF 固定最終バンク）をメモリブロック/オーバーレイで表現  
**エントリ条件**: MS-3 完了  
**完了条件**: headless でインポート＆ブロック整列ログが取れる

### タスク
- ☐ 🔗 `ghidra/scripts/gh_init_unrom.java` の実装（PRG バンク列挙・再配置/オーバーレイ）
- ☐ 🔗 `make ghidra` 実行でログ確認
- 🧪 プログラムビューでブロック境界が仕様通り（可変/固定）になっていること

**成果物**: Ghidra プロジェクト、整列ログ

---

## MS-5 CDL 適用（Code/Data分離）

**目的**: `.cdl` を読み、連続区間単位で Code=逆アセン／Data=byte[] 定義  
**エントリ条件**: MS-4 完了  
**完了条件**: 指定範囲が正しく逆アセン/データ化される

### タスク
- ☐ 🔗 `ghidra/scripts/gh_apply_cdl.java` 実装：  
  - `.cdl` から PRG オフセット→メモリアドレスへの写像  
  - C=1 連続範囲は `disassemble()`、D=1 は `createData()`  
  - 競合時の優先順位ルール（Code優先など）を実装  
  - 補助ビット（AA/c/d 等）をコメント付与
- 🧪 既知のルーチンが Code として可視化されること

**成果物**: 逆アセン/データ定義済みの Ghidra DB

---

## MS-6 バンク間制御フロー再構築

**目的**: `$8000-$FFFF` 書込み（バンク選択）直後の制御遷移を適正なバンクへ補正  
**エントリ条件**: MS-5 完了  
**完了条件**: bank-aware な参照/フォールスルーが設定される

### タスク
- ☐ 🔗 `ghidra/scripts/gh_fix_crossbank_flow.java` 実装：  
  - `STA abs`（abs ∈ `$8000..$FFFF`）命令の検出  
  - 直前の `LDA #imm`、またはテーブル/間接指定から **バンク番号推定**  
  - 次の `JSR/JMP` / 次命令 PC の **fallthrough/参照** を該当バンクの同オフセットへ付替え  
  - 参照再解決・再解析を実行
- 🧪 切替後の関数呼び出しが正しいバンク先へ張り替わっていることをランダムサンプルで検証

**成果物**: 補正済み Ghidra DB、補正ログ

---

## MS-7 ラベル/HLEタグ付与

**目的**: I/O レジスタ名と HLE 置換地点を注釈し、後段の移植効率を上げる  
**エントリ条件**: MS-6 完了  
**完了条件**: 主要 I/O アクセスがラベル化・タグ付けされる

### タスク
- ☐ 🔗 `config/labels.json` を読み込み、$2000-$2007, $4000-$4017, $4016/$4017 へシンボル付与
- ☐ HLE 抽象API（`ppuWrite/ppuDMA/apuWrite/controllerRead/vblankTick`）の **置換候補**を命令列パターンでタグ付け（コメント）
- ☐ ラベル/タグ入り逆アセンを `out/asm/*.asm` にエクスポート
- 🧪 ランダム10箇所で I/O 名が期待通り表示されること

**成果物**: `out/asm/*.asm`, `out/meta/labels.json`（確定版）

---

## MS-8 LLM エージェント運用導入（codex / Claude）

**目的**: Analyzer/Mapper/Porter を CLI 経由で安全に回す運用  
**エントリ条件**: MS-7 完了  
**完了条件**: 1 関数を入力に Swift/Kotlin の雛形が生成される

### タスク
- ☐ 🔗 `agents.md` に従い、`Analyzer/Mapper/Porter` 各プロンプトをシェル化  
- ☐ `.env` で CLI 実体を設定（`CODEX_CMD`, `CLAUDE_CMD`）  
- ☐ `out/asm/XXXX.asm` + `labels.json` + `cdl_stats.json` を入力に Analyzer を実行  
- ☐ Mapper で HLE 置換表を生成  
- ☐ Porter で Swift/Kotlin の初期実装を生成（人手レビュー前提）
- 🧪 生成物がビルド通過（スタブレベル）する

**成果物**: `out/llm/*.md`（解析/置換/実装案）

---

## MS-9 HLE 抽象API設計

**目的**: プラットフォーム非依存の I/O/タイミング API を確定  
**エントリ条件**: MS-8 完了  
**完了条件**: Swift/Kotlin 両方に同等の API が存在

### タスク
- ☐ `ppuWrite/ppuDMA/ppuRead`, `apuWrite`, `controllerRead`, `vblankTick` の **引数/戻り値/副作用**を仕様化
- ☐ **エンティティ境界**（GameState/Renderer/Audio/Net）を簡素に定義
- ☐ `DESIGN.md` に API 仕様を追記
- 🧪 ダミー実装で Porter 生成コードがコンパイル通過

**成果物**: API 仕様、スタブコード

---

## MS-10 Swift/Kotlin スケルトン

**目的**: 双方の最小ゲームループ・HLE スタブ・テスト雛形  
**エントリ条件**: MS-9 完了  
**完了条件**: 空の画面で 60FPS ループと入力取得が動く

### タスク
- ☐ iOS: SwiftUI or UIKit + CADisplayLink で `update()` ループ  
- ☐ Android: Choreographer or Handler で `update()` ループ  
- ☐ HLE スタブを接続（ログ出力のみ）
- ☐ XCTest/JUnit の最小テスト導入
- 🧪 ループ安定（ドロップなし/負荷テストは後続）

**成果物**: iOS/Android プロジェクト雛形

---

## MS-11 垂直スライス移植（1面）

**目的**: タイトル→ゲーム開始→1面クリアまでの完走  
**エントリ条件**: MS-10 完了  
**完了条件**: 🧪 入力シナリオでオリジナル挙動と一致

### タスク
- ☐ 垂直スライスに必要な関数を優先移植（LLM+人手レビュー）  
- ☐ HLE で描画/音を最低限再現（PPU: タイル/スプライト、APU: 代替で可）  
- ☐ ゴールデントレース（FCEUX ログ）とネイティブの状態遷移を比較
- 🧪 期待フレーム数/スコア/位置が一致

**成果物**: 動作動画、差分レポート

---

## MS-12 データ駆動化 & 追加ステージ

**目的**: ROMテーブル抽出→外部データ化→新規ステージ投入  
**エントリ条件**: MS-11 完了  
**完了条件**: 追加ステージがビルド再配布なく差し替え可能

### タスク
- ☐ ステージ/敵配置/パラメータの抽出スクリプト  
- ☐ JSON/独自bin のスキーマ定義、ロード機構  
- ☐ 既存ステージの再現確認、新ステージの投入  
- 🧪 新/旧ステージ双方が動作

**成果物**: データ資産、ロードコード

---

## MS-13 オンライン（Lockstep）PoC

**目的**: 入力同期（決定論）で 2P 協調プレイ  
**エントリ条件**: MS-11 完了  
**完了条件**: ローカル/LAN で遅延許容内の同期確認

### タスク
- ☐ 入力バッファの交換（P2P or 中継）  
- ☐ 可変遅延時の入力遅延/ロールバック簡易対策  
- 🧪 2 クライアントで同一結果

**成果物**: PoC 実行手順、ログ

---

## MS-14 品質/パッケージング

**目的**: 最適化・安定性・配布準備  
**エントリ条件**: MS-11 以降  
**完了条件**: クラッシュ 0、主要端末で 60FPS

### タスク
- ☐ ホットパス最適化（アロケ/GC/描画バッチ）  
- ☐ クラッシュレポート・ログ整備  
- ☐ 配布設定（署名/設定/権利表記）  
- 🧪 負荷/長時間/端末多様性テスト

**成果物**: 配布ビルド、QA レポート

---

## MS-15 ドキュメント整備

**目的**: 技術移譲可能な最終資料  
**エントリ条件**: すべての作業にまたがる  
**完了条件**: 新規メンバーが 1 日で追従可能

### タスク
- ☐ `DESIGN.md` 最終版（アーキ/データ/API/制約）  
- ☐ `agents.md`/`claude.md` 更新（実サンプル、よくある誤読への対処）  
- ☐ 運用 Runbook（ビルド/デプロイ/リリース/緊急手順）  
- ☐ 既知課題/将来改善の Backlog リスト

**成果物**: ドキュメント一式

---

## 共通受け入れ条件（DoD）

- 🧪 `make cdl` → `make ghidra` が CI で安定実行  
- 🧪 `callgraph.json` が自己整合（未解決参照 0）  
- 🧪 HLE 置換候補が I/O レジスタ書読と 1:1 に紐付けられている  
- 🧪 垂直スライスの挙動一致を回帰テストで維持  
- 🧪 追加ステージが差し替え可能で動作

---

## リスクと緩和策（抜粋）

- ⚠️ **間接分岐/ジャンプテーブル**: CDL + パターン検出 + 人手/LLM 補完で参照候補を明示  
- ⚠️ **Ghidra 自動CFGの限界**: バンク切替はスクリプトで明示補正（フォールスルー/参照の張替え）  
- ⚠️ **UNROM 実機差**: 書込み時の値制約（バスコンフリクト）をコメント化し、HLE 側の API 仕様で回避方針を明記  
- ⚠️ **LLM 誤読**: `agents.md` にガードレール、🧪 人手レビュー/単体テストを必須化

---

## 運用コマンド例（再掲）

```bash
# CDL 収集（FCEUX）
make cdl

# Ghidra headless（UNROM整列→CDL適用→制御フロー補正）
make ghidra

# CDL マージ
tools/merge_cdl.py cdl/merged.cdl cdl/run1.cdl cdl/run2.cdl
