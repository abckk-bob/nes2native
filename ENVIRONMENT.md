# ENVIRONMENT.md — 環境構築ガイド

このドキュメントは、NES→Swift/Kotlin移植プロジェクトに必要なツール群のセットアップ手順を記載します。

## 必要ツール

### 1. FCEUX（NESエミュレータ）
- **バージョン**: 2.6.6 以上
- **用途**: CDL（Code/Data Log）収集
- **必須フラグ**: `--nogui`, `--loadlua`

#### macOS（Homebrew）
```bash
brew install fceux
fceux --help  # --nogui, --loadlua が利用可能か確認
```

#### Ubuntu/Debian
```bash
sudo apt install fceux
```

#### ソースビルド
```bash
git clone https://github.com/TASEmulators/fceux.git
cd fceux
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

#### 動作確認
```bash
fceux --nogui 1 --loadlua fceux/run_inputs.lua zanac.nes
# → cdl/zanac.cdl が生成されることを確認
```

---

### 2. Ghidra（リバースエンジニアリングツール）
- **バージョン**: 10.4 以上
- **用途**: UNROM解析・CFG再構築・callgraph生成

#### インストール
1. [Ghidra公式](https://ghidra-sre.org/)からダウンロード（JDK 17以上が必要）
2. 展開先を環境変数に設定:
```bash
export GHIDRA_HOME=/path/to/ghidra_10.x
echo "export GHIDRA_HOME=/path/to/ghidra_10.x" >> ~/.zshrc  # または ~/.bashrc
```

#### 動作確認
```bash
$GHIDRA_HOME/support/analyzeHeadless -help
# → ヘルプが表示されればOK
```

---

### 3. GhidraNes（Ghidraプラグイン）
- **用途**: iNES形式の読込・UNROMマッパー対応

#### インストール
```bash
git clone https://github.com/kylewlacy/GhidraNes.git
cd GhidraNes
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME
# → $GHIDRA_HOME/Extensions/Ghidra/ 以下に .zip がインストールされる
```

#### Ghidra側で有効化
1. Ghidraを起動: `$GHIDRA_HOME/ghidraRun`
2. **File → Install Extensions** → GhidraNes にチェック → 再起動

#### 動作確認
headlessモードでiNESファイルをインポートしてエラーが出ないこと:
```bash
$GHIDRA_HOME/support/analyzeHeadless /tmp/test_proj TestProj \
  -import zanac.nes -deleteProject
```

---

### 4. Graphviz（グラフ可視化）
- **用途**: callgraph.dot → PNG/SVG変換（オプション）

#### macOS
```bash
brew install graphviz
dot -V
```

**Note**: Ghidra requires Java 17+. If `brew install --cask temurin` fails due to sudo requirements, manually install from:
- https://adoptium.net/temurin/releases/ (select macOS ARM64, JDK 17+)
- After installation, verify: `java -version`

#### Ubuntu/Debian
```bash
sudo apt install graphviz
```

---

### 5. Python 3.9+
- **用途**: `tools/merge_cdl.py` など補助スクリプト

#### 動作確認
```bash
python3 --version  # 3.9以上
python3 tools/merge_cdl.py --help || python3 -c "import sys; print('OK')"
```

---

### 6. LLM CLI（Claude Code / codex）
- **用途**: 6502→Swift/Kotlin移植支援（Analyzer/Porter）

#### Claude Code CLI
公式ドキュメント: https://docs.claude.com/en/docs/claude-code

インストール後、`claude` コマンドが利用可能になります。

#### 設定（.env）
`.env.example` をコピーして `.env` を作成:
```bash
cp .env.example .env
```

編集例:
```bash
CLAUDE_CMD=claude
LLM_MODEL=claude-sonnet-4-5
LLM_OUTDIR=out/llm
```

---

## 環境変数まとめ（.env）

```bash
# ROM & CDL
ROM=zanac.nes
CDL=cdl/zanac.cdl

# Ghidra
GHIDRA_HOME=/Applications/ghidra_10.4_PUBLIC

# LLM
CLAUDE_CMD=claude
LLM_MODEL=claude-sonnet-4-5
LLM_OUTDIR=out/llm

# Output
OUT_ASM=out/asm
OUT_META=out/meta
OUT_CFG=out/cfg
```

---

## 受け入れ基準（MS-1完了条件）

- [ ] `fceux --version` が実行できる
- [ ] `$GHIDRA_HOME/support/analyzeHeadless -help` が実行できる
- [ ] GhidraNesがGhidraに認識されている（headlessでiNES読込可能）
- [ ] `dot -V` が実行できる（オプション）
- [ ] `python3 --version` が3.9以上
- [ ] `claude --version` または `codex --version` が実行できる（LLM CLI）
- [ ] `.env` が作成され、上記変数が設定済み

---

## トラブルシューティング

### FCEUX: `--nogui` が認識されない
- GUI版がインストールされている可能性。ソースビルドで `-DCMAKE_BUILD_TYPE=Release` を指定して再ビルド。

### Ghidra: analyzeHeadless で "No loader found"
- GhidraNesが正しくインストールされていない。`File → Install Extensions` で確認。

### Python: merge_cdl.py でエラー
- Python 3.9未満の場合は `brew upgrade python3` で更新。

---

## 次のステップ

MS-1完了後、**MS-2: CDL収集**へ進みます:
```bash
make cdl
```
