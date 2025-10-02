# CDL収集手順（FCEUX）

## macOS版の制約

macOS版のFCEUX（Homebrew）はGUIベースのため、完全な無人実行が困難です。以下の手順で手動またはスクリプト補助でCDL収集を行います。

## 方法1: GUI手動収集（推奨）

### 手順

1. **FCEUXを起動**
   ```bash
   fceux zanac.nes
   ```

2. **CDLロギング開始**
   - メニュー: `Tools → Code/Data Logger`
   - `Start` ボタンをクリック
   - 保存先: `cdl/zanac.cdl`

3. **ゲームプレイ**
   - タイトル画面でSTARTボタン押下
   - ステージ1を数分プレイ（移動・攻撃・敵撃破）
   - 可能なら複数ステージをプレイ

4. **CDLロギング停止**
   - `Code/Data Logger` ウィンドウで `Stop` → `Save`

5. **ファイル確認**
   ```bash
   ls -lh cdl/zanac.cdl
   ```

---

## 方法2: Luaスクリプト自動収集（実験的）

### 手順

1. **FCEUXをLuaスクリプト付きで起動**
   ```bash
   fceux --loadlua fceux/run_inputs.lua zanac.nes
   ```

2. **動作確認**
   - スクリプトが自動で以下を実行:
     - CDLロギング開始
     - タイトルスキップ（60フレーム）
     - 右移動＋攻撃（6000フレーム = 約100秒）
     - CDLロギング停止・保存
     - `os.exit()` で終了

3. **問題が発生した場合**
   - macOS版はGUIが完全に無効化されず、手動で終了が必要な場合があります
   - その場合は方法1を使用してください

---

## 方法3: Linux/Windows版FCEUX（CI環境推奨）

Linux環境では`--nogui`フラグが正常動作します:

```bash
# Ubuntu/Debian
sudo apt install fceux
fceux --nogui 1 --loadlua fceux/run_inputs.lua zanac.nes
```

---

## CDLファイルの確認

収集後、以下で確認:

```bash
ls -lh cdl/zanac.cdl
file cdl/zanac.cdl
hexdump -C cdl/zanac.cdl | head -20
```

期待されるサイズ: PRG ROMサイズと同じ（zanac.nesは128KiB = 131072バイト）

---

## 複数セッションのマージ（MS-3）

異なるシーン（タイトル/ステージ1/ステージ2/ボス等）でCDLを複数回収集し、OR結合で網羅度を向上:

```bash
# セッション1: タイトル〜ステージ1
fceux zanac.nes  # → cdl/zanac_stage1.cdl

# セッション2: ステージ2以降
fceux zanac.nes  # → cdl/zanac_stage2.cdl

# マージ
python3 tools/merge_cdl.py cdl/zanac.cdl cdl/zanac_stage1.cdl cdl/zanac_stage2.cdl
```

---

## トラブルシューティング

### CDLファイルが生成されない
- `Code/Data Logger` で明示的に保存先を指定
- Luaスクリプト内の `emu.cdlogging()` 関数が使用できない可能性
  → GUI経由で手動収集

### サイズが0または異常に小さい
- ゲームが正常にロードされていない
- CDLロギングが開始されていない
- ゲームプレイ時間が短すぎる（最低5〜10分推奨）

### GUI版で`os.exit()`が動作しない
- macOS版の既知の問題
- 手動でウィンドウを閉じてください
