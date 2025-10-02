-- fceux/run_inputs.lua — CDL収集用の最小例
emu.speedmode("maximum")
emu.poweron(); emu.softreset()

-- タイトルスキップ例（必要に応じて調整）
for i=1,60 do joypad.set(1, {start=true}); emu.frameadvance() end

-- 単純移動（右へ）
for i=1,6000 do joypad.set(1, {right=true}); emu.frameadvance() end

os.exit()
