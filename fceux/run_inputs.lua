-- fceux/run_inputs.lua — CDL収集用の最小例

-- CDLロギング開始
emu.cdlogging("start", "cdl/zanac.cdl")

emu.speedmode("maximum")
emu.poweron(); emu.softreset()

-- タイトルスキップ例（必要に応じて調整）
for i=1,60 do
    joypad.set(1, {start=true})
    emu.frameadvance()
end

-- 単純移動（右へ）+ 攻撃
for i=1,6000 do
    joypad.set(1, {right=true, A=true})
    emu.frameadvance()
end

-- CDLロギング停止・保存
emu.cdlogging("stop")
print("CDL saved to cdl/zanac.cdl")

os.exit()
