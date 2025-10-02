# Makefile — NES UNROM → Swift/Kotlin 移植 前処理
ROM ?= roms/GAME_UXROM.nes
CDL ?= cdl/GAME.cdl

.PHONY: cdl ghidra all clean

cdl:
	@echo "[FCEUX] collecting CDL..."
	fceux --nogui 1 --loadlua fceux/run_inputs.lua $(ROM)

ghidra:
	@echo "[Ghidra] headless analysis..."
	$(GHIDRA_HOME)/support/analyzeHeadless ghidra/proj NESProject \
	  -import $(ROM) \
	  -scriptPath ghidra/scripts \
	  -postScript gh_init_unrom.java \
	  -postScript gh_apply_cdl.java $(CDL) \
	  -postScript gh_fix_crossbank_flow.java \
	  -deleteProject false

all: cdl ghidra

clean:
	rm -rf ghidra/proj out/*
