default:
	@echo "[*] Usage: make <os>"
	@echo "[*] Example: make linux"
	@echo "[*] Example: ARGS=clean make linux"

win:
	make -f Win.mk $(ARGS)

linux:
	make -f Linux.mk $(ARGS)

bsd:
	make -f BSD.mk $(ARGS)
