# Hyperscan + mmap PoC. Requires libhyperscan-dev (in the dev image).
CFLAGS ?= -O2 -g -std=c11 -Wall -Wextra -Werror
OUT    ?= out
PATTERNS ?= 6000
PROCS  ?= 8

.PHONY: run clean

$(OUT)/hs_mmap_poc: hs_mmap_poc.c
	@mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< -o $@ $$(pkg-config --cflags --libs libhs)

run: $(OUT)/hs_mmap_poc
	$(OUT)/hs_mmap_poc compile $(OUT) $(PATTERNS)
	$(OUT)/hs_mmap_poc check $(OUT) $(PROCS)
	$(OUT)/hs_mmap_poc bench $(OUT) $(PROCS) none
	$(OUT)/hs_mmap_poc bench $(OUT) $(PROCS) private
	$(OUT)/hs_mmap_poc bench $(OUT) $(PROCS) shared
	$(OUT)/hs_mmap_poc robust $(OUT)
	$(OUT)/hs_mmap_poc platform $(OUT) $(PATTERNS)

clean:
	rm -rf $(OUT)
