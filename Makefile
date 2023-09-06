INSTALL_PATH			:=$(HOME)/usr/libexec/
OBG_NAME			:=obg
OBG_DEBUG_EXEC			:=target/debug/$(OBG_NAME)
OBG_RELEASE_EXEC		:=target/release/$(OBG_NAME)
OBG_EXEC			:=$(OBG_DEBUG_EXEC)
OBG_RUN				:=$(OBG_DEBUG_EXEC)
OBG_RUN				:=cargo run --bin $(OBG_NAME) --
PASSWORD			:="https://soundcloud.com/wave-mandala/home-of-the-future"
PLAINTEXT			:=plaintext.txt
CIPHERTEXT			:=ciphertext.txt
UNCIPHERTEXT			:=unciphertext.txt
export OBG_CONFIG		:=obg-config.yaml
export OBG_KEY0			:=obg-key0.yaml
export OBG_KEY1			:=obg-key1.yaml
export OBG_KEY2			:=obg-key2.yaml
export OBG_FILE			:=obg-file.yaml
export OBG_LOG			:=obg.log
export K9_UPDATE_SNAPSHOTS	:=1
all: test debug release

$(INSTALL_PATH):
	mkdir -p $@

$(OBG_RELEASE_EXEC): $(INSTALL_PATH)
	cargo build --release

$(OBG_DEBUG_EXEC): $(INSTALL_PATH)
	cargo build

release: check fix | $(OBG_RELEASE_EXEC)
	install $(OBG_RELEASE_EXEC) $(INSTALL_PATH)

debug: check fix | $(OBG_DEBUG_EXEC)
	install $(OBG_DEBUG_EXEC) $(INSTALL_PATH)

clean: cls
	@rm -rf target

cleanx:
	@rm -rf $(OBG_DEBUG_EXEC)
	@rm -rf $(OBG_RELEASE_EXEC)

cls:
	-@reset || tput reset

fix:
	cargo fix

fmt:
	rustfmt --edition 2021 src/*.rs

check:
	cargo check --all-targets

run build test: check
	cargo $@

$(OBG_KEY0):
	rm -f $@
	$(OBG_RUN) keygen -p "awihcinok" -p tests/key.png -p tests/nothing.png -s tests/iv.png -s "slytherin" -o $@
	$(OBG_RUN) keygen -p "konichiwa" -p tests/key.png -p tests/nothing.png -s tests/iv.png -s "slytherin" -o $@ -f

$(OBG_KEY1):
	rm -f $@
	$(OBG_RUN) keygen -p tests/key.rst -s tests/iv.dat -o $@
	$(OBG_RUN) keygen -fp tests/key.rst -s tests/iv.dat -o $@

$(OBG_KEY2):
	rm -f $@
	dd if=/dev/random of="$$(pwd)/0password72.bin" bs=9 count=8
	dd if=/dev/random of="$$(pwd)/0salt.bin" bs=5 count=8
	$(OBG_RUN) keygen --password "$$(pwd)/password72.bin" --salt "$$(pwd)/salt.bin" --randomize-iv --cycles 37000 -o $@
	$(OBG_RUN) keygen --password "$$(pwd)/password72.bin" --salt "$$(pwd)/salt.bin" --randomize-iv --cycles 37000 -o $@ --force
	# obg keygen --password /dev/random --password-hwm 137 --salt "/dev/random" --salt-hwm 100 --randomize-iv --cycles 42 -o $@
	rm -f "$$(pwd)/salt.bin" "$$(pwd)/password72.bin"

e2e: cleanx
	cargo build
	@rm -f $(OBG_KEY0)
	$(MAKE) $(OBG_KEY0)
	$(OBG_RUN) encrypt text -k $(OBG_KEY0) "Hello World" > cipher.txt
	test "$$($(OBG_RUN) decrypt text -k $(OBG_KEY0) "$$(cat cipher.txt)")" = "Hello World"
	test "$$(cat cipher.txt | $(OBG_RUN) decrypt text -k $(OBG_KEY0))" = "Hello World"
	$(OBG_RUN) encrypt file -k $(OBG_KEY0) tests/testcases.yaml tests/testcases.cipher
	$(OBG_RUN) decrypt file -k $(OBG_KEY0) tests/testcases.cipher tests/testcases.plain
	diff tests/testcases.yaml tests/testcases.plain
	$(OBG_RUN) encrypt file -k $(OBG_KEY0) tests/plaintext.jpg tests/ciphertext.jpg
	$(OBG_RUN) decrypt file -k $(OBG_KEY0) tests/ciphertext.jpg tests/decrypted.jpg
	diff  tests/plaintext.jpg tests/decrypted.jpg
	@rm -f $(OBG_KEY1)
	$(MAKE) $(OBG_KEY1)
	$(OBG_RUN) encrypt text -k $(OBG_KEY1) "Hello World" > cipher.txt
	test "$$($(OBG_RUN) decrypt text -k $(OBG_KEY1) "$$(cat cipher.txt)")" = "Hello World"
	test "$$(cat cipher.txt | $(OBG_RUN) decrypt text -k $(OBG_KEY1))" = "Hello World"
	$(OBG_RUN) encrypt file -k $(OBG_KEY1) tests/testcases.yaml tests/testcases.cipher
	$(OBG_RUN) decrypt file -k $(OBG_KEY1) tests/testcases.cipher tests/testcases.plain
	diff tests/testcases.yaml tests/testcases.plain
	$(OBG_RUN) encrypt file -k $(OBG_KEY1) tests/plaintext.jpg tests/ciphertext.jpg
	$(OBG_RUN) decrypt file -k $(OBG_KEY1) tests/ciphertext.jpg tests/decrypted.jpg
	diff  tests/plaintext.jpg tests/decrypted.jpg
	@rm -f $(OBG_KEY2)
	$(MAKE) $(OBG_KEY2)
	$(OBG_RUN) encrypt text -k $(OBG_KEY2) "Hello World" > cipher.txt
	test "$$($(OBG_RUN) decrypt text -k $(OBG_KEY2) "$$(cat cipher.txt)")" = "Hello World"
	test "$$(cat cipher.txt | $(OBG_RUN) decrypt text -k $(OBG_KEY2))" = "Hello World"
	$(OBG_RUN) encrypt file -k $(OBG_KEY2) tests/testcases.yaml tests/testcases.cipher
	$(OBG_RUN) decrypt file -k $(OBG_KEY2) tests/testcases.cipher tests/testcases.plain
	diff tests/testcases.yaml tests/testcases.plain
	$(OBG_RUN) encrypt file -k $(OBG_KEY2) tests/plaintext.jpg tests/ciphertext.jpg
	$(OBG_RUN) decrypt file -k $(OBG_KEY2) tests/ciphertext.jpg tests/decrypted.jpg
	diff  tests/plaintext.jpg tests/decrypted.jpg

.PHONY: all clean cls release debug fix fmt check build test examples run-$(OBG_NAME)
