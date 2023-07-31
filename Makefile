INSTALL_PATH			:=$(HOME)/usr/libexec/
OBG_NAME			:=obg
OBG_DEBUG_EXEC			:=target/debug/$(OBG_NAME)
OBG_RELEASE_EXEC		:=target/release/$(OBG_NAME)
OBG_EXEC			:=$(OBG_RELEASE_EXEC)
OBG_RUN				:=cargo run --bin $(OBG_NAME) --
PASSWORD			:="https://soundcloud.com/wave-mandala/home-of-the-future"
PLAINTEXT			:=plaintext.txt
CIPHERTEXT			:=ciphertext.txt
UNCIPHERTEXT			:=unciphertext.txt
export OBG_CONFIG		:=.obg-config.yaml
export OBG_KEY			:=.obg-key.yaml
export OBG_FILE			:=.obg-file.yaml
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

$(OBG_KEY):
	$(OBG_RUN) keygen -p tests/key.png -s tests/iv.png -o $@

e2e:
	rm -f $(OBG_KEY)
	$(MAKE) $(OBG_KEY)
	$(OBG_RUN) decrypt text -k $(OBG_KEY) $$($(OBG_RUN) encrypt text -k $(OBG_KEY) "Hello World")
	$(OBG_RUN) encrypt file -k $(OBG_KEY) -i tests/plaintext.jpg -o tests/ciphertext.jpg


.PHONY: all clean cls release debug fix fmt check build test examples run-$(OBG_NAME)
