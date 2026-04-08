REPO_ROOT     := $(shell cd ../../../.. && pwd)
CARGO_PROFILE ?= debug
LIB_DIR       := $(REPO_ROOT)/target/$(CARGO_PROFILE)
INCLUDE_DIR   := $(REPO_ROOT)/crates/client-ffi
HEADER        := $(INCLUDE_DIR)/client_ffi.h

CC     ?= cc
CFLAGS := -Wall -Wextra -std=c11 -I$(INCLUDE_DIR)
LIBS   := -L$(LIB_DIR) -lclient_ffi -lpthread -ldl -lm

.PHONY: all run valgrind clean generate-headers _cargo

all: c-client

generate-headers:
	cargo run --manifest-path $(REPO_ROOT)/Cargo.toml \
	    -p client-ffi --bin generate-headers --features headers \
	    -- $(HEADER)

_cargo:
	cargo build --manifest-path $(REPO_ROOT)/Cargo.toml -p client-ffi \
	    $(if $(filter release,$(CARGO_PROFILE)),--release,)

c-client: src/main.c generate-headers _cargo
	$(CC) $(CFLAGS) src/main.c $(LIBS) -o c-client

run: c-client
	./c-client

valgrind: c-client
	valgrind \
	    --error-exitcode=1 \
	    --leak-check=full \
	    --errors-for-leak-kinds=definite,indirect \
	    --track-origins=yes \
	    ./c-client

clean:
	rm -f c-client $(HEADER)
