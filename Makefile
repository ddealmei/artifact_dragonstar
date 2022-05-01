CC=gcc
CFLAGS += -O3 # -DDEBUG # -DPERF
BIN=bin/sae_dragonstar bin/sae_dragonfly

HACL_dir=$(PWD)/haclstar
OPENSSL_local_dir=/opt/local_install
REF_IMPLEM_dir=$(PWD)/src/ref/
DRAGONSTAR_IMPLEM_dir=$(PWD)/src/dragonstar

LDFLAGS_HACL=-L$(HACL_dir)/gcc-compatible -Wl,-rpath=$(HACL_dir)/gcc-compatible -levercrypt
INCLUDE_HACL=-I$(DRAGONSTAR_IMPLEM_DIR)/ -I$(HACL_dir)/gcc-compatible -I$(HACL_dir)/kremlin/kremlib/dist/minimal/

SOURCES_openssl := $(shell find $(REF_IMPLEM_dir)/ -name "*.c")
OBJECTS_openssl := $(patsubst $(REF_IMPLEM_dir)/%.c, $(REF_IMPLEM_dir)/%.o, $(SOURCES_openssl))

SOURCES_dragonstar := $(wildcard $(DRAGONSTAR_IMPLEM_dir)/*.c)
OBJECTS_dragonstar  := $(patsubst $(DRAGONSTAR_IMPLEM_dir)/%.c, $(DRAGONSTAR_IMPLEM_dir)/%.o, $(SOURCES_dragonstar))

# Compile with OpenSSL-noasm
ifeq ($(NOASM), 1)
	LDFLAGS_OPENSSL=-L$(OPENSSL_local_dir)/lib -Wl,-rpath=$(OPENSSL_local_dir)/lib
	INCLUDE_OPENSSL=-I$(OPENSSL_local_dir)/include
	BIN += bin/sae_dragonfly-noasm
endif

all: $(BIN)

bin/sae_dragonfly: $(OBJECTS_openssl)
	mkdir -p bin
	$(CC) $(CFLAGS) $^ -lcrypto -o $@

bin/sae_dragonfly-noasm: $(OBJECTS_openssl)
	mkdir -p bin
	$(CC) $(CFLAGS) $(INCLUDE_OPENSSL) $^ $(LDFLAGS_OPENSSL) -lcrypto -o $@

bin/sae_dragonstar: $(OBJECTS_dragonstar) $(HACL_dir)/gcc-compatible/libevercrypt.so
	mkdir -p bin
	$(CC) $(CFLAGS) $(INCLUDE_HACL) $^ $(LDFLAGS_HACL) -lcrypto -o $@

$(HACL_dir)/gcc-compatible/libevercrypt.so:
	cd $(HACL_dir)/gcc-compatible ; ./configure
	make -C $(HACL_dir)/gcc-compatible CC=clang -j libevercrypt.so

$(OPENSSL_IMPLEM_dir)/%.o: $(OPENSSL_IMPLEM_dir)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(DRAGONSTAR_IMPLEM_dir)/%.o: $(DRAGONSTAR_IMPLEM_dir)/%.c
	$(CC) $(CFLAGS) $(INCLUDE_HACL) -c $< -o $@

clean: clean_hacl clean_ref clean_dragonstar

clean_bin: 
	rm -rf ./bin/*

clean_hacl:
	make -C $(HACL_dir)/gcc-compatible clean

clean_dragonstar:
	rm -f $(OBJECTS_dragonstar)

clean_ref:
	rm -f $(OBJECTS_openssl) 
