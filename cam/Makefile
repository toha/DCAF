MKDIR_P = mkdir -p
NAME=cam
OUT_DIR=build
SRC=src

CC=gcc
CFLAGS=-w -std=c99 -DWITH_POSIX -DNDEBUG -DHAVE_NO_BUILTIN_BSWAP16
LDFLAGS=-ldl -L/usr/local/lib -ltinydtls -lcurl -lcoap -lpthread -lm -ljansson -luriparser
TMPFLAGS=

SRCS=$(SRC)/lib/riot-cbor/cbor.c $(SRC)/common.c $(SRC)/coap_app.c
OBJS=$(SRC)/lib/riot-cbor/cbor.o $(SRC)/common.o $(SRC)/coap_app.o

all: builddir cam

cam: $(OBJS)
	$(CC) $(CFLAGS) $(TMPFLAGS) $(SRCS) $(SRC)/cam.c -o $(OUT_DIR)/$(NAME) $(LDFLAGS)
	cp conf/* build/

# create build dir
builddir: ${OUT_DIR}

${OUT_DIR}:
	$(MKDIR_P) ${OUT_DIR}

clean:
	@- $(RM) $(OBJS)
	@- $(RM) -rf $(OUT_DIR)

.PHONY: builddir all clean
