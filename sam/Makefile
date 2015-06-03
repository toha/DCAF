MKDIR_P = mkdir -p
NAME=sam
OUT_DIR=build
SRC=src

CC=gcc
CFLAGS=-w -DWITH_POSIX
LDFLAGS=-ldl -L/usr/local/lib -lcrypto -lssl -ltinydtls -lcoap -lpthread -lm -ljansson -luriparser
TMPFLAGS=

SRCS=$(SRC)/http/http_srv.c $(SRC)/http/http_cfg_api.c $(SRC)/http/http_ticket_api.c $(SRC)/dao.c $(SRC)/models.c $(SRC)/tickets.c $(SRC)/revocation.c $(SRC)/commissioning.c $(SRC)/lib/mongoose/mongoose.c $(SRC)/lib/b64/b64.c $(SRC)/lib/riot-cbor/cbor.c $(SRC)/lib/coap-client/client.c $(SRC)/common.c
OBJS=$(SRC)/http/http_srv.o $(SRC)/http/http_cfg_api.o $(SRC)/http/http_ticket_api.o $(SRC)/dao.o $(SRC)/models.o $(SRC)/tickets.o $(SRC)/revocation.o $(SRC)/commissioning.o $(SRC)/lib/mongoose/mongoose.o $(SRC)/lib/b64/b64.o $(SRC)/lib/riot-cbor/cbor.o $(SRC)/lib/coap-client/client.o $(SRC)/common.o

all: builddir sam emptyconf

sam: $(OBJS)
	$(CC) $(CFLAGS) $(TMPFLAGS) -DNS_ENABLE_SSL -DNS_ENABLE_IPV6 -DUSE_IPV6 -DNS_ENABLE_THREADS -DMONGOOSE_NO_DAV -DMONGOOSE_NO_CGI -DMONGOOSE_NO_SSI -DMONGOOSE_NO_DIRECTORY_LISTING -lssl $(SRCS) $(SRC)/dcaf-sam.c -o $(OUT_DIR)/$(NAME) $(LDFLAGS)

emptyconf:
	cp conf/* build/

exampleconf:
	cp example_conf/* build/

# create build dir
builddir: ${OUT_DIR}

${OUT_DIR}:
	$(MKDIR_P) ${OUT_DIR}

clean:
	@- $(RM) $(OBJS)
	@- $(RM) -rf $(OUT_DIR)

.PHONY: builddir all clean
