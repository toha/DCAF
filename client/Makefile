########################################################################
# platform-specific options

ifeq ($(TARGET), econotag)
CFLAGS += -DUIP_CONF_TCP=0
endif

ifeq ($(TARGET), minimal-net)
UIP_CONF_IPV6_RPL=0
CFLAGS += -DUIP_CONF_IPV6_RPL=0 -DRPL_BORDER_ROUTER=0
endif

ifeq ($(TARGET), mbxxx)
STM32W_CPUREV=CC
UIP_CONF_IPV6_RPL=0
CFLAGS += -DPLATFORM_HAS_BUTTON -DPLATFORM_HAS_LEDS #-DPLATFORM_HAS_SERIAL
endif

# usually, you should not need changing anything beyond this line
########################################################################


CONTIKI=../../..
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

UIP_CONF_IPV6=1

CFLAGS += -ffunction-sections -DCBOR_NO_FLOAT -DCBOR_NO_PRINT -DCBOR_NO_SEMANTIC_TAGGING
CFLAGS += -DNDEBUG
#CFLAGS += -DDCAF_TIME
CFLAGS += -DDCAF_DEBUG
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DSHA2_USE_INTTYPES_H

APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls
APPS += cn-cbor
APPS += libcoap
#APPS += powertrace

all: dcaf-client

PROJECT_SOURCEFILES = common.c

include $(CONTIKI)/Makefile.include
