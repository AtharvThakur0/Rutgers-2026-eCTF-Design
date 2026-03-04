MSPM0_SDK_INSTALL_DIR ?= $(abspath ../../../../../..)

include $(MSPM0_SDK_INSTALL_DIR)/tools/imports_mak/imports.mak.linux

CC = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
LNK = "$(TICLANG_ARMCOMPILER)/bin/tiarmclang"
OBJCOPY = "$(TICLANG_ARMCOMPILER)/bin/tiarmobjcopy"
BUILDDIR ?= /tmp/build
VPATH = "src"
LINKERFILE = "firmware.ld"

# wolfSSL is required for secure_crypto.c AES-GCM support.
# Prefer the build-container install at /opt/wolfssl and fall back to a
# local checkout in firmware/wolfssl for ad-hoc host builds.
WOLFSSL_DIR ?= $(if $(wildcard /opt/wolfssl/wolfssl/wolfcrypt/aes.h),/opt/wolfssl,$(if $(wildcard $(CURDIR)/wolfssl/wolfssl/wolfcrypt/aes.h),$(CURDIR)/wolfssl,))
ifeq ($(strip $(WOLFSSL_DIR)),)
$(error wolfSSL source tree not found. Rebuild the Docker image to install /opt/wolfssl, or clone wolfSSL into firmware/wolfssl)
endif

WOLFSSL_SRC_DIR = $(WOLFSSL_DIR)/wolfcrypt/src
WOLFSSL_CORE_SRCS = \
    $(WOLFSSL_SRC_DIR)/aes.c \
    $(WOLFSSL_SRC_DIR)/misc.c
WOLFSSL_CORE_OBJECTS = $(patsubst $(WOLFSSL_SRC_DIR)/%.c,$(BUILDDIR)/wolfssl_%.o,$(WOLFSSL_CORE_SRCS))
WOLFSSL_EXAMPLE_SRCS = \
    $(WOLFSSL_SRC_DIR)/hash.c \
    $(WOLFSSL_SRC_DIR)/md5.c \
    $(WOLFSSL_SRC_DIR)/cryptocb.c
WOLFSSL_EXAMPLE_OBJECTS = $(patsubst $(WOLFSSL_SRC_DIR)/%.c,$(BUILDDIR)/wolfssl_%.o,$(WOLFSSL_EXAMPLE_SRCS))

# to enable the legacy simple crypto example, set this to 1
CRYPTO_EXAMPLE = 0

OBJECTS = $(BUILDDIR)/HSM.so \
    $(BUILDDIR)/simple_uart.so \
    $(BUILDDIR)/ti_msp_dl_config.so \
    $(BUILDDIR)/startup_mspm0l222x_ticlang.so \
    $(BUILDDIR)/simple_flash.so \
    $(BUILDDIR)/host_messaging.so \
    $(BUILDDIR)/security.so \
    $(BUILDDIR)/filesystem.so \
    $(BUILDDIR)/commands.so \
    $(BUILDDIR)/secrets.so \
    $(BUILDDIR)/trng.so \
    $(BUILDDIR)/sha256_raw.so \
    $(BUILDDIR)/secure_crypto.so \
    $(BUILDDIR)/secure_design.so \
    $(BUILDDIR)/storage.so \
    $(BUILDDIR)/secure_blob_store.so \
    $(WOLFSSL_CORE_OBJECTS)

ifeq ($(CRYPTO_EXAMPLE), 1)
OBJECTS += $(BUILDDIR)/simple_crypto.so

# change C flags
CFLAGS += -DCRYPTO_EXAMPLE=1
# From https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#building-with-gcc-arm
CFLAGS += -DHAVE_PK_CALLBACKS
CFLAGS += -DWOLFSSL_USER_IO
CFLAGS += -DNO_WRITEV -DTIME_T_NOT_64BIT
CFLAGS += -DNO_FILESYSTEM
# tells wolfssl that we will handle RNG on the baremetal target
# user will need to implement the callbacks
CFLAGS += -DNO_DEV_RANDOM
CFLAGS += -DWC_NO_DEFAULT_DEVID
CFLAGS += -DWOLF_CRYPTO_CB

OBJECTS += $(WOLFSSL_EXAMPLE_OBJECTS)
endif

NAME = hsm

CFLAGS += -I.. \
    -I$(WOLFSSL_DIR) \
    -DWOLFSSL_USER_SETTINGS \
    -DNO_WOLFSSL_DIR \
    -D__MSPM0L2228__ \
    -O2 \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source/third_party/CMSIS/Core/Include" \
    "-I$(MSPM0_SDK_INSTALL_DIR)/source" \
	"-I./inc" \
    -gdwarf-3 \
    -mcpu=cortex-m0plus \
    -march=thumbv6m \
    -mfloat-abi=soft \
    -mthumb

LFLAGS += "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/drivers/lib/ticlang/m0p/drivers_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/kernel/nortos/lib/ticlang/m0p/nortos_mspm0l122x_l222x.a" \
    "-l$(MSPM0_SDK_INSTALL_DIR)/source/ti/driverlib/lib/ticlang/m0p/mspm0l122x_l222x/driverlib.a" \
    "-L$(MSPM0_SDK_INSTALL_DIR)/source" \
    -L.. \
    ./$(LINKERFILE) \
    "-Wl,-m,$(BUILDDIR)/$(NAME).map" \
    -Wl,--rom_model \
    -Wl,--warn_sections \
    "-L$(TICLANG_ARMCOMPILER)/lib" \
    -llibc.a

all: $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

$(BUILDDIR):
	@ mkdir -p $(BUILDDIR)

$(BUILDDIR)/%.so: ./src/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/wolfssl_%.o: $(WOLFSSL_SRC_DIR)/%.c | $(BUILDDIR)
	@ echo Building $@
	@ $(CC) $(CFLAGS) -c $< -o $@

$(BUILDDIR)/$(NAME).elf: $(OBJECTS)
	@ echo linking $@
	@ $(LNK) -Wl,-u,_c_int00 $(OBJECTS)  $(LFLAGS) -o $(BUILDDIR)/$(NAME).elf

$(BUILDDIR)/$(NAME).bin: $(BUILDDIR)/$(NAME).elf
	@ $(OBJCOPY) -O binary $(BUILDDIR)/$(NAME).elf $(BUILDDIR)/$(NAME).bin

clean:
	@ echo Cleaning...
	@ $(RM) $(OBJECTS) > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).elf > $(DEVNULL) 2>&1
	@ $(RM) $(NAME).map > $(DEVNULL) 2>&1
