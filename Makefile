# This file is a helper script to make repetitive build actions easier
# Invoking `make docker` will build the docker image.
# `make docker-nc` will build the docker image without using the Docker cache.
# `make secrets` will generate secrets for group 1234.
# `make firmware` will make the firmware image.
# `make clean` will remove build artifacts, both in the firmware
# directory and the final output directory.

BUILDDIR ?= /tmp/build
NAME = hsm
OUTDIR ?=  build
OPENOCD ?= openocd
OPENOCD_PREFIX ?= $(shell brew --prefix open-ocd 2>/dev/null)
OPENOCD_SCRIPTS ?= $(OPENOCD_PREFIX)/share/openocd/scripts
# Clear the mutable HSM state pages so local reflashes do not inherit stale
# filesystem, PIN, or provisioning state from older images.
FLASH_STATE_BASE ?= 0x00027000
FLASH_STATE_LEN ?= 0x00012800


docker:
	docker build -t build-hsm ./firmware/

docker-nc:
	docker build --no-cache -t build-hsm ./firmware/

global.secrets:
	@if [ -z "${GROUPS}" ]; then echo 'Must pass valid groups like:\r\n\tmake global.secrets GROUPS=1234\r\nor, if multiple groups defined:\r\n\tmake global.secrets GROUPS="1234 5678"' && false; fi
	uvx --with-editable ./ectf26_design --from ectf26_design secrets global.secrets $(GROUPS)

%.hsm:
	@mkdir -p $@
	@if [ ! -f global.secrets ]; then echo 'Must generate global secrets first with\r\n\tmake global.secrets' && false; fi
	@if [ -z "${PIN}" ] || [ -z "${PERMS}" ]; then echo "Must provide PIN and permissions for HSM. For example:\r\n\tmake $@ PIN=123456 PERMS='1234=RWC'" && false; fi
	docker run --rm \
	  -v ./firmware:/hsm \
	  -v ./global.secrets:/secrets/global.secrets:ro \
	  -v ./$@:/out \
	  -e HSM_PIN=${PIN} \
	  -e PERMISSIONS='${PERMS}' \
	  build-hsm $(BUILDDIR)

flash: $(OUTDIR)
	@if [ -z "$(OPENOCD_SCRIPTS)" ] || [ ! -d "$(OPENOCD_SCRIPTS)" ]; then echo 'OpenOCD scripts not found. Set OPENOCD_SCRIPTS=/path/to/openocd/scripts' && false; fi
	$(OPENOCD) \
	  -s "$(OPENOCD_SCRIPTS)" \
	  -f interface/xds110.cfg \
	  -f target/ti/mspm0.cfg \
	  -c "init; reset halt; flash erase_address $(FLASH_STATE_BASE) $(FLASH_STATE_LEN); program ./$(OUTDIR)/$(NAME).elf verify reset exit"

clean:
	rm -rfI *.hsm/ global.secrets
