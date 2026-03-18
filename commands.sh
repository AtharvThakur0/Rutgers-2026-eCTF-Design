
docker build -t build-hsm ./firmware &&
docker run --rm -v ./firmware:/hsm -v ./global.secrets:/secrets/global.secrets:ro -v ./build:/out -e HSM_PIN='123abc' -e PERMISSIONS='1234=R--:4321=RWC' build-hsm  &&
make flash PIN=123abc PERMS='1234=RWC' &&
uvx ectf tools  /dev/cu.usbmodemML2200011 list 123abc &&
uvx ectf tools /dev/cu.usbmodemML2200011 write 123abc 0 0x4321 ./somefile.txt  &&
rm -rf ./readback && mkdir -p ./readback &&
uvx ectf tools /dev/cu.usbmodemML2200011 read --force 123abc 0 ./readback
