# rwcompression
GCC .data/.bss runtime loader and post-build data compressor

- This tool provides the ability to compress/load rw image with gcc binaries, just like what commercial toolchain did (`Keil MDK`, `IAR EWARM`, etc)
- Loader: `startup_load.c`, The only thing need to do is: 
  1. add `startup_load.c` to project
  2. call `_mainCRTStartup` before `main`
- Post-build: `process.py` 
  - Everything should be done automatically, even without changing a single line in your link script

---

call `process.py` with a given elf file will generate a patched file `patched.elf`

```
python3 process.py firmware.elf
```

you can use `objcopy` to generate executable binary from `patched.elf` directly

```
objcopy -O binary -S patched.elf patched.bin
```

`patched.elf` also can be load & programmed by debuggers automatically
