SRC = payload.c
OBJ = $(SRC:.c=.o)
CFLAGS = --target=armv7-none-eabi -mcpu=cortex-a7 -mfloat-abi=soft -nostdlib -fPIC -nodefaultlibs
LDFLAGS = -Wl,-static -Wl,--gc-sections -Wl,-T,linker.ld

all: clean payload.elf payload.bin

payload.elf: $(OBJ)
	clang $(CFLAGS) $(LDFLAGS) $(OBJ) -o $@

payload.bin: payload.elf
	llvm-objcopy-18 -O binary $< $@

%.o: %.c
	clang $(CFLAGS) -c $< -o $@

clean:
	$(RM) -f payload.elf payload.bin *.o