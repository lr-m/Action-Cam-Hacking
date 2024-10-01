# Compiler and Linker
CC = clang
LD = ld.lld

# Source files
SRCS = gameboy_app.c buttons.c rom.c lcd.c cpu.c interrupt.c mbc.c mem.c timer.c 
OBJS = $(SRCS:.c=.o)

# Output files
OUTPUT = gameboy.app

# Compiler flags
CFLAGS = --target=armv7-none-eabi \
         -mcpu=cortex-a7 \
         -mfloat-abi=soft \
         -nostdlib \
         -fPIC \
         -nodefaultlibs \
         -O3 \
         -flto \
         -ffunction-sections \
         -fdata-sections \
         -fno-exceptions \
         -fno-rtti \
         -ffast-math \
         -march=armv7-a \
         -mtune=cortex-a7 \
         -Wall \
         -Wextra \
         -Werror

# Linker flags
LDFLAGS = -shared \
          --no-undefined \
          --entry=gameboy_main \
          -T Linker.ld \
          -O3 \
          --gc-sections \
          --icf=all

# Default rule
all: $(OUTPUT)

# Compile source files to object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Link object files into a shared object
$(OUTPUT): $(OBJS) Linker.ld
	$(LD) $(LDFLAGS) $(OBJS) -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(OUTPUT)

.PHONY: all clean