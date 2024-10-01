#include "rom.h"
#include "addresses.h"

unsigned char *bytes;
unsigned int mapper;

static long rom_size;

static char *carts[] = {
	[0x00] = "ROM ONLY",
	[0x01] = "MBC1",
	[0x02] = "MBC1+RAM",
	[0x03] = "MBC1+RAM+BATTERY",
	[0x05] = "MBC2",
	[0x06] = "MBC2+BATTERY",
	[0x08] = "ROM+RAM",
	[0x09] = "ROM+RAM+BATTERY",
	[0x0B] = "MMM01",
	[0x0C] = "MMM01+RAM",
	[0x0D] = "MMM01+RAM+BATTERY",
	[0x0F] = "MBC3+TIMER+BATTERY",
	[0x10] = "MBC3+TIMER+RAM+BATTERY",
	[0x11] = "MBC3",
	[0x12] = "MBC3+RAM",
	[0x13] = "MBC3+RAM+BATTERY",
	[0x15] = "MBC4",
	[0x16] = "MBC4+RAM",
	[0x17] = "MBC4+RAM+BATTERY",
	[0x19] = "MBC5",
	[0x1A] = "MBC5+RAM",
	[0x1B] = "MBC5+RAM+BATTERY",
	[0x1C] = "MBC5+RUMBLE",
	[0x1D] = "MBC5+RUMBLE+RAM",
	[0x1E] = "MBC5+RUMBLE+RAM+BATTERY",
	[0xFC] = "POCKET CAMERA",
	[0xFD] = "BANDAI TAMA5",
	[0xFE] = "HuC3",
	[0xFF] = "HuC1+RAM+BATTERY",
};

static char *banks[] = {
	" 32KiB",
	" 64KiB",
	"128KiB",
	"256KiB",
	"512KiB",
	"  1MiB",
	"  2MiB",
	"  4MiB",
	/* 0x52 */
	"1.1MiB",
	"1.2MiB",
	"1.5MiB",
	"Unknown"
};

static const int bank_sizes[] = {
	32*1024,
	64*1024,
	128*1024,
	256*1024,
	512*1024,
	1024*1024,
	2048*1024,
	4096*1024,
	1152*1024,
	1280*1024,
	1536*1024
};

static char *rams[] = {
	"None",
	"  2KiB",
	"  8KiB",
	" 32KiB",
	"Unknown"
};

static char *regions[] = {
	"Japan",
	"Non-Japan",
	"Unknown"
};

static unsigned char header[] = {
	0xCE, 0xED, 0x66, 0x66, 0xCC, 0x0D, 0x00, 0x0B,
	0x03, 0x73, 0x00, 0x83, 0x00, 0x0C, 0x00, 0x0D,
	0x00, 0x08, 0x11, 0x1F, 0x88, 0x89, 0x00, 0x0E,
	0xDC, 0xCC, 0x6E, 0xE6, 0xDD, 0xDD, 0xD9, 0x99,
	0xBB, 0xBB, 0x67, 0x63, 0x6E, 0x0E, 0xEC, 0xCC,
	0xDD, 0xDC, 0x99, 0x9F, 0xBB, 0xB9, 0x33, 0x3E
};

static int rom_init(unsigned char *rombytes, int32_t filesize)
{
	kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;
	memcpy_t memcpy = (memcpy_t) MEMCPY_ADDRESS;
	memcmp_t memcmp = (memcmp_t) MEMCMP_ADDRESS;

	char buf[17];
	int type, bank_index, ram, region, version, i, pass;
	unsigned char checksum = 0;

	if(memcmp(&rombytes[0x104], header, sizeof(header)) != 0)
		return 0;

	memcpy(buf, &rombytes[0x134], 16);
	buf[16] = '\0';
	kprintf("Rom title: %s\n", buf);

	type = rombytes[0x147];

	kprintf("Cartridge type: %s (%02X)\n", carts[type], type);

	bank_index = rombytes[0x148];
	/* Adjust for the gap in the bank indicies */
	if(bank_index >= 0x52 && bank_index <= 0x54)
		bank_index -= 74;
	else if(bank_index > 7)
		bank_index = 11;

	if(bank_index >= 10)
	{
		kprintf("Illegal ROM size in header\n");
		return 0;
	}

	kprintf("Rom size: %s\n", banks[bank_index]);

	rom_size = bank_sizes[bank_index];

	if(rom_size < filesize)
	{
		kprintf("File not big enough for ROM size.\n");
		return 0;
	}

	ram = rombytes[0x149];
	if(ram > 3)
		ram = 4;

	kprintf("RAM size: %s\n", rams[ram]);

	region = rombytes[0x14A];
	if(region > 2)
		region = 2;
	kprintf("Region: %s\n", regions[region]);

	version = rombytes[0x14C];
	kprintf("Version: %02X\n", version);

	for(i = 0x134; i <= 0x14C; i++)
		checksum = checksum - rombytes[i] - 1;

	pass = rombytes[0x14D] == checksum;

	kprintf("Checksum: %s (%02X)\n", pass ? "OK" : "FAIL", checksum);
	if(!pass)
		return 0;

	bytes = rombytes;

	switch(type)
	{
		case 0x00:
		case 0x08:
		case 0x09:
			mapper = NROM;
		break;
		case 0x01:
		case 0x02:
		case 0x03:
			mapper = MBC1;
		break;
		case 0x05:
		case 0x06:
			mapper = MBC2;
		break;
		case 0x0B:
		case 0x0C:
			mapper = MMM01;
		break;
		case 0x0F:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
			mapper = MBC3;
		break;
		case 0x15:
		case 0x16:
		case 0x17:
			mapper = MBC4;
		break;
		case 0x19:
		case 0x1A:
		case 0x1B:
		case 0x1C:
		case 0x1D:
		case 0x1E:
			mapper = MBC5;
		break;
	}

	return 1;
}

unsigned int rom_get_mapper(void)
{
	return mapper;
}

long getFileLength(int32_t *file) {
	fseek_t fseek = (fseek_t)FSEEK_ADDRESS;
	ftell_t ftell = (ftell_t)FTELL_ADDRESS;
	fclose_t fclose = (fclose_t)FCLOSE_ADDRESS;
	kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;

    // Seek to the end of the file
    if (fseek(file, 0, 2) != 0) {
        kprintf("Error seeking to end of file");
        fclose(file);
        return -1;
    }

    // Get the current position (length of the file)
    long length = ftell(file);
    if (length == -1) {
        kprintf("Error getting the file length");
        fclose(file);
        return -1;
    }

	kprintf("File length: %d\n", length);

    return length; // Return the length of the file
}

int rom_load(const char *filename) {
	// Function pointer variables for the specific addresses
	fseek_t fseek = (fseek_t)FSEEK_ADDRESS;
	fopen_t fopen = (fopen_t)FOPEN_ADDRESS;
	malloc_t malloc = (malloc_t)MALLOC_ADDRESS;
	fclose_t fclose = (fclose_t)FCLOSE_ADDRESS;
	fread_t fread = (fread_t)FREAD_ADDRESS;
	free_t free = (free_t)FREE_ADDRESS;

	kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;

	kprintf("Reading ROM from %s\n", filename);

    int32_t *file;
    unsigned char *bytes;
    uint32_t rom_size;

    // Open the file
    file = fopen(filename, "rb");
    if (file == NULL){
        return 0;
	}

	rom_size = getFileLength(file); // closes the file

    // Allocate memory to hold the ROM data
    bytes = malloc(rom_size);
    if (bytes == NULL) {
		kprintf("Failed to allocate rom_size buffer\n");
        fclose(file);
        return 0;
    }

	if (fseek(file, 0, 0) != 0) {
        kprintf("Error seeking to start of file");
        fclose(file);
        return 1;
    }

    // Read the file contents into memory
    uint32_t bytes_read = fread(bytes, 1, rom_size, file);
    if (bytes_read != rom_size) {
		kprintf("bytes_read(%d) != rom_size(%d) error\n", bytes_read, rom_size);
        free(bytes);
        fclose(file);
        return 0;
    }

    // Close the file
    fclose(file);

    // Initialize the ROM
    return rom_init(bytes, rom_size);
}

unsigned char *rom_getbytes(void)
{
	return bytes;
}

int rom_bank_valid(int bank)
{
	if(bank * 0x4000 > rom_size)
		return 0;
	return 1;
}
