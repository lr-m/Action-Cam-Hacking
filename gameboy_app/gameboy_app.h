#include <stdint.h>
#include "buttons.h"
#include "addresses.h"
#include "rom.h"
#include "lcd.h"

// #define ENABLE_SOUND 0

// struct priv_t
// {
// 	/* Pointer to allocated memory holding GB file. */
// 	uint8_t *rom;
// 	/* Pointer to allocated memory holding save file. */
// 	uint8_t *cart_ram;

// 	/* Frame buffer */
// 	uint32_t fb[LCD_HEIGHT][LCD_WIDTH];
// };

// uint8_t gb_rom_read(struct gb_s *gb, const uint_fast32_t addr);

// uint8_t gb_cart_ram_read(struct gb_s *gb, const uint_fast32_t addr);

// void gb_cart_ram_write(struct gb_s *gb, const uint_fast32_t addr, const uint8_t val);

// uint8_t *read_rom_to_ram(const char *file_name);

// void gb_error(struct gb_s *gb, const enum gb_error_e gb_err, const uint16_t val);

// void lcd_draw_line(struct gb_s *gb, const uint8_t pixels[160], const uint_fast8_t line);