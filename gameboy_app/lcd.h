#ifndef LCD_H
#define LCD_H

#include <stdint.h>

int lcd_init(uint32_t* fb1, uint32_t* fb2);
int lcd_cycle(void);
int lcd_get_line(void);
unsigned char lcd_get_stat();
void lcd_write_control(unsigned char);
void lcd_write_stat(unsigned char);
void lcd_write_scroll_x(unsigned char);
void lcd_write_scroll_y(unsigned char);
void lcd_write_bg_palette(unsigned char);
void lcd_write_spr_palette1(unsigned char);
void lcd_write_spr_palette2(unsigned char);
void lcd_set_window_y(unsigned char);
void lcd_set_window_x(unsigned char);
void lcd_set_ly_compare(unsigned char);
unsigned char lcd_get_ly_compare(void);
#endif
