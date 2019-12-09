#include "glyphs.h"
unsigned int const C_icon_default_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_default_bitmap[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0x7f,
  0xff, 0xff, 0xff, 0xff, 0x3f, 0x7e, 0xfc, 0xff, 0xff, 0xff, 0x3f, 0x30, 0xf0, 0xff, 0xff, 0xff,
  0x7f, 0x00, 0xe0, 0xff, 0xff, 0xff, 0xff, 0x03, 0xf0, 0xff, 0xff, 0xff, 0xff, 0x1f, 0xf8, 0xff,
  0xff, 0xff, 0xff, 0xef, 0xdc, 0xff, 0xff, 0xff, 0xff, 0x8f, 0x1f, 0xff, 0xff, 0xff, 0xff, 0x0f,
  0x0c, 0xfc, 0xff, 0xff, 0xff, 0x1f, 0x00, 0xf8, 0xff, 0xff, 0xff, 0xff, 0x00, 0xfc, 0xff, 0xff,
  0xff, 0xff, 0x07, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_default = { GLYPH_icon_default_WIDTH, GLYPH_icon_default_HEIGHT, 1, C_icon_default_colors, C_icon_default_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_down_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_down_bitmap[] = {
  0x41, 0x11, 0x05, 0x01,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_down = { GLYPH_icon_down_WIDTH, GLYPH_icon_down_HEIGHT, 1, C_icon_down_colors, C_icon_down_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_left_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_left_bitmap[] = {
  0x48, 0x12, 0x42, 0x08,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_left = { GLYPH_icon_left_WIDTH, GLYPH_icon_left_HEIGHT, 1, C_icon_left_colors, C_icon_left_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_right_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_right_bitmap[] = {
  0x21, 0x84, 0x24, 0x01,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_right = { GLYPH_icon_right_WIDTH, GLYPH_icon_right_HEIGHT, 1, C_icon_right_colors, C_icon_right_bitmap };
        #endif // OS_IO_SEPROXYHAL
#include "glyphs.h"
unsigned int const C_icon_up_colors[] = {
  0x00000000,
  0x00ffffff,
};

unsigned char const C_icon_up_bitmap[] = {
  0x08, 0x8a, 0x28, 0x08,
};
#ifdef OS_IO_SEPROXYHAL
        #include "os_io_seproxyhal.h"
        const bagl_icon_details_t C_icon_up = { GLYPH_icon_up_WIDTH, GLYPH_icon_up_HEIGHT, 1, C_icon_up_colors, C_icon_up_bitmap };
        #endif // OS_IO_SEPROXYHAL
