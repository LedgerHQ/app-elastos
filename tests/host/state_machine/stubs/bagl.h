/* Harness stub: bagl.h. bagl_element_t matches ui.c's positional initializers. */
#ifndef SM_BAGL_H
#define SM_BAGL_H

typedef struct {
    long comp[13];
    const void* text;
    long touch_area_brim;
    long overfgcolor;
    long overbgcolor;
    const void* tap;
    const void* out;
    const void* over;
} bagl_element_t;

#define BAGL_RECTANGLE 0
#define BAGL_LABELINE  1
#define BAGL_ICON      2
#define BAGL_FILL      0
/* distinct values, so the driver can tell a bold heading from a regular line */
#define BAGL_FONT_OPEN_SANS_EXTRABOLD_11px 1
#define BAGL_FONT_OPEN_SANS_LIGHT_14px     2
#define BAGL_FONT_OPEN_SANS_REGULAR_11px   3
#define BAGL_FONT_ID_MASK                  0x0FFF
#define BAGL_FONT_ALIGNMENT_CENTER         0x8000
#define BAGL_FONT_ALIGNMENT_MIDDLE         0x4000
#define BAGL_GLYPH_ICON_CROSS              0
#define BAGL_GLYPH_ICON_EYE_BADGE          0
#define BAGL_GLYPH_ICON_DOWN               0
#define BAGL_GLYPH_ICON_UP                 0
#define BAGL_GLYPH_ICON_LEFT               0
#define BAGL_GLYPH_ICON_RIGHT              0
#define BAGL_GLYPH_ICON_CHECK              0
#define BAGL_GLYPH_ICON_DASHBOARD          0

#endif
