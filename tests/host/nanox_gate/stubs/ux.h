/* Stand-in for the SDK's flow engine, enough to build the Nano X and Nano S Plus flows. As in the
 * SDK, a step keeps its init (which draws its layout), its validate (both buttons) and, with an
 * init, its layout parameters as <step>_val. The driver walks the flow, so it can fault it. */
#ifndef GATE_UX_H
#define GATE_UX_H

typedef struct ux_flow_step_s {
    void (*init)(unsigned int stack_slot);
    void (*validate)(void);
    const char *name;
} ux_flow_step_t;

/* The fields of the SDK's display stack slot that the app reads. */
typedef struct {
    unsigned short element_index;
    struct {
        unsigned char element_array_count;
    } element_arrays[1];
} gate_ux_stack_slot_t;
typedef struct {
    unsigned int stack_count;
    gate_ux_stack_slot_t stack[1];
} ux_state_t;
/* Parameters of the SDK layouts the flows use. */
typedef struct {
    const char *lines[4];
} ux_layout_bnnn_params_t;
typedef struct {
    const void *icon;
    const char *line;
} ux_layout_pb_params_t;
typedef struct {
    const void *icon;
    const char *line1;
    const char *line2;
} ux_layout_pnn_params_t;

/* Elements per layout, as in the SDK: a review step is a bnnn, Accept a pb. */
#define GATE_BNNN_ELEMENTS 7
#define GATE_PB_ELEMENTS   5
#define GATE_PNN_ELEMENTS  6

/* implemented by the driver, which can fault the drawing */
void gate_draw_layout(unsigned int stack_slot, unsigned int count);
static inline void ux_layout_bnnn_init(unsigned int stack_slot) { gate_draw_layout(stack_slot, GATE_BNNN_ELEMENTS); }
static inline void ux_layout_pb_init(unsigned int stack_slot) { gate_draw_layout(stack_slot, GATE_PB_ELEMENTS); }
static inline void ux_layout_pnn_init(unsigned int stack_slot) { gate_draw_layout(stack_slot, GATE_PNN_ELEMENTS); }
typedef struct {
    int dummy;
} bolos_ux_params_t;

#define FLOW_END_STEP ((const ux_flow_step_t *) 0xFFFFFFFFUL)

#define UX_STEP_NOCB(name, layout, ...) const ux_flow_step_t name = {0, 0, #name}
#define UX_STEP_NOCB_INIT(name, layout, preinit, ...)      \
    static void name##_init(unsigned int s) {                \
        preinit;                                             \
        ux_layout_##layout##_init(s);                        \
    }                                                        \
    const ux_layout_##layout##_params_t name##_val = __VA_ARGS__; \
    const ux_flow_step_t name = {name##_init, 0, #name}
#define UX_STEP_CB(name, layout, cb, ...) \
    static void name##_validate(void) {   \
        cb;                               \
    }                                     \
    const ux_flow_step_t name = {0, name##_validate, #name}
#define UX_STEP_VALID UX_STEP_CB
#define UX_STEP_CB_INIT(name, layout, preinit, cb, ...)      \
    static void name##_init(unsigned int s) {                 \
        preinit;                                              \
        ux_layout_##layout##_init(s);                         \
    }                                                         \
    static void name##_validate(void) {                       \
        cb;                                                   \
    }                                                         \
    const ux_layout_##layout##_params_t name##_val = __VA_ARGS__; \
    const ux_flow_step_t name = {name##_init, name##_validate, #name}
#define UX_FLOW(name, ...) const ux_flow_step_t *const name[] = {__VA_ARGS__, FLOW_END_STEP}

/* implemented by the driver */
void ux_flow_init(unsigned int stack_slot, const ux_flow_step_t *const *steps, const ux_flow_step_t *start);
void ux_stack_push(void);

#define UX_INIT() do { } while (0)
#define UX_REDISPLAY() do { } while (0)
#define UX_DISPLAYED() 1
#define UX_DISPLAYED_EVENT() do { } while (0)
#define UX_TICKER_EVENT(buf, block) do { } while (0)
#define UX_FINGER_EVENT(buf) do { (void) (buf); } while (0)
#define UX_BUTTON_PUSH_EVENT(buf) do { (void) (buf); } while (0)
#define UX_DEFAULT_EVENT() do { } while (0)
#define UX_ALLOWED 1
#endif
