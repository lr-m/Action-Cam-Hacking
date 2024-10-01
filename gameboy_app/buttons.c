#include "buttons.h"
#include "addresses.h"

#define BUTTON_TIMEOUT 250  // Configurable timeout value
#define NUM_BUTTONS 8       // Total number of buttons we're tracking

static uint32_t button_state;
static uint16_t button_timers[NUM_BUTTONS];  // Array to track button press durations

// Helper function to update button timers
void update_button_timers(void) {
    for (int i = 0; i < NUM_BUTTONS; i++) {
        if (button_timers[i] > 0) {
            button_timers[i]--;
        }
    }
}

void button_press_handle(int idk, int* data_stuff) {
    int button_press_ID = *data_stuff;
    kprintf_t kprintf = (kprintf_t) KPRINTF_ADDRESS;
    kprintf("Button pressed: %d\n", idk);

    // if display is off turn it on
    char * display_on_ptr = (char*) 0xc09d7bb0;
    char display_on = *display_on_ptr;
    kprintf("[*] Display on status: %d\n", display_on);
    if (!display_on){
        lb_eui_screen_standby_switch_t lb_eui_screen_standby_switch = (lb_eui_screen_standby_switch_t) 0xc00839f4;
        lb_eui_screen_standby_switch();
    }

    // 8----7------6------5-------4---3---2-------1--------0
    // | UP | LEFT | DOWN | RIGHT | A | B | START | SELECT |
    int bit_to_set = -1;
    switch (button_press_ID) {
        case MIDDLE_BUTTON: // START
            kprintf("Button pressed: MIDDLE_BUTTON\n");
            bit_to_set = START_BIT;
            break;
        case RECORD_BUTTON: // A
            kprintf("Button pressed: RECORD_BUTTON\n");
            bit_to_set = A_BIT;
            break;
        case UP_BUTTON: // UP
            kprintf("Button pressed: UP_BUTTON\n");
            bit_to_set = UP_BIT;
            break;
        case LEFT_BUTTON: // LEFT
            kprintf("Button pressed: LEFT_BUTTON\n");
            bit_to_set = LEFT_BIT;
            break;
        case RIGHT_BUTTON: // RIGHT
            kprintf("Button pressed: RIGHT_BUTTON\n");
            bit_to_set = RIGHT_BIT;
            break;
        case DOWN_BUTTON: // DOWN
            kprintf("Button pressed: DOWN_BUTTON\n");
            bit_to_set = DOWN_BIT;
            break;
        case SNAPSHOT_BUTTON: // B
            kprintf("Button pressed: SNAPSHOT_BUTTON\n");
            bit_to_set = B_BIT;
            break;
        case CAMERA_FLIP_BUTTON: // SELECT
            kprintf("Button pressed: CAMERA_FLIP_BUTTON\n");
            bit_to_set = SELECT_BIT;
            break;
        case POWER_BUTTON:
            kprintf("Button pressed: POWER_BUTTON\n");
            // Power button doesn't correspond to a bit in our button_state
            break;
        default:
            kprintf("Button pressed: UNKNOWN (ID: 0x%x)\n", button_press_ID);
            break;
    }

    if (bit_to_set != -1) {
        button_state |= (1U << bit_to_set);
        button_timers[bit_to_set] = BUTTON_TIMEOUT;  // Set the timer for this button
    }
}

// Function to get the state of the action buttons (A, B, Start, Select)
unsigned int get_action_buttons(void)
{
    update_button_timers();  // Update all button timers

    unsigned int action_buttons = ((button_state >> START_BIT) & 1) << 3 |
                                  ((button_state >> SELECT_BIT) & 1) << 2 |
                                  ((button_state >> B_BIT) & 1) << 1 |
                                  ((button_state >> A_BIT) & 1);

    // Clear action button bits if their timers have expired
    for (int i = 0; i <= 3; i++) {
        if (button_timers[i] == 0) {
            button_state &= ~(1 << i);
        }
    }

    return action_buttons;
}

// Function to get the state of the direction buttons (Up, Down, Left, Right)
unsigned int get_direction_buttons(void)
{
    update_button_timers();  // Update all button timers

    unsigned int direction_buttons = ((button_state >> DOWN_BIT) & 1) << 3 |
                                     ((button_state >> UP_BIT) & 1) << 2 |
                                     ((button_state >> LEFT_BIT) & 1) << 1 |
                                     ((button_state >> RIGHT_BIT) & 1);

    // Clear direction button bits if their timers have expired
    for (int i = 4; i <= 7; i++) {
        if (button_timers[i] == 0) {
            button_state &= ~(1 << i);
        }
    }

    return direction_buttons;
}