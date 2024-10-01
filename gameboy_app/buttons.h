#ifndef BUTTON_H
#define BUTTON_H

enum Button {
    MIDDLE_BUTTON = 0x1c,
    RECORD_BUTTON = 0x66,
    UP_BUTTON = 0x67,
    LEFT_BUTTON = 0x69,
    RIGHT_BUTTON = 0x6a,
    DOWN_BUTTON = 0x6c,
    SNAPSHOT_BUTTON = 0x71,
    POWER_BUTTON = 0x74,
    CAMERA_FLIP_BUTTON = 0x8b,
}; 

enum ButtonBits {
    SELECT_BIT  = 0,
    START_BIT   = 1,
    B_BIT       = 2,
    A_BIT       = 3,
    RIGHT_BIT   = 4,
    DOWN_BIT    = 5,
    LEFT_BIT    = 6,
    UP_BIT      = 7
};

void button_press_handle(int idk, int* data_stuff);

// Function to get the state of the action buttons (A, B, Start, Select)
unsigned int get_action_buttons(void);

// Function to get the state of the direction buttons (Up, Down, Left, Right)
unsigned int get_direction_buttons(void);

#endif