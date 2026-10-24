#ifndef MATTER_LAB_RGB_LED_H
#define MATTER_LAB_RGB_LED_H 1
#include "rgb_light.h"
typedef struct Matter_Lab_Led* Matter_Lab_Led_T;
Matter_Lab_Led_T matter_lab_led_new(void);
bool matter_lab_led_process(Matter_Lab_Led_T,Matter_Lab_Rgb_T,bool* changed);
bool matter_lab_led_delete(Matter_Lab_Led_T);
#endif
