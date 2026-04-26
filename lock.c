#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "tm4c123gh6pm.h"
#include "lock.h"
#include "mqtt.h"
#include "uart0.h"

// -----------------------------------------------------------------------------
// Globals
// -----------------------------------------------------------------------------

static volatile LockState currentState = STATE_LOCKED;
static volatile uint8_t changeRequested = 0;

static volatile bool motorMoving = false;
static volatile LockState targetState = STATE_JARRED;
static volatile uint32_t motorTimeout = 0;

// -----------------------------------------------------------------------------
// Masked GPIO addresses
// -----------------------------------------------------------------------------

#define GPIOB_PIN0  (*((volatile uint32_t *)(0x40005000 + (0x01 << 2))))
#define GPIOB_PIN1  (*((volatile uint32_t *)(0x40005000 + (0x02 << 2))))

// -----------------------------------------------------------------------------
// Motor control
// -----------------------------------------------------------------------------

#define MOTOR_LEFT()   do { GPIOB_PIN0 = 0xFF; GPIOB_PIN1 = 0x00; } while(0)
#define MOTOR_RIGHT()  do { GPIOB_PIN0 = 0x00; GPIOB_PIN1 = 0xFF; } while(0)
#define MOTOR_STOP()   do { GPIOB_PIN0 = 0x00; GPIOB_PIN1 = 0x00; } while(0)

// -----------------------------------------------------------------------------
// Sensor helpers
// PF4 = locked sensor
// PF0 = unlocked sensor
// Both are active-low
// -----------------------------------------------------------------------------

#define LOCKED_SENSOR_ACTIVE()    ((GPIO_PORTF_DATA_R & 0x10) == 0)
#define UNLOCKED_SENSOR_ACTIVE()  ((GPIO_PORTF_DATA_R & 0x01) == 0)

// -----------------------------------------------------------------------------
// Local delay
// -----------------------------------------------------------------------------

static void delayMs(uint32_t ms)
{
    uint32_t i;

    for (i = 0; i < ms * 3180; i++)
    {
    }
}

// -----------------------------------------------------------------------------
// Hardware init
// -----------------------------------------------------------------------------

static void initMotorPortB(void)
{
    SYSCTL_RCGCGPIO_R |= 0x02;
    while ((SYSCTL_PRGPIO_R & 0x02) == 0)
    {
    }

    GPIO_PORTB_LOCK_R  = 0x4C4F434B;
    GPIO_PORTB_CR_R   |= 0x03;
    GPIO_PORTB_AMSEL_R &= ~0x03;
    GPIO_PORTB_PCTL_R  &= ~0x000000FF;
    GPIO_PORTB_AFSEL_R &= ~0x03;
    GPIO_PORTB_DR8R_R  |= 0x03;
    GPIO_PORTB_DIR_R   |= 0x03;
    GPIO_PORTB_DEN_R   |= 0x03;

    MOTOR_STOP();
}

static void initSensorPortF(void)
{
    SYSCTL_RCGCGPIO_R |= 0x20;
    while ((SYSCTL_PRGPIO_R & 0x20) == 0)
    {
    }

    GPIO_PORTF_LOCK_R  = 0x4C4F434B;
    GPIO_PORTF_CR_R   |= 0x1F;

    GPIO_PORTF_AMSEL_R &= ~0x1F;
    GPIO_PORTF_PCTL_R  &= ~0x000FFFFF;
    GPIO_PORTF_AFSEL_R &= ~0x1F;

    // PF4 and PF0 are inputs.
    // PF1, PF2, PF3 are LEDs.
    GPIO_PORTF_DIR_R = (GPIO_PORTF_DIR_R & ~0x1F) | 0x0E;

    GPIO_PORTF_DEN_R |= 0x1F;
    GPIO_PORTF_PUR_R |= 0x11;

    GPIO_PORTF_IS_R  &= ~0x11;
    GPIO_PORTF_IBE_R &= ~0x11;
    GPIO_PORTF_IEV_R &= ~0x11;
    GPIO_PORTF_ICR_R |= 0x11;
    GPIO_PORTF_IM_R  |= 0x11;

    NVIC_PRI7_R = (NVIC_PRI7_R & 0xFF00FFFF) | 0x00400000;
    NVIC_EN0_R |= (1 << 30);

    GPIO_PORTF_DATA_R &= ~0x0E;
}

static void updateLed(LockState state)
{
    GPIO_PORTF_DATA_R &= ~0x0E;

    if (state == STATE_LOCKED)
        GPIO_PORTF_DATA_R |= 0x02;      // Red PF1
    else if (state == STATE_UNLOCKED)
        GPIO_PORTF_DATA_R |= 0x08;      // Green PF3
    else
        GPIO_PORTF_DATA_R |= 0x04;      // Blue PF2
}

// -----------------------------------------------------------------------------
// Public lock functions
// -----------------------------------------------------------------------------

void initLock(void)
{
    initMotorPortB();
    initSensorPortF();

    if (LOCKED_SENSOR_ACTIVE())
        currentState = STATE_LOCKED;
    else if (UNLOCKED_SENSOR_ACTIVE())
        currentState = STATE_UNLOCKED;
    else
        currentState = STATE_JARRED;

    updateLed(currentState);
    MOTOR_STOP();
}

LockState getLockState(void)
{
    return currentState;
}

const char* getLockStateString(void)
{
    if (currentState == STATE_LOCKED)
        return "locked";

    if (currentState == STATE_UNLOCKED)
        return "unlocked";

    return "jarred";
}

void publishLockState(void)
{
    publishMqtt("lock_state", (char*)getLockStateString());
}

void goToUnlocked(void)
{
    if (currentState == STATE_UNLOCKED)
    {
        putsUart0("Already unlocked\r\n");
        return;
    }

    currentState = STATE_JARRED;
    targetState = STATE_UNLOCKED;
    motorMoving = true;
    motorTimeout = 0;

    updateLed(STATE_JARRED);
    MOTOR_RIGHT();

    putsUart0("Motor unlocking...\r\n");

    while (motorMoving)
    {
        motorTimeout++;

        if (motorTimeout > 3000000)
        {
            MOTOR_STOP();
            motorMoving = false;
            currentState = STATE_UNLOCKED;
            updateLed(STATE_UNLOCKED);
            putsUart0("Unlock timeout\r\n");
            return;
        }
    }

    publishLockState();
}

void goToLocked(void)
{
    if (currentState == STATE_LOCKED)
    {
        putsUart0("Already locked\r\n");
        return;
    }

    currentState = STATE_JARRED;
    targetState = STATE_LOCKED;
    motorMoving = true;
    motorTimeout = 0;

    updateLed(STATE_JARRED);
    MOTOR_LEFT();

    putsUart0("Motor locking...\r\n");

    while (motorMoving)
    {
        motorTimeout++;

        if (motorTimeout > 3000000)
        {
            MOTOR_STOP();
            motorMoving = false;
            currentState = STATE_LOCKED;
            updateLed(STATE_LOCKED);
            putsUart0("Lock timeout\r\n");
            return;
        }
    }

    publishLockState();
}

void lockSetState(char desiredState[])
{
    if (strcmp(desiredState, "lock") == 0 ||
        strcmp(desiredState, "locked") == 0 ||
        strcmp(desiredState, "close") == 0)
    {
        if (currentState != STATE_LOCKED)
        {
            putsUart0("Lock command received\r\n");
            goToLocked();
        }
        else
        {
            putsUart0("Already locked\r\n");
        }

        publishLockState();
    }
    else if (strcmp(desiredState, "unlock") == 0 ||
             strcmp(desiredState, "unlocked") == 0 ||
             strcmp(desiredState, "open") == 0)
    {
        if (currentState != STATE_UNLOCKED)
        {
            putsUart0("Unlock command received\r\n");
            goToUnlocked();
        }
        else
        {
            putsUart0("Already unlocked\r\n");
        }

        publishLockState();
    }
    else
    {
        putsUart0("Invalid lock_set_state command\r\n");
    }
}

void serviceLockButton(void)
{
    if (changeRequested)
    {
        changeRequested = 0;

        if (currentState == STATE_LOCKED)
            goToUnlocked();
        else
            goToLocked();

        publishLockState();
    }
}

// -----------------------------------------------------------------------------
// Interrupt handler for PF4 and PF0 sensors
// -----------------------------------------------------------------------------

void GPIOF_Handler(void)
{
    // PF4 = locked sensor
    if (GPIO_PORTF_RIS_R & 0x10)
    {
        GPIO_PORTF_ICR_R |= 0x10;
        delayMs(20);

        if (LOCKED_SENSOR_ACTIVE())
        {
            currentState = STATE_LOCKED;
            updateLed(STATE_LOCKED);

            if (motorMoving && targetState == STATE_LOCKED)
            {
                MOTOR_STOP();
                motorMoving = false;
                targetState = STATE_JARRED;
                putsUart0("Locked sensor hit\r\n");
            }
        }
    }

    // PF0 = unlocked sensor
    if (GPIO_PORTF_RIS_R & 0x01)
    {
        GPIO_PORTF_ICR_R |= 0x01;
        delayMs(20);

        if (UNLOCKED_SENSOR_ACTIVE())
        {
            currentState = STATE_UNLOCKED;
            updateLed(STATE_UNLOCKED);

            if (motorMoving && targetState == STATE_UNLOCKED)
            {
                MOTOR_STOP();
                motorMoving = false;
                targetState = STATE_JARRED;
                putsUart0("Unlocked sensor hit\r\n");
            }
        }
    }
}
