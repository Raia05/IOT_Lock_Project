/*
 * lock.h
 *
 *  Created on: Apr 25, 2026
 *      Author: mltnr
 */

#ifndef LOCK_H_
#define LOCK_H_

#include <stdint.h>
#include <stdbool.h>

typedef enum
{
    STATE_LOCKED   = 0,
    STATE_UNLOCKED = 1,
    STATE_JARRED   = 2
} LockState;

void initLock(void);
void serviceLockButton(void);

void goToLocked(void);
void goToUnlocked(void);

void lockSetState(char desiredState[]);
void publishLockState(void);

LockState getLockState(void);
const char* getLockStateString(void);



#endif /* LOCK_H_ */
