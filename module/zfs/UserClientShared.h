//
//  UserClientShared.h
//  UserSpaceClient
//

#include <stdint.h>

typedef struct TimerValue
{
	uint64_t	time;
	uint64_t	timebase;
} TimerValue;

// User client method dispatch selectors.
enum TimerRequestCode {
	kTestUserClientStartTimer,
	kTestUserClientStopTimer,
	kTestUserClientGetElapsedTimerTime,
	kTestUserClientGetElapsedTimerValue,
	kTestUserClientDelayForMs,
	kTestUserClientDelayForTime,
	kTestUserClientInstallTimer,
	
	kTestUserClientMethodCount
};
