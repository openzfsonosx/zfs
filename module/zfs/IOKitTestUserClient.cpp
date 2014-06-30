//
//  IOKitTestUserClient.cpp
//  IOKitTest
//

#include <IOKit/IOLib.h>
#include "IOKitTestUserClient.h"

// Define the superclass
#define super IOUserClient

OSDefineMetaClassAndStructors(com_osxkernel_driver_IOKitTestUserClient, IOUserClient)


bool	com_osxkernel_driver_IOKitTestUserClient::initWithTask (task_t owningTask, void* securityToken, UInt32 type, OSDictionary* properties)
{
	if (!owningTask)
        return false;

	if (! super::initWithTask(owningTask, securityToken , type, properties))
		return false;

	printf("**initWithTask\n");

	m_task = owningTask;

	IOReturn ret = clientHasPrivilege(securityToken, kIOClientPrivilegeAdministrator);
	if ( ret == kIOReturnSuccess )
	{
		// m_taskIsAdmin = true;
	}

    return true;
}

//#include <sys/zvolIO.h>
#include <ZFSProxyMediaScheme.h>


bool	com_osxkernel_driver_IOKitTestUserClient::start (IOService* provider)
{
	if (! super::start(provider))
		return false;

	printf("**start\n");

	//m_driver = OSDynamicCast(com_osxkernel_driver_IOKitTest, provider);
	m_driver = OSDynamicCast(ZFSProxyMediaScheme, provider);
	if (!m_driver)
		return false;

	return true;
}

void	com_osxkernel_driver_IOKitTestUserClient::stop (IOService* provider)
{
	IOLog("userClient::stop\n");
	super::stop(provider);
}

void	com_osxkernel_driver_IOKitTestUserClient::free (void)
{
	IOLog("userClient::free\n");
	super::free();
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::clientClose (void)
{
	terminate();
	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::clientDied (void)
{
	IOLog("userClient::clientDied\n");
	return super::clientDied();
}




IOReturn	com_osxkernel_driver_IOKitTestUserClient::sStartTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;

	return me->startTimer();
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sStopTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;

	return me->stopTimer();
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sGetElapsedTimerTime (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;
	uint32_t		timerTime;
	IOReturn		result;

	result = me->getElapsedTimerTime(&timerTime);
	arguments->scalarOutput[0] = timerTime;

	return result;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sGetElapsedTimerValue (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;

	return me->getElapsedTimerValue((TimerValue*)arguments->structureOutput);
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sDelayForMs (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;

	return me->delayForMs((uint32_t)arguments->scalarInput[0]);
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sDelayForTime (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	com_osxkernel_driver_IOKitTestUserClient*	me = (com_osxkernel_driver_IOKitTestUserClient*)target;

	return me->delayForTime((TimerValue*)arguments->structureInput);
}


// A structure to hold parameters required by the background operation
struct TimerParams
{
	OSAsyncReference64		asyncRef;
	uint32_t				milliseconds;
	OSObject*				userClient;
};

IOReturn	com_osxkernel_driver_IOKitTestUserClient::sInstallTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments)
{
	TimerParams*	timerParams;
	thread_t		newThread;

	// Allocate a structure to store parameters required by the timer
	timerParams = (TimerParams*)IOMalloc(sizeof(TimerParams));
	// Take a copy of the asyncReference buffer
	bcopy(arguments->asyncReference, timerParams->asyncRef, sizeof(OSAsyncReference64));
	// Take a copy of the "milliseconds" value provided by the user application
	timerParams->milliseconds = (uint32_t)arguments->scalarInput[0];
	// Take a reference to the userClient object
	timerParams->userClient = target;
	// Retain the user client while an asynchronous operation is in progress
	target->retain();

	// Start a background thread to perform the synchronous operation
	kernel_thread_start(DelayThreadFunc, timerParams, &newThread);
	thread_deallocate(newThread);

	// Return immediately to the calling application
	return kIOReturnSuccess;
}

void	com_osxkernel_driver_IOKitTestUserClient::DelayThreadFunc (void *parameter, wait_result_t)
{
	TimerParams*	timerParams = (TimerParams*)parameter;

	// Sleep for the requested time
	IOSleep(timerParams->milliseconds);
	// Send a notification to the user application that the operation has competed
	sendAsyncResult64(timerParams->asyncRef, kIOReturnSuccess, NULL, 0);

	// The background operation has completed, release the extra reference to the user client object
	timerParams->userClient->release();

	IOFree(timerParams, sizeof(TimerParams));
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::startTimer ()
{
	if (m_timerRunning == true)
		return kIOReturnBusy;

	m_timerRunning = true;
	clock_get_uptime(&m_timerStartTime);

	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::stopTimer ()
{
	if (m_timerRunning == false)
		return kIOReturnNotOpen;

	m_timerRunning = false;
	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::getElapsedTimerTime (uint32_t* timerTime)
{
	uint64_t	timeNow;
	uint64_t	elapsedTime;

	if (m_timerRunning == false)
		return kIOReturnNotOpen;

	clock_get_uptime(&timeNow);
	absolutetime_to_nanoseconds((timeNow - m_timerStartTime), &elapsedTime);
	*timerTime = (uint32_t)(elapsedTime / 1000000);

	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::getElapsedTimerValue (TimerValue* timerValue)
{
	uint64_t	timeNow;
	uint64_t	elapsedTime;

	if (m_timerRunning == false)
		return kIOReturnNotOpen;

	clock_get_uptime(&timeNow);
	absolutetime_to_nanoseconds((timeNow - m_timerStartTime), &elapsedTime);
	timerValue->timebase = 1000000;
	timerValue->time = (elapsedTime * timerValue->timebase) / 1000000000;

	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::delayForMs (uint32_t milliseconds)
{
	IOSleep(milliseconds);
	return kIOReturnSuccess;
}

IOReturn	com_osxkernel_driver_IOKitTestUserClient::delayForTime (const TimerValue* timerValue)
{
	uint32_t		milliseconds;

	if (timerValue->timebase == 0)
		return kIOReturnBadArgument;

	milliseconds = (uint32_t)((timerValue->time * 1000) / timerValue->timebase);
	IOSleep(milliseconds);

	return kIOReturnSuccess;
}



const IOExternalMethodDispatch com_osxkernel_driver_IOKitTestUserClient::sMethods[kTestUserClientMethodCount] =
{
	// kTestUserClientStartTimer   (void)
	{ sStartTimer, 0, 0, 0, 0 },

	// kTestUserClientStopTimer   (void)
	{ sStopTimer, 0, 0, 0, 0 },

	// kTestUserClientGetElapsedTimerTime   (uint32_t* timerValue)
	{ sGetElapsedTimerTime, 0, 0, 1, 0 },

	// kTestUserClientGetElapsedTimerValue   (TimerValue* timerValue)
	{ sGetElapsedTimerValue, 0, 0, 0, sizeof(TimerValue) },

	// kTestUserClientDelayForMs   (uint32_t milliseconds)
	{ sDelayForMs, 1, 0, 0, 0 },

	// kTestUserClientDelayForTime  (const TimerValue* timerValue)
	{ sDelayForTime, 0, sizeof(TimerValue), 0, 0 },

	// kTestUserClientInstallTimer  (uint32_t milliseconds)
	{ sInstallTimer, 1, 0, 0, 0 }
};

IOReturn	com_osxkernel_driver_IOKitTestUserClient::externalMethod (uint32_t selector, IOExternalMethodArguments* arguments,
									IOExternalMethodDispatch* dispatch, OSObject* target, void* reference)
{
	// Ensure the requested control selector is within range
	if (selector >= kTestUserClientMethodCount)
		return kIOReturnUnsupported;

	printf("**externalMethods\n");

	dispatch = (IOExternalMethodDispatch*)&sMethods[selector];
	target = this;
	reference = NULL;
	return super::externalMethod(selector, arguments, dispatch, target, reference);
}

IOReturn com_osxkernel_driver_IOKitTestUserClient::setProperties(OSObject *properties)
{
	OSDictionary* propertyDict;

	printf("setProperties called\n");

	// The provided properties object should be an OSDictionary object.
	propertyDict = OSDynamicCast(OSDictionary, properties);
	if (propertyDict != NULL)
	{
		OSObject* theValue;
		OSString* theString;

		// Read the value corresponding to the key "StopMessage" from the dictionary.
		theValue = propertyDict->getObject("DOMOUNTME");
		theString = OSDynamicCast(OSString, theValue);
		if (theString != NULL)
		{
			// Add the value to the driver's property table.
			IOMedia *media = m_driver->getProvider();
			media->setProperty("DOMOUNTME", theString);
			printf("SETTING THE DAMN VALUE NOW\n");
			return kIOReturnSuccess;
		}
	}

	return kIOReturnUnsupported;

}
