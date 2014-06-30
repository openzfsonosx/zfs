//
//  IOKitTestUserClient.h
//  IOKitTest
//

#include <IOKit/IOUserClient.h>
#include "IOKitTest.h"
#include "UserClientShared.h"
#include <ZFSProxyMediaScheme.h>

class com_osxkernel_driver_IOKitTestUserClient : public IOUserClient
{
	OSDeclareDefaultStructors(com_osxkernel_driver_IOKitTestUserClient)

private:
	task_t								m_task;
	ZFSProxyMediaScheme*		m_driver;

	bool		m_timerRunning;
	uint64_t	m_timerStartTime;

	static const IOExternalMethodDispatch	sMethods[kTestUserClientMethodCount];

	static IOReturn		sStartTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sStopTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sGetElapsedTimerTime (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sGetElapsedTimerValue (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sDelayForMs (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sDelayForTime (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static IOReturn		sInstallTimer (OSObject* target, void* reference, IOExternalMethodArguments* arguments);
	static void			DelayThreadFunc (void *parameter, wait_result_t);

	IOReturn		startTimer ();
	IOReturn		stopTimer ();
	IOReturn		getElapsedTimerTime (uint32_t* timerTime);
	IOReturn		getElapsedTimerValue (TimerValue* timerValue);
	IOReturn		delayForMs (uint32_t milliseconds);
	IOReturn		delayForTime (const TimerValue* timerValue);

public:
	virtual bool		initWithTask (task_t owningTask, void* securityToken, UInt32 type, OSDictionary* properties);
	virtual IOReturn	clientClose (void);
	virtual IOReturn	clientDied (void);

	virtual bool		start (IOService* provider);
	virtual void		stop (IOService* provider);
	virtual void		free (void);

	virtual IOReturn	externalMethod (uint32_t selector, IOExternalMethodArguments* arguments,
										IOExternalMethodDispatch* dispatch = 0, OSObject* target = 0, void* reference = 0);
	virtual IOReturn setProperties(OSObject *properties);
};
