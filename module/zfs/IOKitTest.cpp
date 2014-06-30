#include "IOKitTest.h"
#include <IOKit/IOLib.h>

// Define the superclass
#define super IOService

OSDefineMetaClassAndStructors(com_osxkernel_driver_IOKitTest, IOService)


bool com_osxkernel_driver_IOKitTest::init (OSDictionary* dict)
{
	bool res = super::init(dict);
	return res;
}

void com_osxkernel_driver_IOKitTest::free (void)
{
	super::free();
}

bool com_osxkernel_driver_IOKitTest::start (IOService *provider)
{
	bool res = super::start(provider);
	setProperty("IOUserClientClass", "com_osxkernel_driver_IOKitTestUserClient");
	registerService();
	return res;
}

void com_osxkernel_driver_IOKitTest::stop (IOService *provider)
{
	super::stop(provider);
}
