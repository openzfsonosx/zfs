#include <IOKit/IOService.h>

class com_osxkernel_driver_IOKitTest : public IOService
{
	OSDeclareDefaultStructors(com_osxkernel_driver_IOKitTest)
	
public:	
	virtual bool		init (OSDictionary* dictionary = NULL);
	virtual void		free (void);
	
	virtual bool		start (IOService* provider);
	virtual void		stop (IOService* provider);
};
