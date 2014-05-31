/*
 *  vdevIO.h
 *  zfs
 *
 *  Created by Evan Susarret on 5/8/14.
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifndef __zfs__vdevIO__
#define	__zfs__vdevIO__

/*
 * #include <IOKit/IOCommand.h>
 * #include <IOKit/IOCommandPool.h>
 */
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOTypes.h>

typedef struct vdev_iokit_context {
	IOMemoryDescriptor * buffer;
	IOStorageCompletion completion;
} vdev_iokit_context_t;

#if 0 /* Disabled */
class net_lundman_vdev_io_context : public IOCommand
{
	OSDeclareDefaultStructors(net_lundman_vdev_io_context)

private:

public:
	virtual inline bool init(OSDictionary* dict = NULL);
	virtual inline void free(void);
	virtual inline bool initWithTransfer(zio_t * new_zio = NULL);
	virtual inline bool initWithDirection(IODirection);
	static IOCommand* withTransfer(zio_t * new_zio = NULL);
	static IOCommand* withDirection(IODirection);
	virtual bool configure(zio_t * new_zio = NULL);
	virtual bool prepare();
	virtual bool complete();
	virtual bool reset();

	IOBufferMemoryDescriptor * buffer;
	zio_t * zio;
	IOStorageCompletion completion;
	IODirection direction;
};
#endif /* Disabled */

#endif /* __zfs__vdevIO__ */


#ifdef __cplusplus
}
#endif /* __cplusplus */