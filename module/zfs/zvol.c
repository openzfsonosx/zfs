/*
 * This file left empty as an exercise to the reader.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/zap.h>
#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/dsl_prop.h>
#include <sys/dkio.h>
#include <sys/byteorder.h>
#include <sys/pathname.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/crc32.h>
#include <sys/dirent.h>
#include <sys/policy.h>
#include <sys/fs/zfs.h>
#include <sys/zfs_ioctl.h>
#include <sys/mkdev.h>
#include <sys/zil.h>
#include <sys/refcount.h>
#include <sys/zfs_znode.h>
#include <sys/zfs_rlock.h>

#include "zfs_namecheck.h"

int zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
    return 0;
}

int zvol_check_volblocksize(uint64_t volblocksize)
{
    return 0;
}

int zvol_get_stats(objset_t *os, nvlist_t *nv)
{
    return 0;
}


void zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
}

int zvol_create_minor(const char *name)
{
    return 0;
}

int zvol_create_minors(const char *name)
{
    return 0;
}

int zvol_remove_minor(const char *name)
{
    return 0;
}

void zvol_remove_minors(const char *name)
{
}

int zvol_set_volsize(const char *name, uint64_t size)
{
    return 0;
}

int zvol_set_volblocksize(const char *name, uint64_t size)
{
    return 0;
}


int zvol_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
    return 0;
}

int zvol_close(dev_t dev, int flag, int otyp, cred_t *cr)
{
    return 0;
}

int zvol_read(dev_t dev, uio_t *uiop, cred_t *cr)
{
    return 0;
}

int zvol_write(dev_t dev, uio_t *uiop, cred_t *cr)
{
    return 0;
}


int zvol_busy(void)
{
    return 0;
}

int zvol_init(void)
{
    return 0;
}

void zvol_fini(void)
{
}

