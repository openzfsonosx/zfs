/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2016, Brendon Humphrey (brendon.humphrey@mac.com). All rights reserved.
 */

#ifndef _LIBDISKMGT_H
#define _LIBDISKMGT_H

#include <libnvpair.h>

#ifdef __cplusplus
extern "C" {
#endif

  /* attribute definitions */

  /* drive */
  //#define	DM_DISK_UP		1
  //#define	DM_DISK_DOWN		0

  //#define	DM_CLUSTERED		"clustered"
  //#define	DM_DRVTYPE		"drvtype"
  //#define	DM_FAILING		"failing"
  //#define	DM_LOADED		"loaded"	/* also in media */
  //#define	DM_NDNRERRS		"ndevice_not_ready_errors"
  //#define	DM_NBYTESREAD		"nbytes_read"
  //#define	DM_NBYTESWRITTEN	"nbytes_written"
  //#define	DM_NHARDERRS		"nhard_errors"
  //#define	DM_NILLREQERRS		"nillegal_req_errors"
  //#define	DM_NMEDIAERRS		"nmedia_errors"
  //#define	DM_NNODEVERRS		"nno_dev_errors"
  //#define	DM_NREADOPS		"nread_ops"
  //#define	DM_NRECOVERRS		"nrecoverable_errors"
  //#define	DM_NSOFTERRS		"nsoft_errors"
  //#define	DM_NTRANSERRS		"ntransport_errors"
  //#define	DM_NWRITEOPS		"nwrite_ops"
  //#define	DM_OPATH		"opath"
  //#define	DM_PRODUCT_ID		"product_id"
  //#define	DM_REMOVABLE		"removable"	/* also in media */
  //#define	DM_RPM			"rpm"
  //#define	DM_SOLIDSTATE		"solid_state"
  //#define	DM_STATUS		"status"
  //#define	DM_SYNC_SPEED		"sync_speed"
  //#define	DM_TEMPERATURE		"temperature"
  //#define	DM_VENDOR_ID		"vendor_id"
  //#define	DM_WIDE			"wide"		/* also on controller */
  //#define	DM_WWN			"wwn"

  /* bus */
  //#define	DM_BTYPE		"btype"
  //#define	DM_CLOCK		"clock"		/* also on controller */
  //#define	DM_PNAME		"pname"

  /* controller */
  //#define	DM_FAST			"fast"
  //#define	DM_FAST20		"fast20"
  //#define	DM_FAST40		"fast40"
  //#define	DM_FAST80		"fast80"
  //#define	DM_MULTIPLEX		"multiplex"
  //#define	DM_PATH_STATE		"path_state"

  //#define	DM_CTYPE_ATA		"ata"
  //#define	DM_CTYPE_SCSI		"scsi"
  //#define	DM_CTYPE_FIBRE		"fibre channel"
  //#define	DM_CTYPE_USB		"usb"
  //#define	DM_CTYPE_UNKNOWN	"unknown"

  /* media */
  //#define	DM_BLOCKSIZE		"blocksize"
  //#define	DM_FDISK		"fdisk"
  //#define	DM_MTYPE		"mtype"
  //#define	DM_NACTUALCYLINDERS	"nactual_cylinders"
  //#define	DM_NALTCYLINDERS	"nalt_cylinders"
  //#define	DM_NCYLINDERS		"ncylinders"
  //#define	DM_NHEADS		"nheads"
  //#define	DM_NPHYSCYLINDERS	"nphys_cylinders"
  //#define	DM_NSECTORS		"nsectors"	/* also in partition */
  //#define	DM_SIZE			"size"		/* also in slice */
  //#define	DM_NACCESSIBLE		"naccessible"
  //#define	DM_LABEL		"label"

  /* partition */
  //#define	DM_BCYL			"bcyl"
  //#define	DM_BHEAD		"bhead"
  //#define	DM_BOOTID		"bootid"
  //#define	DM_BSECT		"bsect"
  //#define	DM_ECYL			"ecyl"
  //#define	DM_EHEAD		"ehead"
  //#define	DM_ESECT		"esect"
  //#define	DM_PTYPE		"ptype" /* this references the partition id */
  //#define	DM_PARTITION_TYPE	"part_type" /* primary, extended, logical */
  //#define	DM_RELSECT		"relsect"

  /* slice */
  //#define	DM_DEVICEID		"deviceid"
  //#define	DM_DEVT			"devt"
  //#define	DM_INDEX		"index"
  //#define	DM_EFI_NAME		"name"
  //#define	DM_MOUNTPOINT		"mountpoint"
  //#define	DM_LOCALNAME		"localname"
  //#define	DM_START		"start"
  //#define	DM_TAG			"tag"
  //#define	DM_FLAG			"flag"
  //#define	DM_EFI			"efi"	/* also on media */
#define	DM_USED_BY		"used_by"
#define	DM_USED_NAME		"used_name"
#define	DM_USE_MOUNT		"mount"
  //#define	DM_USE_SVM		"svm"
  //#define	DM_USE_LU		"lu"
  //#define	DM_USE_DUMP		"dump"
  //#define	DM_USE_VXVM		"vxvm"
#define	DM_USE_FS		"fs"
  //#define	DM_USE_VFSTAB		"vfstab"
#define	DM_USE_EXPORTED_ZPOOL	"exported_zpool"
#define	DM_USE_ACTIVE_ZPOOL	"active_zpool"
#define	DM_USE_SPARE_ZPOOL	"spare_zpool"
#define	DM_USE_L2CACHE_ZPOOL	"l2cache_zpool"

  /* event */
  //#define	DM_EV_NAME		"name"
  //#define	DM_EV_DTYPE		"edtype"
  //#define	DM_EV_TYPE		"evtype"
  //#define	DM_EV_TADD		"add"
  //#define	DM_EV_TREMOVE		"remove"
  //#define	DM_EV_TCHANGE		"change"

  /* findisks */
  //#define	DM_CTYPE		"ctype"
  //#define	DM_LUN			"lun"
  //#define	DM_TARGET		"target"

#define	NOINUSE_SET	getenv("NOINUSE_CHECK") != NULL
  
  typedef enum {
    DM_WHO_ZPOOL = 0,
    DM_WHO_ZPOOL_FORCE,
    DM_WHO_ZPOOL_SPARE
  } dm_who_type_t;

  /* slice stat name */
  typedef enum {
    DM_SLICE_STAT_USE = 0
  } dm_slice_stat_t;
  
  /*
   * This is a partial implementation of (or similar to) libdiskmgt, adapted for OSX use.
   */
  int dm_in_swap_dir(const char *dev_name);
  int dm_inuse(char *dev_name, char **msg, dm_who_type_t who, int *errp);	

#ifdef __cplusplus
}
#endif

#endif
