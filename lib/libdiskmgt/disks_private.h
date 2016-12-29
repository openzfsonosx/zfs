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

#ifndef DISKS_PRIVATE_H
#define DISKS_PRIVATE_H

#include <libnvpair.h>
//#include <libdiskmgt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	NVATTRS	NV_UNIQUE_NAME | NV_UNIQUE_NAME_TYPE
#define	NVATTRS_STAT	0x0

	struct DU_CS_Info {
		int valid;
		char *summary;
	};

	struct DU_Info {
		int valid;
		char *summary;
	};
	
	void destroy_diskutil_cs_info(struct DU_CS_Info *info);
	void get_diskutil_cs_info(char *slice, struct DU_CS_Info *info);
	int is_cs_disk(struct DU_CS_Info *info);
	int is_converted(struct DU_CS_Info *info);
	int is_locked(struct DU_CS_Info *info);
	int is_logical_volume(struct DU_CS_Info *info);
	int is_physical_volume(struct DU_CS_Info *info);
	int is_online(struct DU_CS_Info *info);
	char* get_LV_status(struct DU_CS_Info *info);
	

	void destroy_diskutil_info(struct DU_Info *info);
	void get_diskutil_info(char *slice, struct DU_Info *info);

	int inuse_corestorage(char *slice, nvlist_t *attrs, int *errp);	
	int inuse_fs(char *slice, nvlist_t *attrs, int *errp);
	int inuse_macswap(const char *dev_name);
	int inuse_mnt(char *slice, nvlist_t *attrs, int *errp);  
	int inuse_mnt(char *slice, nvlist_t *attrs, int *errp);
	int inuse_active_zpool(char *slice, nvlist_t *attrs, int *errp);
	int inuse_exported_zpool(char *slice, nvlist_t *attrs, int *errp);
  
	void libdiskmgt_add_str(nvlist_t *attrs, char *name, char *val, int *errp);

	nvlist_t *slice_get_stats(char *slice, int stat_type, int *errp);
  
#ifdef __cplusplus
}
#endif

#endif
