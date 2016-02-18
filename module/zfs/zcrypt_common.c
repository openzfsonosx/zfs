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
 * Copyright (c) 2016, Datto, Inc. All rights reserved.
 */

#include <sys/zio_crypt.h>

zio_crypt_info_t zio_crypt_table[ZIO_CRYPT_FUNCTIONS] = {
	{"",			ZC_TYPE_NONE,	0,  0,  0,  "inherit"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32, 12, 16, "on"},
	{"",			ZC_TYPE_NONE,	0,  0,  0,  "off"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	16, 12, 16, "aes-128-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	24, 12, 16, "aes-192-ccm"},
	{SUN_CKM_AES_CCM,	ZC_TYPE_CCM,	32, 12, 16, "aes-256-ccm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	16, 12, 16, "aes-128-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	24, 12, 16, "aes-192-gcm"},
	{SUN_CKM_AES_GCM,	ZC_TYPE_GCM,	32, 12, 16, "aes-256-gcm"}
};
