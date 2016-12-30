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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "disks_private.h"

static int out_pipe[2], err_pipe[2];

static int
run_command(char *argv[], int *out_length)
{
	pid_t pid;
	int status = 0;
	struct stat out_stat; //, err_stat;
	
	pipe(out_pipe); //create a pipe
	pipe(err_pipe);
	pid = fork();
	
	if(pid == 0) {
		close(out_pipe[0]);
		close(err_pipe[0]);
		dup2(out_pipe[1], STDOUT_FILENO);
		dup2(err_pipe[1], STDERR_FILENO);
		
		execv(argv[0], argv);
	}
	
	// Parent
	close(out_pipe[1]);
	close(err_pipe[1]);
	waitpid(pid, &status, 0);
	
	fstat(out_pipe[0], &out_stat);
	
	*out_length = (int) out_stat.st_size;
	
	return status;
}

static void
read_buffers(char *out_buffer, int out_length)
{
	out_buffer[read(out_pipe[0], out_buffer, out_length)] = 0;
}

void
init_diskutil_cs_info(struct DU_CS_Info *info)
{
	info->valid = 0;
	info->summary = NULL;
}

void
destroy_diskutil_cs_info(struct DU_CS_Info *info)
{
	info->valid = 0;
	if (info->summary) {
		free(info->summary);
		info->summary = NULL;
	}
}

int
diskutil_cs_info_valid(struct DU_CS_Info *info)
{
	return info->valid;
}

void
get_diskutil_cs_info(char *slice, struct DU_CS_Info *info)
{
	int status = 0;
	int out_length = 0;
	char *cc[] = {"/usr/sbin/diskutil", "cs", "info", slice, NULL};
	
	destroy_diskutil_cs_info(info);
	
	status = run_command(cc, &out_length);
	
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		info->valid = 1;
		info->summary = (char*)malloc(out_length);
		read_buffers(info->summary, out_length);
	} else {
		info->valid = 0;
	}
}

static int
compare_key(char *summary, char *key, char *value)
{
	int matched = 0;
	char *rest = NULL;
	char *token = NULL;
	char k[128] = {0};
	char v[128] = {0};
	char *tmp_summary = NULL;
	
	tmp_summary = strdup(summary);
	
	if (tmp_summary) {
		rest = tmp_summary;
		
		while((token = strtok_r(rest, "\n", &rest)))
		{
			sscanf(token, " %[^:]: %[^\n]", k, v);
			
			if(strcmp(k, key) == 0) {
				//printf("compare ->%s<-, ->%s<- with ->%s<- ::: %d\n", k, v, value,  (strcmp(v, value) == 0));
				matched = (strcmp(v, value) == 0);
				break;
			}
		}
		
		free(tmp_summary);
	}
	
	return (matched);
}

static char*
get_value(char *summary, char *key)
{
	char *rest = NULL;
	char *token = NULL;
	char k[128] = {0};
	char v[128] = {0};
	char *tmp_summary = NULL;
	
	tmp_summary = strdup(summary);
	
	if (tmp_summary) {
		rest = tmp_summary;
		
		while((token = strtok_r(rest, "\n", &rest)))
		{
			sscanf(token, " %[^:]: %[^\n]", k, v);
			
			if(strcmp(k, key) == 0) {
				return strdup(v);
			}
		}
		
		free(tmp_summary);
	}
	
	return (NULL);
}

static int
compare_diskutil_cs_key(struct DU_CS_Info *info, char *key, char *value)
{
	return compare_key(info->summary, key, value);
}

static char*
get_diskutil_cs_value(struct DU_CS_Info *info, char *key)
{
	return (get_value(info->summary, key));
}

int
is_cs_disk(struct DU_CS_Info *info)
{
	return info->valid;
}

int
is_converted(struct DU_CS_Info *info)
{
	return (compare_diskutil_cs_key(info, "Conversion State", "Complete"));
}

int
is_locked(struct DU_CS_Info *info)
{
	return (compare_diskutil_cs_key(info, "LV Status", "Locked"));
}

int
is_online(struct DU_CS_Info *info)
{
	return (compare_diskutil_cs_key(info, "LV Status", "Online"));
}

char*
get_LV_status(struct DU_CS_Info *info)
{
	return (get_diskutil_cs_value(info, "LV Status"));
}

int
is_logical_volume(struct DU_CS_Info *info)
{
	return (compare_diskutil_cs_key(info, "Role", "Logical Volume (LV)"));
}

int
is_physical_volume(struct DU_CS_Info *info)
{
	return (compare_diskutil_cs_key(info, "Role", "Physical Volume (PV)"));
}

void
init_diskutil_info(struct DU_Info *info)
{
	info->valid = 0;
	info->summary = NULL;
}

void
destroy_diskutil_info(struct DU_Info *info)
{
	info->valid = 0;
	if (info->summary) {
		free(info->summary);
		info->summary = NULL;
	}
}

void
get_diskutil_info(char *slice, struct DU_Info *info)
{
	int status = 0;
	int out_length = 0;
	char *cc[] = {"/usr/sbin/diskutil", "info", slice, NULL};

	destroy_diskutil_info(info);
	
	status = run_command(cc, &out_length);
	
	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
		info->valid = 1;
		info->summary = (char*)malloc(out_length);
		read_buffers(info->summary, out_length);
	} else {
		info->valid = 0;
	}
}

static int
compare_diskutil_key(struct DU_Info *info, char *key, char *value)
{
	return compare_key(info->summary, key, value);
}

int
is_efi_partition(struct DU_Info *info)
{
	return (compare_diskutil_key(info, "Partition Type", "EFI"));
}

int
is_recovery_partition(struct DU_Info *info)
{
	return (compare_diskutil_key(info, "Partition Type", "Apple_Boot"));
}

int
is_APFS_partition(struct DU_Info *info)
{
	return (compare_diskutil_key(info, "Partition Type", "Apple_APFS"));
}

int
is_HFS_partition(struct DU_Info *info)
{
	return (compare_diskutil_key(info, "Partition Type", "Apple_HFS"));
}

int
is_MSDOS_partition(struct DU_Info *info)
{
	return (compare_diskutil_key(info, "Partition Type", "Microsoft Basic Data"));	
}

int
diskutil_info_valid(struct DU_Info *info)
{
	return (info->valid);
}
