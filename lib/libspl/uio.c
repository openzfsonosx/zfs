/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)uio.h       8.5 (Berkeley) 2/22/94
 */

/*
 * Cut down for userland's ztest: lundman 2017
 */

#include <sys/types.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <string.h>
#include <assert.h>

uio_t *uio_create(int iovcount, off_t offset, int spacetype, int iodirection)
{
	uint64_t                        my_size;
	uio_t                          *my_uio;

	// Future, make sure the uio struct is aligned, and do one alloc for uio and iovec
	my_size = sizeof(uio_t);
	my_uio = malloc(my_size);

	memset(my_uio, 0, my_size);
	//my_uio->uio_size = my_size;
	my_uio->uio_segflg = spacetype;

	if (iovcount > 0) {
		my_uio->uio_iov = malloc(iovcount * sizeof(iovec_t));
		memset(my_uio->uio_iov, 0, iovcount * sizeof(iovec_t));
	}
	else {
		my_uio->uio_iov = NULL;
	}
	my_uio->uio_max_iovs = iovcount;
	my_uio->uio_offset = offset;
	my_uio->uio_rw = iodirection;

	return (my_uio);
}

void uio_free(uio_t *uio)
{
	ASSERT(uio != NULL);
	ASSERT(uio->uio_iov != NULL);

	free(uio->uio_iov);
	free(uio);

}

int uio_addiov(uio_t *uio, user_addr_t baseaddr, user_size_t length)
{
	ASSERT(uio != NULL);
	ASSERT(uio->uio_iov != NULL);

	for (int i = 0; i < uio->uio_max_iovs; i++) {
		if (uio->uio_iov[i].iov_len == 0 && uio->uio_iov[i].iov_base == 0) {
			uio->uio_iov[i].iov_len = (size_t)length;
			uio->uio_iov[i].iov_base = (void *)baseaddr;
			uio->uio_iovcnt++;
			uio->uio_resid += length;
			return(0);
		}
	}

	return(-1);
}

int uio_isuserspace(uio_t *uio)
{
	ASSERT(uio != NULL);
	if (uio->uio_segflg == UIO_USERSPACE)
		return 1;
	return 0;
}

int uio_getiov(uio_t *uio, int index, user_addr_t *baseaddr, user_size_t *length)
{
	ASSERT(uio != NULL);
	ASSERT(uio->uio_iov != NULL);

	if (index < 0 || index >= uio->uio_iovcnt) {
		return(-1);
	}

	if (baseaddr != NULL) {
		*baseaddr = (uint64_t)uio->uio_iov[index].iov_base;
	}
	if (length != NULL) {
		*length = uio->uio_iov[index].iov_len;
	}

	return 0;
}

int uio_iovcnt(uio_t *uio)
{
	if (uio == NULL) {
		return(0);
	}

	return(uio->uio_iovcnt);
}


off_t uio_offset(uio_t *uio)
{
	ASSERT(uio != NULL);
	ASSERT(uio->uio_iov != NULL);

	if (uio == NULL) {
		return(0);
	}

	return(uio->uio_offset);
}

/*
 * This function is modelled after OsX, which means you can only pass
 * in a value between 0 and current "iov_len". Any larger number will
 * ignore the extra bytes.
*/
void uio_update(uio_t *uio, user_size_t count)
{
	uint32_t ind;

	if (uio == NULL || uio->uio_iovcnt < 1) {
		return;
	}

	ASSERT(uio->uio_index < uio->uio_iovcnt);

	ind = uio->uio_index;

	if (count) {
		if (count > uio->uio_iov->iov_len) {
			uio->uio_iov[ind].iov_base += uio->uio_iov[ind].iov_len;
			uio->uio_iov[ind].iov_len = 0;
		}
		else {
			uio->uio_iov[ind].iov_base += count;
			uio->uio_iov[ind].iov_len -= count;
		}
		if (count > (user_size_t)uio->uio_resid) {
			uio->uio_offset += uio->uio_resid;
			uio->uio_resid = 0;
		}
		else {
			uio->uio_offset += count;
			uio->uio_resid -= count;
		}
	}

	while (uio->uio_iovcnt > 0 && uio->uio_iov[ind].iov_len == 0) {
		uio->uio_iovcnt--;
		if (uio->uio_iovcnt > 0) {
			uio->uio_index = (ind++);
		}
	}
}


uint64_t uio_resid(uio_t *uio)
{
	if (uio == NULL) {
		return(0);
	}

	return(uio->uio_resid);
}

user_addr_t uio_curriovbase(uio_t *uio)
{
	if (uio == NULL || uio->uio_iovcnt < 1) {
		return(0);
	}

	return((user_addr_t)uio->uio_iov[uio->uio_index].iov_base);
}

user_size_t uio_curriovlen(uio_t *a_uio)
{
	if (a_uio == NULL || a_uio->uio_iovcnt < 1) {
		return(0);
	}

	return((user_size_t)a_uio->uio_iov[a_uio->uio_index].iov_len);
}

void uio_setoffset(uio_t *uio, off_t offset)
{
	if (uio == NULL) {
		return;
	}
	uio->uio_offset = offset;
}

int uio_rw(uio_t *a_uio)
{
	if (a_uio == NULL) {
		return(-1);
	}
	return(a_uio->uio_rw);
}

void uio_setrw(uio_t *a_uio, int a_value)
{
	if (a_uio == NULL) {
		return;
	}

	if (a_value == UIO_READ || a_value == UIO_WRITE) {
		a_uio->uio_rw = a_value;
	}
	return;
}

int uio_spacetype(uio_t *a_uio)
{
	if (a_uio == NULL) {
		return(-1);
	}

	return(a_uio->uio_segflg);
}


uio_t *uio_duplicate(uio_t *a_uio)
{
	uio_t           *my_uio;

	if (a_uio == NULL) {
		return(NULL);
	}

	my_uio = uio_create(a_uio->uio_max_iovs,
		uio_offset(a_uio),
		uio_spacetype(a_uio),
		uio_rw(a_uio));

	bcopy((void *)a_uio->uio_iov, (void *)my_uio->uio_iov, a_uio->uio_max_iovs * sizeof(iovec_t));
	my_uio->uio_index = a_uio->uio_index;
	my_uio->uio_resid = a_uio->uio_resid;
	my_uio->uio_iovcnt = a_uio->uio_iovcnt;

	return(my_uio);
}

int spllib_uiomove(const uint8_t *c_cp, uint32_t n, struct uio *uio)
{
	const uint8_t *cp = c_cp;
	uint64_t acnt;
	int error = 0;

	while (n > 0 && uio_resid(uio)) {
		uio_update(uio, 0);
		acnt = uio_curriovlen(uio);
		if (acnt == 0) {
			continue;
		}
		if (n > 0 && acnt > (uint64_t)n)
			acnt = n;

		switch ((int)uio->uio_segflg) {
		case UIO_SYSSPACE:
			if (uio->uio_rw == UIO_READ)
				/*error =*/ bcopy(cp, uio->uio_iov[uio->uio_index].iov_base,
					acnt);
			else
				/*error =*/ bcopy(uio->uio_iov[uio->uio_index].iov_base,
					(void *)cp,
					acnt);
			break;
		default:
			break;
		}
		uio_update(uio, acnt);
		cp += acnt;
		n -= acnt;
	}
	return (error);
}
