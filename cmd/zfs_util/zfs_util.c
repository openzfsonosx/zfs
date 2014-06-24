/*
* Copyright (c) 2007 Apple Inc. All rights reserved.
* Use is subject to license terms stated below.
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License v. 1.0 (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://www.opensolaris.org/os/licensing <http://www.opensolaris.org/os/licensing> .
* See the License for the specific language governing permissions
* and limitations under the License.
*
* THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
*THE POSSIBILITY OF SUCH DAMAGE.
*/

/*	@(#)zfsutil.c   (c) 2007 Apple Inc.	*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/loadable_fs.h>

static void
usage(char *argv[])
{
	printf("usage: %s action_arg device_arg [Flags] \n", argv[0]);
	printf("action_arg:\n");
	printf("       -%c (Probe for mounting)\n", FSUC_PROBE);
	printf("device_arg:\n");
	printf("       device we are acting upon (for example, 'disk0s1')\n");
	printf("Flags:\n");
	printf("       required for Probe\n");
	printf("       indicates removable or fixed (for example 'fixed')\n");
	printf("       indicates readonly or writable (for example 'readonly')\n");
	printf("Examples:\n");
	printf("       %s -p disk0s1 removable readonly\n", argv[0]);
}

int
main(int argc, char **argv)
{
	/* Must have at least 3 arguments and the action argument must start * with a '-' */
	if ( (argc < 3) || (argv[1][0] != '-') ) {
		usage(argv);
		exit(FSUR_INVAL);
	}
	switch (argv[1][1]) {
	case FSUC_PROBE:
		exit(FSUR_RECOGNIZED);
	default:
		exit(FSUR_INVAL);
	}
}
