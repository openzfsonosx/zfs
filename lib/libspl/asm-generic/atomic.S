	.section	__TEXT,__text,regular,pure_instructions
	.section	__DWARF,__debug_frame,regular,debug
Lsection_debug_frame:
	.section	__DWARF,__debug_info,regular,debug
Lsection_info:
	.section	__DWARF,__debug_abbrev,regular,debug
Lsection_abbrev:
	.section	__DWARF,__debug_aranges,regular,debug
Lsection_aranges:
	.section	__DWARF,__debug_macinfo,regular,debug
Lsection_macinfo:
Lsection_line:
	.section	__DWARF,__debug_loc,regular,debug
Lsection_loc:
	.section	__DWARF,__debug_pubnames,regular,debug
Lsection_pubnames:
	.section	__DWARF,__debug_pubtypes,regular,debug
Lsection_pubtypes:
	.section	__DWARF,__debug_str,regular,debug
Lsection_str:
	.section	__DWARF,__debug_ranges,regular,debug
Lsection_ranges:
	.section	__TEXT,__text,regular,pure_instructions
Ltext_begin:
	.section	__DATA,__data
Ldata_begin:
	.section	__TEXT,__text,regular,pure_instructions
	.globl	_atomic_inc_long
	.align	4, 0x90
_atomic_inc_long:
Leh_func_begin1:
Lfunc_begin1:
Ltmp3:
	pushq	%rbp
Ltmp0:
	movq	%rsp, %rbp
Ltmp1:
	subq	$128, %rsp
Ltmp2:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp4:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB1_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp5:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$51, %esi
	leaq	___func__.4157(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp6:
LBB1_2:
Ltmp7:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB1_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp8:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$51, %esi
	leaq	___func__.4157(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB1_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB1_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB1_7:
	callq	___stack_chk_fail
Ltmp9:
Lfunc_end1:
Leh_func_end1:

	.align	4, 0x90
___assert_c99:
Leh_func_begin2:
Lfunc_begin2:
Ltmp13:
	pushq	%rbp
Ltmp10:
	movq	%rsp, %rbp
Ltmp11:
	subq	$48, %rsp
Ltmp12:
	movq	%rcx, %rax
	movl	%edx, %r8d
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movl	%r8d, -20(%rbp)
	movq	%rax, -32(%rbp)
Ltmp14:
	movq	___stderrp@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-16(%rbp), %rsi
	movl	-20(%rbp), %edi
	movq	-32(%rbp), %r8
	movq	-8(%rbp), %r9
	xorb	%r10b, %r10b
	leaq	L_.str6(%rip), %r11
	movl	%edi, -36(%rbp)
	movq	%rax, %rdi
	movq	%rsi, -48(%rbp)
	movq	%r11, %rsi
	movq	-48(%rbp), %rax
	movq	%rax, %rdx
	movl	-36(%rbp), %eax
	movl	%eax, %ecx
	movb	%r10b, %al
	callq	_fprintf
Ltmp15:
	callq	_abort
Ltmp16:
Lfunc_end2:
Leh_func_end2:

	.globl	_atomic_inc_8
	.align	4, 0x90
_atomic_inc_8:
Leh_func_begin3:
Lfunc_begin3:
Ltmp20:
	pushq	%rbp
Ltmp17:
	movq	%rsp, %rbp
Ltmp18:
	subq	$128, %rsp
Ltmp19:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp21:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB3_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp22:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$52, %esi
	leaq	___func__.4183(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp23:
LBB3_2:
Ltmp24:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	addb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB3_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp25:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$52, %esi
	leaq	___func__.4183(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB3_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB3_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB3_7:
	callq	___stack_chk_fail
Ltmp26:
Lfunc_end3:
Leh_func_end3:

	.globl	_atomic_inc_uchar
	.align	4, 0x90
_atomic_inc_uchar:
Leh_func_begin4:
Lfunc_begin4:
Ltmp30:
	pushq	%rbp
Ltmp27:
	movq	%rsp, %rbp
Ltmp28:
	subq	$128, %rsp
Ltmp29:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp31:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB4_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp32:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$53, %esi
	leaq	___func__.4209(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp33:
LBB4_2:
Ltmp34:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	addb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB4_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp35:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$53, %esi
	leaq	___func__.4209(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB4_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB4_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB4_7:
	callq	___stack_chk_fail
Ltmp36:
Lfunc_end4:
Leh_func_end4:

	.globl	_atomic_inc_16
	.align	4, 0x90
_atomic_inc_16:
Leh_func_begin5:
Lfunc_begin5:
Ltmp40:
	pushq	%rbp
Ltmp37:
	movq	%rsp, %rbp
Ltmp38:
	subq	$128, %rsp
Ltmp39:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp41:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB5_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp42:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$54, %esi
	leaq	___func__.4235(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp43:
LBB5_2:
Ltmp44:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	addw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB5_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp45:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$54, %esi
	leaq	___func__.4235(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB5_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB5_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB5_7:
	callq	___stack_chk_fail
Ltmp46:
Lfunc_end5:
Leh_func_end5:

	.globl	_atomic_inc_ushort
	.align	4, 0x90
_atomic_inc_ushort:
Leh_func_begin6:
Lfunc_begin6:
Ltmp50:
	pushq	%rbp
Ltmp47:
	movq	%rsp, %rbp
Ltmp48:
	subq	$128, %rsp
Ltmp49:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp51:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB6_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp52:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$55, %esi
	leaq	___func__.4261(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp53:
LBB6_2:
Ltmp54:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	addw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB6_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp55:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$55, %esi
	leaq	___func__.4261(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB6_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB6_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB6_7:
	callq	___stack_chk_fail
Ltmp56:
Lfunc_end6:
Leh_func_end6:

	.globl	_atomic_inc_32
	.align	4, 0x90
_atomic_inc_32:
Leh_func_begin7:
Lfunc_begin7:
Ltmp60:
	pushq	%rbp
Ltmp57:
	movq	%rsp, %rbp
Ltmp58:
	subq	$128, %rsp
Ltmp59:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp61:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB7_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp62:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$56, %esi
	leaq	___func__.4287(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp63:
LBB7_2:
Ltmp64:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	addl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB7_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp65:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$56, %esi
	leaq	___func__.4287(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB7_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB7_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB7_7:
	callq	___stack_chk_fail
Ltmp66:
Lfunc_end7:
Leh_func_end7:

	.globl	_atomic_inc_uint
	.align	4, 0x90
_atomic_inc_uint:
Leh_func_begin8:
Lfunc_begin8:
Ltmp70:
	pushq	%rbp
Ltmp67:
	movq	%rsp, %rbp
Ltmp68:
	subq	$128, %rsp
Ltmp69:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp71:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB8_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp72:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$57, %esi
	leaq	___func__.4313(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp73:
LBB8_2:
Ltmp74:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	addl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB8_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp75:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$57, %esi
	leaq	___func__.4313(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB8_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB8_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB8_7:
	callq	___stack_chk_fail
Ltmp76:
Lfunc_end8:
Leh_func_end8:

	.globl	_atomic_inc_ulong
	.align	4, 0x90
_atomic_inc_ulong:
Leh_func_begin9:
Lfunc_begin9:
Ltmp80:
	pushq	%rbp
Ltmp77:
	movq	%rsp, %rbp
Ltmp78:
	subq	$128, %rsp
Ltmp79:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp81:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB9_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp82:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$58, %esi
	leaq	___func__.4339(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp83:
LBB9_2:
Ltmp84:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB9_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp85:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$58, %esi
	leaq	___func__.4339(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB9_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB9_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB9_7:
	callq	___stack_chk_fail
Ltmp86:
Lfunc_end9:
Leh_func_end9:

	.globl	_atomic_inc_64
	.align	4, 0x90
_atomic_inc_64:
Leh_func_begin10:
Lfunc_begin10:
Ltmp90:
	pushq	%rbp
Ltmp87:
	movq	%rsp, %rbp
Ltmp88:
	subq	$128, %rsp
Ltmp89:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp91:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB10_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp92:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$59, %esi
	leaq	___func__.4365(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp93:
LBB10_2:
Ltmp94:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB10_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp95:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$59, %esi
	leaq	___func__.4365(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB10_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB10_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB10_7:
	callq	___stack_chk_fail
Ltmp96:
Lfunc_end10:
Leh_func_end10:

	.globl	_atomic_dec_long
	.align	4, 0x90
_atomic_dec_long:
Leh_func_begin11:
Lfunc_begin11:
Ltmp100:
	pushq	%rbp
Ltmp97:
	movq	%rsp, %rbp
Ltmp98:
	subq	$128, %rsp
Ltmp99:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp101:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB11_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp102:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$70, %esi
	leaq	___func__.4391(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp103:
LBB11_2:
Ltmp104:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB11_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp105:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$70, %esi
	leaq	___func__.4391(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB11_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB11_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB11_7:
	callq	___stack_chk_fail
Ltmp106:
Lfunc_end11:
Leh_func_end11:

	.globl	_atomic_dec_8
	.align	4, 0x90
_atomic_dec_8:
Leh_func_begin12:
Lfunc_begin12:
Ltmp110:
	pushq	%rbp
Ltmp107:
	movq	%rsp, %rbp
Ltmp108:
	subq	$128, %rsp
Ltmp109:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp111:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB12_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp112:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$71, %esi
	leaq	___func__.4417(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp113:
LBB12_2:
Ltmp114:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	subb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB12_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp115:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$71, %esi
	leaq	___func__.4417(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB12_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB12_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB12_7:
	callq	___stack_chk_fail
Ltmp116:
Lfunc_end12:
Leh_func_end12:

	.globl	_atomic_dec_uchar
	.align	4, 0x90
_atomic_dec_uchar:
Leh_func_begin13:
Lfunc_begin13:
Ltmp120:
	pushq	%rbp
Ltmp117:
	movq	%rsp, %rbp
Ltmp118:
	subq	$128, %rsp
Ltmp119:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp121:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB13_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp122:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$72, %esi
	leaq	___func__.4443(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp123:
LBB13_2:
Ltmp124:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	subb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB13_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp125:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$72, %esi
	leaq	___func__.4443(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB13_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB13_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB13_7:
	callq	___stack_chk_fail
Ltmp126:
Lfunc_end13:
Leh_func_end13:

	.globl	_atomic_dec_16
	.align	4, 0x90
_atomic_dec_16:
Leh_func_begin14:
Lfunc_begin14:
Ltmp130:
	pushq	%rbp
Ltmp127:
	movq	%rsp, %rbp
Ltmp128:
	subq	$128, %rsp
Ltmp129:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp131:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB14_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp132:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$73, %esi
	leaq	___func__.4469(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp133:
LBB14_2:
Ltmp134:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	subw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB14_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp135:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$73, %esi
	leaq	___func__.4469(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB14_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB14_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB14_7:
	callq	___stack_chk_fail
Ltmp136:
Lfunc_end14:
Leh_func_end14:

	.globl	_atomic_dec_ushort
	.align	4, 0x90
_atomic_dec_ushort:
Leh_func_begin15:
Lfunc_begin15:
Ltmp140:
	pushq	%rbp
Ltmp137:
	movq	%rsp, %rbp
Ltmp138:
	subq	$128, %rsp
Ltmp139:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp141:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB15_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp142:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$74, %esi
	leaq	___func__.4495(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp143:
LBB15_2:
Ltmp144:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	subw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB15_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp145:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$74, %esi
	leaq	___func__.4495(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB15_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB15_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB15_7:
	callq	___stack_chk_fail
Ltmp146:
Lfunc_end15:
Leh_func_end15:

	.globl	_atomic_dec_32
	.align	4, 0x90
_atomic_dec_32:
Leh_func_begin16:
Lfunc_begin16:
Ltmp150:
	pushq	%rbp
Ltmp147:
	movq	%rsp, %rbp
Ltmp148:
	subq	$128, %rsp
Ltmp149:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp151:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB16_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp152:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$75, %esi
	leaq	___func__.4521(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp153:
LBB16_2:
Ltmp154:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	subl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB16_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp155:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$75, %esi
	leaq	___func__.4521(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB16_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB16_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB16_7:
	callq	___stack_chk_fail
Ltmp156:
Lfunc_end16:
Leh_func_end16:

	.globl	_atomic_dec_uint
	.align	4, 0x90
_atomic_dec_uint:
Leh_func_begin17:
Lfunc_begin17:
Ltmp160:
	pushq	%rbp
Ltmp157:
	movq	%rsp, %rbp
Ltmp158:
	subq	$128, %rsp
Ltmp159:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp161:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB17_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp162:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$76, %esi
	leaq	___func__.4547(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp163:
LBB17_2:
Ltmp164:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	subl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB17_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp165:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$76, %esi
	leaq	___func__.4547(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB17_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB17_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB17_7:
	callq	___stack_chk_fail
Ltmp166:
Lfunc_end17:
Leh_func_end17:

	.globl	_atomic_dec_ulong
	.align	4, 0x90
_atomic_dec_ulong:
Leh_func_begin18:
Lfunc_begin18:
Ltmp170:
	pushq	%rbp
Ltmp167:
	movq	%rsp, %rbp
Ltmp168:
	subq	$128, %rsp
Ltmp169:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp171:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB18_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp172:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$77, %esi
	leaq	___func__.4573(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp173:
LBB18_2:
Ltmp174:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB18_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp175:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$77, %esi
	leaq	___func__.4573(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB18_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB18_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB18_7:
	callq	___stack_chk_fail
Ltmp176:
Lfunc_end18:
Leh_func_end18:

	.globl	_atomic_dec_64
	.align	4, 0x90
_atomic_dec_64:
Leh_func_begin19:
Lfunc_begin19:
Ltmp180:
	pushq	%rbp
Ltmp177:
	movq	%rsp, %rbp
Ltmp178:
	subq	$128, %rsp
Ltmp179:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp181:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -24(%rbp)
	movq	$0, -32(%rbp)
	movq	-24(%rbp), %rcx
	movq	-32(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB19_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp182:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -40(%rbp)
	movq	-32(%rbp), %rdx
	movq	-24(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -72(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -73(%rbp)
	movq	%rax, %rsi
	movq	-72(%rbp), %rcx
	movb	-73(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-40(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$78, %esi
	leaq	___func__.4599(%rip), %rdi
	movq	%rdi, -88(%rbp)
	movq	%rax, %rdi
	movl	%esi, -92(%rbp)
	movq	%rcx, %rsi
	movl	-92(%rbp), %eax
	movl	%eax, %edx
	movq	-88(%rbp), %rcx
	callq	___assert_c99
Ltmp183:
LBB19_2:
Ltmp184:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB19_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp185:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$78, %esi
	leaq	___func__.4599(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
LBB19_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB19_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB19_7:
	callq	___stack_chk_fail
Ltmp186:
Lfunc_end19:
Leh_func_end19:

	.globl	_atomic_add_8
	.align	4, 0x90
_atomic_add_8:
Leh_func_begin20:
Lfunc_begin20:
Ltmp190:
	pushq	%rbp
Ltmp187:
	movq	%rsp, %rbp
Ltmp188:
	subq	$144, %rsp
Ltmp189:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp191:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB20_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp192:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$89, %esi
	leaq	___func__.4626(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp193:
LBB20_2:
Ltmp194:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	addb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB20_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp195:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$89, %esi
	leaq	___func__.4626(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB20_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB20_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB20_7:
	callq	___stack_chk_fail
Ltmp196:
Lfunc_end20:
Leh_func_end20:

	.globl	_atomic_add_char
	.align	4, 0x90
_atomic_add_char:
Leh_func_begin21:
Lfunc_begin21:
Ltmp200:
	pushq	%rbp
Ltmp197:
	movq	%rsp, %rbp
Ltmp198:
	subq	$144, %rsp
Ltmp199:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp201:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB21_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp202:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$90, %esi
	leaq	___func__.4654(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp203:
LBB21_2:
Ltmp204:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	addb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB21_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp205:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$90, %esi
	leaq	___func__.4654(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB21_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB21_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB21_7:
	callq	___stack_chk_fail
Ltmp206:
Lfunc_end21:
Leh_func_end21:

	.globl	_atomic_add_16
	.align	4, 0x90
_atomic_add_16:
Leh_func_begin22:
Lfunc_begin22:
Ltmp210:
	pushq	%rbp
Ltmp207:
	movq	%rsp, %rbp
Ltmp208:
	subq	$144, %rsp
Ltmp209:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp211:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB22_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp212:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$91, %esi
	leaq	___func__.4682(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp213:
LBB22_2:
Ltmp214:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	addw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB22_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp215:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$91, %esi
	leaq	___func__.4682(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB22_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB22_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB22_7:
	callq	___stack_chk_fail
Ltmp216:
Lfunc_end22:
Leh_func_end22:

	.globl	_atomic_add_short
	.align	4, 0x90
_atomic_add_short:
Leh_func_begin23:
Lfunc_begin23:
Ltmp220:
	pushq	%rbp
Ltmp217:
	movq	%rsp, %rbp
Ltmp218:
	subq	$144, %rsp
Ltmp219:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp221:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB23_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp222:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$92, %esi
	leaq	___func__.4710(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp223:
LBB23_2:
Ltmp224:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	addw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB23_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp225:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$92, %esi
	leaq	___func__.4710(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB23_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB23_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB23_7:
	callq	___stack_chk_fail
Ltmp226:
Lfunc_end23:
Leh_func_end23:

	.globl	_atomic_add_32
	.align	4, 0x90
_atomic_add_32:
Leh_func_begin24:
Lfunc_begin24:
Ltmp230:
	pushq	%rbp
Ltmp227:
	movq	%rsp, %rbp
Ltmp228:
	subq	$144, %rsp
Ltmp229:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp231:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB24_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp232:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$93, %esi
	leaq	___func__.4738(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp233:
LBB24_2:
Ltmp234:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	addl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB24_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp235:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$93, %esi
	leaq	___func__.4738(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB24_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB24_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB24_7:
	callq	___stack_chk_fail
Ltmp236:
Lfunc_end24:
Leh_func_end24:

	.globl	_atomic_add_int
	.align	4, 0x90
_atomic_add_int:
Leh_func_begin25:
Lfunc_begin25:
Ltmp240:
	pushq	%rbp
Ltmp237:
	movq	%rsp, %rbp
Ltmp238:
	subq	$144, %rsp
Ltmp239:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp241:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB25_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp242:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$94, %esi
	leaq	___func__.4766(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp243:
LBB25_2:
Ltmp244:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	addl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB25_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp245:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$94, %esi
	leaq	___func__.4766(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB25_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB25_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB25_7:
	callq	___stack_chk_fail
Ltmp246:
Lfunc_end25:
Leh_func_end25:

	.globl	_atomic_add_long
	.align	4, 0x90
_atomic_add_long:
Leh_func_begin26:
Lfunc_begin26:
Ltmp250:
	pushq	%rbp
Ltmp247:
	movq	%rsp, %rbp
Ltmp248:
	subq	$144, %rsp
Ltmp249:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp251:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB26_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp252:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$95, %esi
	leaq	___func__.4794(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp253:
LBB26_2:
Ltmp254:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB26_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp255:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$95, %esi
	leaq	___func__.4794(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB26_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB26_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB26_7:
	callq	___stack_chk_fail
Ltmp256:
Lfunc_end26:
Leh_func_end26:

	.globl	_atomic_add_64
	.align	4, 0x90
_atomic_add_64:
Leh_func_begin27:
Lfunc_begin27:
Ltmp260:
	pushq	%rbp
Ltmp257:
	movq	%rsp, %rbp
Ltmp258:
	subq	$144, %rsp
Ltmp259:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp261:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB27_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp262:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$96, %esi
	leaq	___func__.4822(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp263:
LBB27_2:
Ltmp264:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB27_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp265:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$96, %esi
	leaq	___func__.4822(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB27_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB27_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB27_7:
	callq	___stack_chk_fail
Ltmp266:
Lfunc_end27:
Leh_func_end27:

	.globl	_atomic_add_ptr
	.align	4, 0x90
_atomic_add_ptr:
Leh_func_begin28:
Lfunc_begin28:
Ltmp270:
	pushq	%rbp
Ltmp267:
	movq	%rsp, %rbp
Ltmp268:
	subq	$144, %rsp
Ltmp269:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp271:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB28_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp272:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$100, %esi
	leaq	___func__.4850(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp273:
LBB28_2:
Ltmp274:
	movq	-16(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-24(%rbp), %rdx
	addq	%rdx, %rcx
	movq	%rcx, (%rax)
Ltmp275:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB28_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp276:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$102, %esi
	leaq	___func__.4850(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB28_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB28_7
Ltmp277:
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB28_7:
	callq	___stack_chk_fail
Ltmp278:
Lfunc_end28:
Leh_func_end28:

	.globl	_atomic_sub_8
	.align	4, 0x90
_atomic_sub_8:
Leh_func_begin29:
Lfunc_begin29:
Ltmp282:
	pushq	%rbp
Ltmp279:
	movq	%rsp, %rbp
Ltmp280:
	subq	$144, %rsp
Ltmp281:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp283:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB29_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp284:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$114, %esi
	leaq	___func__.4879(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp285:
LBB29_2:
Ltmp286:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	subb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB29_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp287:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$114, %esi
	leaq	___func__.4879(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB29_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB29_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB29_7:
	callq	___stack_chk_fail
Ltmp288:
Lfunc_end29:
Leh_func_end29:

	.globl	_atomic_sub_char
	.align	4, 0x90
_atomic_sub_char:
Leh_func_begin30:
Lfunc_begin30:
Ltmp292:
	pushq	%rbp
Ltmp289:
	movq	%rsp, %rbp
Ltmp290:
	subq	$144, %rsp
Ltmp291:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp293:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB30_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp294:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$115, %esi
	leaq	___func__.4907(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp295:
LBB30_2:
Ltmp296:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	subb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB30_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp297:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$115, %esi
	leaq	___func__.4907(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB30_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB30_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB30_7:
	callq	___stack_chk_fail
Ltmp298:
Lfunc_end30:
Leh_func_end30:

	.globl	_atomic_sub_16
	.align	4, 0x90
_atomic_sub_16:
Leh_func_begin31:
Lfunc_begin31:
Ltmp302:
	pushq	%rbp
Ltmp299:
	movq	%rsp, %rbp
Ltmp300:
	subq	$144, %rsp
Ltmp301:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp303:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB31_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp304:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$116, %esi
	leaq	___func__.4935(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp305:
LBB31_2:
Ltmp306:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	subw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB31_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp307:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$116, %esi
	leaq	___func__.4935(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB31_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB31_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB31_7:
	callq	___stack_chk_fail
Ltmp308:
Lfunc_end31:
Leh_func_end31:

	.globl	_atomic_sub_short
	.align	4, 0x90
_atomic_sub_short:
Leh_func_begin32:
Lfunc_begin32:
Ltmp312:
	pushq	%rbp
Ltmp309:
	movq	%rsp, %rbp
Ltmp310:
	subq	$144, %rsp
Ltmp311:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp313:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB32_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp314:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$117, %esi
	leaq	___func__.4963(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp315:
LBB32_2:
Ltmp316:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	subw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB32_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp317:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$117, %esi
	leaq	___func__.4963(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB32_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB32_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB32_7:
	callq	___stack_chk_fail
Ltmp318:
Lfunc_end32:
Leh_func_end32:

	.globl	_atomic_sub_32
	.align	4, 0x90
_atomic_sub_32:
Leh_func_begin33:
Lfunc_begin33:
Ltmp322:
	pushq	%rbp
Ltmp319:
	movq	%rsp, %rbp
Ltmp320:
	subq	$144, %rsp
Ltmp321:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp323:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB33_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp324:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$118, %esi
	leaq	___func__.4991(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp325:
LBB33_2:
Ltmp326:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	subl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB33_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp327:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$118, %esi
	leaq	___func__.4991(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB33_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB33_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB33_7:
	callq	___stack_chk_fail
Ltmp328:
Lfunc_end33:
Leh_func_end33:

	.globl	_atomic_sub_int
	.align	4, 0x90
_atomic_sub_int:
Leh_func_begin34:
Lfunc_begin34:
Ltmp332:
	pushq	%rbp
Ltmp329:
	movq	%rsp, %rbp
Ltmp330:
	subq	$144, %rsp
Ltmp331:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp333:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB34_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp334:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$119, %esi
	leaq	___func__.5019(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp335:
LBB34_2:
Ltmp336:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	subl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB34_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp337:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$119, %esi
	leaq	___func__.5019(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB34_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB34_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB34_7:
	callq	___stack_chk_fail
Ltmp338:
Lfunc_end34:
Leh_func_end34:

	.globl	_atomic_sub_long
	.align	4, 0x90
_atomic_sub_long:
Leh_func_begin35:
Lfunc_begin35:
Ltmp342:
	pushq	%rbp
Ltmp339:
	movq	%rsp, %rbp
Ltmp340:
	subq	$144, %rsp
Ltmp341:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp343:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB35_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp344:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$120, %esi
	leaq	___func__.5047(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp345:
LBB35_2:
Ltmp346:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB35_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp347:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$120, %esi
	leaq	___func__.5047(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB35_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB35_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB35_7:
	callq	___stack_chk_fail
Ltmp348:
Lfunc_end35:
Leh_func_end35:

	.globl	_atomic_sub_64
	.align	4, 0x90
_atomic_sub_64:
Leh_func_begin36:
Lfunc_begin36:
Ltmp352:
	pushq	%rbp
Ltmp349:
	movq	%rsp, %rbp
Ltmp350:
	subq	$144, %rsp
Ltmp351:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp353:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB36_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp354:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$121, %esi
	leaq	___func__.5075(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp355:
LBB36_2:
Ltmp356:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB36_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp357:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$121, %esi
	leaq	___func__.5075(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB36_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB36_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB36_7:
	callq	___stack_chk_fail
Ltmp358:
Lfunc_end36:
Leh_func_end36:

	.globl	_atomic_sub_ptr
	.align	4, 0x90
_atomic_sub_ptr:
Leh_func_begin37:
Lfunc_begin37:
Ltmp362:
	pushq	%rbp
Ltmp359:
	movq	%rsp, %rbp
Ltmp360:
	subq	$144, %rsp
Ltmp361:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp363:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB37_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp364:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$125, %esi
	leaq	___func__.5103(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp365:
LBB37_2:
Ltmp366:
	movq	-16(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-24(%rbp), %rdx
	movabsq	$0, %rsi
	subq	%rdx, %rsi
	addq	%rsi, %rcx
	movq	%rcx, (%rax)
Ltmp367:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB37_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp368:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$127, %esi
	leaq	___func__.5103(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB37_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB37_7
Ltmp369:
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB37_7:
	callq	___stack_chk_fail
Ltmp370:
Lfunc_end37:
Leh_func_end37:

	.globl	_atomic_or_8
	.align	4, 0x90
_atomic_or_8:
Leh_func_begin38:
Lfunc_begin38:
Ltmp374:
	pushq	%rbp
Ltmp371:
	movq	%rsp, %rbp
Ltmp372:
	subq	$144, %rsp
Ltmp373:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp375:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB38_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp376:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$139, %esi
	leaq	___func__.5133(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp377:
LBB38_2:
Ltmp378:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	orb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB38_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp379:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$139, %esi
	leaq	___func__.5133(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB38_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB38_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB38_7:
	callq	___stack_chk_fail
Ltmp380:
Lfunc_end38:
Leh_func_end38:

	.globl	_atomic_or_uchar
	.align	4, 0x90
_atomic_or_uchar:
Leh_func_begin39:
Lfunc_begin39:
Ltmp384:
	pushq	%rbp
Ltmp381:
	movq	%rsp, %rbp
Ltmp382:
	subq	$144, %rsp
Ltmp383:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp385:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB39_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp386:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$140, %esi
	leaq	___func__.5160(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp387:
LBB39_2:
Ltmp388:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	orb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB39_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp389:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$140, %esi
	leaq	___func__.5160(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB39_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB39_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB39_7:
	callq	___stack_chk_fail
Ltmp390:
Lfunc_end39:
Leh_func_end39:

	.globl	_atomic_or_16
	.align	4, 0x90
_atomic_or_16:
Leh_func_begin40:
Lfunc_begin40:
Ltmp394:
	pushq	%rbp
Ltmp391:
	movq	%rsp, %rbp
Ltmp392:
	subq	$144, %rsp
Ltmp393:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp395:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB40_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp396:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$141, %esi
	leaq	___func__.5187(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp397:
LBB40_2:
Ltmp398:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	orw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB40_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp399:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$141, %esi
	leaq	___func__.5187(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB40_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB40_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB40_7:
	callq	___stack_chk_fail
Ltmp400:
Lfunc_end40:
Leh_func_end40:

	.globl	_atomic_or_ushort
	.align	4, 0x90
_atomic_or_ushort:
Leh_func_begin41:
Lfunc_begin41:
Ltmp404:
	pushq	%rbp
Ltmp401:
	movq	%rsp, %rbp
Ltmp402:
	subq	$144, %rsp
Ltmp403:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp405:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB41_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp406:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$142, %esi
	leaq	___func__.5214(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp407:
LBB41_2:
Ltmp408:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	orw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB41_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp409:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$142, %esi
	leaq	___func__.5214(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB41_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB41_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB41_7:
	callq	___stack_chk_fail
Ltmp410:
Lfunc_end41:
Leh_func_end41:

	.globl	_atomic_or_32
	.align	4, 0x90
_atomic_or_32:
Leh_func_begin42:
Lfunc_begin42:
Ltmp414:
	pushq	%rbp
Ltmp411:
	movq	%rsp, %rbp
Ltmp412:
	subq	$144, %rsp
Ltmp413:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp415:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB42_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp416:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$143, %esi
	leaq	___func__.5241(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp417:
LBB42_2:
Ltmp418:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	orl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB42_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp419:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$143, %esi
	leaq	___func__.5241(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB42_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB42_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB42_7:
	callq	___stack_chk_fail
Ltmp420:
Lfunc_end42:
Leh_func_end42:

	.globl	_atomic_or_uint
	.align	4, 0x90
_atomic_or_uint:
Leh_func_begin43:
Lfunc_begin43:
Ltmp424:
	pushq	%rbp
Ltmp421:
	movq	%rsp, %rbp
Ltmp422:
	subq	$144, %rsp
Ltmp423:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp425:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB43_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp426:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$144, %esi
	leaq	___func__.5268(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp427:
LBB43_2:
Ltmp428:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	orl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB43_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp429:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$144, %esi
	leaq	___func__.5268(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB43_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB43_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB43_7:
	callq	___stack_chk_fail
Ltmp430:
Lfunc_end43:
Leh_func_end43:

	.globl	_atomic_or_ulong
	.align	4, 0x90
_atomic_or_ulong:
Leh_func_begin44:
Lfunc_begin44:
Ltmp434:
	pushq	%rbp
Ltmp431:
	movq	%rsp, %rbp
Ltmp432:
	subq	$144, %rsp
Ltmp433:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp435:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB44_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp436:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$145, %esi
	leaq	___func__.5295(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp437:
LBB44_2:
Ltmp438:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB44_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp439:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$145, %esi
	leaq	___func__.5295(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB44_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB44_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB44_7:
	callq	___stack_chk_fail
Ltmp440:
Lfunc_end44:
Leh_func_end44:

	.globl	_atomic_or_64
	.align	4, 0x90
_atomic_or_64:
Leh_func_begin45:
Lfunc_begin45:
Ltmp444:
	pushq	%rbp
Ltmp441:
	movq	%rsp, %rbp
Ltmp442:
	subq	$144, %rsp
Ltmp443:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp445:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB45_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp446:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$146, %esi
	leaq	___func__.5322(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp447:
LBB45_2:
Ltmp448:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB45_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp449:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$146, %esi
	leaq	___func__.5322(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB45_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB45_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB45_7:
	callq	___stack_chk_fail
Ltmp450:
Lfunc_end45:
Leh_func_end45:

	.globl	_atomic_and_8
	.align	4, 0x90
_atomic_and_8:
Leh_func_begin46:
Lfunc_begin46:
Ltmp454:
	pushq	%rbp
Ltmp451:
	movq	%rsp, %rbp
Ltmp452:
	subq	$144, %rsp
Ltmp453:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp455:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB46_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp456:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$157, %esi
	leaq	___func__.5349(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp457:
LBB46_2:
Ltmp458:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	andb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB46_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp459:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$157, %esi
	leaq	___func__.5349(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB46_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB46_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB46_7:
	callq	___stack_chk_fail
Ltmp460:
Lfunc_end46:
Leh_func_end46:

	.globl	_atomic_and_uchar
	.align	4, 0x90
_atomic_and_uchar:
Leh_func_begin47:
Lfunc_begin47:
Ltmp464:
	pushq	%rbp
Ltmp461:
	movq	%rsp, %rbp
Ltmp462:
	subq	$144, %rsp
Ltmp463:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp465:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB47_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp466:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$158, %esi
	leaq	___func__.5376(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp467:
LBB47_2:
Ltmp468:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	andb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB47_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp469:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$158, %esi
	leaq	___func__.5376(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB47_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB47_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB47_7:
	callq	___stack_chk_fail
Ltmp470:
Lfunc_end47:
Leh_func_end47:

	.globl	_atomic_and_16
	.align	4, 0x90
_atomic_and_16:
Leh_func_begin48:
Lfunc_begin48:
Ltmp474:
	pushq	%rbp
Ltmp471:
	movq	%rsp, %rbp
Ltmp472:
	subq	$144, %rsp
Ltmp473:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp475:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB48_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp476:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$159, %esi
	leaq	___func__.5403(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp477:
LBB48_2:
Ltmp478:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	andw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB48_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp479:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$159, %esi
	leaq	___func__.5403(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB48_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB48_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB48_7:
	callq	___stack_chk_fail
Ltmp480:
Lfunc_end48:
Leh_func_end48:

	.globl	_atomic_and_ushort
	.align	4, 0x90
_atomic_and_ushort:
Leh_func_begin49:
Lfunc_begin49:
Ltmp484:
	pushq	%rbp
Ltmp481:
	movq	%rsp, %rbp
Ltmp482:
	subq	$144, %rsp
Ltmp483:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp485:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB49_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp486:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$160, %esi
	leaq	___func__.5430(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp487:
LBB49_2:
Ltmp488:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	andw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB49_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp489:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$160, %esi
	leaq	___func__.5430(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB49_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB49_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB49_7:
	callq	___stack_chk_fail
Ltmp490:
Lfunc_end49:
Leh_func_end49:

	.globl	_atomic_and_32
	.align	4, 0x90
_atomic_and_32:
Leh_func_begin50:
Lfunc_begin50:
Ltmp494:
	pushq	%rbp
Ltmp491:
	movq	%rsp, %rbp
Ltmp492:
	subq	$144, %rsp
Ltmp493:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp495:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB50_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp496:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$161, %esi
	leaq	___func__.5457(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp497:
LBB50_2:
Ltmp498:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	andl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB50_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp499:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$161, %esi
	leaq	___func__.5457(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB50_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB50_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB50_7:
	callq	___stack_chk_fail
Ltmp500:
Lfunc_end50:
Leh_func_end50:

	.globl	_atomic_and_uint
	.align	4, 0x90
_atomic_and_uint:
Leh_func_begin51:
Lfunc_begin51:
Ltmp504:
	pushq	%rbp
Ltmp501:
	movq	%rsp, %rbp
Ltmp502:
	subq	$144, %rsp
Ltmp503:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp505:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB51_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp506:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$162, %esi
	leaq	___func__.5484(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp507:
LBB51_2:
Ltmp508:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	andl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB51_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp509:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$162, %esi
	leaq	___func__.5484(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB51_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB51_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB51_7:
	callq	___stack_chk_fail
Ltmp510:
Lfunc_end51:
Leh_func_end51:

	.globl	_atomic_and_ulong
	.align	4, 0x90
_atomic_and_ulong:
Leh_func_begin52:
Lfunc_begin52:
Ltmp514:
	pushq	%rbp
Ltmp511:
	movq	%rsp, %rbp
Ltmp512:
	subq	$144, %rsp
Ltmp513:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp515:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB52_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp516:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$163, %esi
	leaq	___func__.5511(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp517:
LBB52_2:
Ltmp518:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB52_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp519:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$163, %esi
	leaq	___func__.5511(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB52_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB52_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB52_7:
	callq	___stack_chk_fail
Ltmp520:
Lfunc_end52:
Leh_func_end52:

	.globl	_atomic_and_64
	.align	4, 0x90
_atomic_and_64:
Leh_func_begin53:
Lfunc_begin53:
Ltmp524:
	pushq	%rbp
Ltmp521:
	movq	%rsp, %rbp
Ltmp522:
	subq	$144, %rsp
Ltmp523:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp525:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -32(%rbp)
	movq	$0, -40(%rbp)
	movq	-32(%rbp), %rcx
	movq	-40(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB53_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp526:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -48(%rbp)
	movq	-40(%rbp), %rdx
	movq	-32(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -80(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -81(%rbp)
	movq	%rax, %rsi
	movq	-80(%rbp), %rcx
	movb	-81(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-48(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$164, %esi
	leaq	___func__.5538(%rip), %rdi
	movq	%rdi, -96(%rbp)
	movq	%rax, %rdi
	movl	%esi, -100(%rbp)
	movq	%rcx, %rsi
	movl	-100(%rbp), %eax
	movl	%eax, %edx
	movq	-96(%rbp), %rcx
	callq	___assert_c99
Ltmp527:
LBB53_2:
Ltmp528:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB53_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp529:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$164, %esi
	leaq	___func__.5538(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
LBB53_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	-8(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB53_7
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB53_7:
	callq	___stack_chk_fail
Ltmp530:
Lfunc_end53:
Leh_func_end53:

	.globl	_atomic_inc_long_nv
	.align	4, 0x90
_atomic_inc_long_nv:
Leh_func_begin54:
Lfunc_begin54:
Ltmp534:
	pushq	%rbp
Ltmp531:
	movq	%rsp, %rbp
Ltmp532:
	subq	$160, %rsp
Ltmp533:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp535:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB54_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp536:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$181, %esi
	leaq	___func__.5565(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp537:
LBB54_2:
Ltmp538:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB54_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp539:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$181, %esi
	leaq	___func__.5565(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp540:
LBB54_4:
Ltmp541:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB54_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB54_7:
	callq	___stack_chk_fail
Ltmp542:
Lfunc_end54:
Leh_func_end54:

	.globl	_atomic_inc_8_nv
	.align	4, 0x90
_atomic_inc_8_nv:
Leh_func_begin55:
Lfunc_begin55:
Ltmp546:
	pushq	%rbp
Ltmp543:
	movq	%rsp, %rbp
Ltmp544:
	subq	$144, %rsp
Ltmp545:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp547:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB55_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp548:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$182, %esi
	leaq	___func__.5594(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp549:
LBB55_2:
Ltmp550:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	addb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -25(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB55_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp551:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$182, %esi
	leaq	___func__.5594(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp552:
LBB55_4:
Ltmp553:
	movb	-25(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB55_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB55_7:
	callq	___stack_chk_fail
Ltmp554:
Lfunc_end55:
Leh_func_end55:

	.globl	_atomic_inc_uchar_nv
	.align	4, 0x90
_atomic_inc_uchar_nv:
Leh_func_begin56:
Lfunc_begin56:
Ltmp558:
	pushq	%rbp
Ltmp555:
	movq	%rsp, %rbp
Ltmp556:
	subq	$144, %rsp
Ltmp557:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp559:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB56_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp560:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$183, %esi
	leaq	___func__.5623(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp561:
LBB56_2:
Ltmp562:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	addb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -25(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB56_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp563:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$183, %esi
	leaq	___func__.5623(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp564:
LBB56_4:
Ltmp565:
	movb	-25(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB56_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB56_7:
	callq	___stack_chk_fail
Ltmp566:
Lfunc_end56:
Leh_func_end56:

	.globl	_atomic_inc_16_nv
	.align	4, 0x90
_atomic_inc_16_nv:
Leh_func_begin57:
Lfunc_begin57:
Ltmp570:
	pushq	%rbp
Ltmp567:
	movq	%rsp, %rbp
Ltmp568:
	subq	$144, %rsp
Ltmp569:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp571:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB57_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp572:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$184, %esi
	leaq	___func__.5652(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp573:
LBB57_2:
Ltmp574:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	addw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -26(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB57_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp575:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$184, %esi
	leaq	___func__.5652(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp576:
LBB57_4:
Ltmp577:
	movw	-26(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB57_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB57_7:
	callq	___stack_chk_fail
Ltmp578:
Lfunc_end57:
Leh_func_end57:

	.globl	_atomic_inc_ushort_nv
	.align	4, 0x90
_atomic_inc_ushort_nv:
Leh_func_begin58:
Lfunc_begin58:
Ltmp582:
	pushq	%rbp
Ltmp579:
	movq	%rsp, %rbp
Ltmp580:
	subq	$144, %rsp
Ltmp581:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp583:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB58_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp584:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$185, %esi
	leaq	___func__.5681(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp585:
LBB58_2:
Ltmp586:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	addw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -26(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB58_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp587:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$185, %esi
	leaq	___func__.5681(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp588:
LBB58_4:
Ltmp589:
	movw	-26(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB58_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB58_7:
	callq	___stack_chk_fail
Ltmp590:
Lfunc_end58:
Leh_func_end58:

	.globl	_atomic_inc_32_nv
	.align	4, 0x90
_atomic_inc_32_nv:
Leh_func_begin59:
Lfunc_begin59:
Ltmp594:
	pushq	%rbp
Ltmp591:
	movq	%rsp, %rbp
Ltmp592:
	subq	$144, %rsp
Ltmp593:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp595:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB59_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp596:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$186, %esi
	leaq	___func__.5710(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp597:
LBB59_2:
Ltmp598:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	addl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -28(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB59_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp599:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$186, %esi
	leaq	___func__.5710(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp600:
LBB59_4:
Ltmp601:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB59_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB59_7:
	callq	___stack_chk_fail
Ltmp602:
Lfunc_end59:
Leh_func_end59:

	.globl	_atomic_inc_uint_nv
	.align	4, 0x90
_atomic_inc_uint_nv:
Leh_func_begin60:
Lfunc_begin60:
Ltmp606:
	pushq	%rbp
Ltmp603:
	movq	%rsp, %rbp
Ltmp604:
	subq	$144, %rsp
Ltmp605:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp607:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB60_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp608:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$187, %esi
	leaq	___func__.5739(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp609:
LBB60_2:
Ltmp610:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	addl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -28(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB60_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp611:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$187, %esi
	leaq	___func__.5739(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp612:
LBB60_4:
Ltmp613:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB60_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB60_7:
	callq	___stack_chk_fail
Ltmp614:
Lfunc_end60:
Leh_func_end60:

	.globl	_atomic_inc_ulong_nv
	.align	4, 0x90
_atomic_inc_ulong_nv:
Leh_func_begin61:
Lfunc_begin61:
Ltmp618:
	pushq	%rbp
Ltmp615:
	movq	%rsp, %rbp
Ltmp616:
	subq	$160, %rsp
Ltmp617:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp619:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB61_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp620:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$188, %esi
	leaq	___func__.5768(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp621:
LBB61_2:
Ltmp622:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB61_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp623:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$188, %esi
	leaq	___func__.5768(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp624:
LBB61_4:
Ltmp625:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB61_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB61_7:
	callq	___stack_chk_fail
Ltmp626:
Lfunc_end61:
Leh_func_end61:

	.globl	_atomic_inc_64_nv
	.align	4, 0x90
_atomic_inc_64_nv:
Leh_func_begin62:
Lfunc_begin62:
Ltmp630:
	pushq	%rbp
Ltmp627:
	movq	%rsp, %rbp
Ltmp628:
	subq	$160, %rsp
Ltmp629:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp631:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB62_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp632:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$189, %esi
	leaq	___func__.5797(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp633:
LBB62_2:
Ltmp634:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB62_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp635:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$189, %esi
	leaq	___func__.5797(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp636:
LBB62_4:
Ltmp637:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB62_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB62_7:
	callq	___stack_chk_fail
Ltmp638:
Lfunc_end62:
Leh_func_end62:

	.globl	_atomic_dec_long_nv
	.align	4, 0x90
_atomic_dec_long_nv:
Leh_func_begin63:
Lfunc_begin63:
Ltmp642:
	pushq	%rbp
Ltmp639:
	movq	%rsp, %rbp
Ltmp640:
	subq	$160, %rsp
Ltmp641:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp643:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB63_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp644:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$202, %esi
	leaq	___func__.5826(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp645:
LBB63_2:
Ltmp646:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB63_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp647:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$202, %esi
	leaq	___func__.5826(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp648:
LBB63_4:
Ltmp649:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB63_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB63_7:
	callq	___stack_chk_fail
Ltmp650:
Lfunc_end63:
Leh_func_end63:

	.globl	_atomic_dec_8_nv
	.align	4, 0x90
_atomic_dec_8_nv:
Leh_func_begin64:
Lfunc_begin64:
Ltmp654:
	pushq	%rbp
Ltmp651:
	movq	%rsp, %rbp
Ltmp652:
	subq	$144, %rsp
Ltmp653:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp655:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB64_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp656:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$203, %esi
	leaq	___func__.5855(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp657:
LBB64_2:
Ltmp658:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	subb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -25(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB64_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp659:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$203, %esi
	leaq	___func__.5855(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp660:
LBB64_4:
Ltmp661:
	movb	-25(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB64_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB64_7:
	callq	___stack_chk_fail
Ltmp662:
Lfunc_end64:
Leh_func_end64:

	.globl	_atomic_dec_uchar_nv
	.align	4, 0x90
_atomic_dec_uchar_nv:
Leh_func_begin65:
Lfunc_begin65:
Ltmp666:
	pushq	%rbp
Ltmp663:
	movq	%rsp, %rbp
Ltmp664:
	subq	$144, %rsp
Ltmp665:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp667:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB65_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp668:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$204, %esi
	leaq	___func__.5884(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp669:
LBB65_2:
Ltmp670:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	subb	$1, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -25(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB65_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp671:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$204, %esi
	leaq	___func__.5884(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp672:
LBB65_4:
Ltmp673:
	movb	-25(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB65_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB65_7:
	callq	___stack_chk_fail
Ltmp674:
Lfunc_end65:
Leh_func_end65:

	.globl	_atomic_dec_16_nv
	.align	4, 0x90
_atomic_dec_16_nv:
Leh_func_begin66:
Lfunc_begin66:
Ltmp678:
	pushq	%rbp
Ltmp675:
	movq	%rsp, %rbp
Ltmp676:
	subq	$144, %rsp
Ltmp677:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp679:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB66_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp680:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$205, %esi
	leaq	___func__.5913(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp681:
LBB66_2:
Ltmp682:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	subw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -26(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB66_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp683:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$205, %esi
	leaq	___func__.5913(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp684:
LBB66_4:
Ltmp685:
	movw	-26(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB66_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB66_7:
	callq	___stack_chk_fail
Ltmp686:
Lfunc_end66:
Leh_func_end66:

	.globl	_atomic_dec_ushort_nv
	.align	4, 0x90
_atomic_dec_ushort_nv:
Leh_func_begin67:
Lfunc_begin67:
Ltmp690:
	pushq	%rbp
Ltmp687:
	movq	%rsp, %rbp
Ltmp688:
	subq	$144, %rsp
Ltmp689:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp691:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB67_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp692:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$206, %esi
	leaq	___func__.5942(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp693:
LBB67_2:
Ltmp694:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	subw	$1, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -26(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB67_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp695:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$206, %esi
	leaq	___func__.5942(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp696:
LBB67_4:
Ltmp697:
	movw	-26(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB67_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB67_7:
	callq	___stack_chk_fail
Ltmp698:
Lfunc_end67:
Leh_func_end67:

	.globl	_atomic_dec_32_nv
	.align	4, 0x90
_atomic_dec_32_nv:
Leh_func_begin68:
Lfunc_begin68:
Ltmp702:
	pushq	%rbp
Ltmp699:
	movq	%rsp, %rbp
Ltmp700:
	subq	$144, %rsp
Ltmp701:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp703:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB68_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp704:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$207, %esi
	leaq	___func__.5971(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp705:
LBB68_2:
Ltmp706:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	subl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -28(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB68_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp707:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$207, %esi
	leaq	___func__.5971(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp708:
LBB68_4:
Ltmp709:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB68_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB68_7:
	callq	___stack_chk_fail
Ltmp710:
Lfunc_end68:
Leh_func_end68:

	.globl	_atomic_dec_uint_nv
	.align	4, 0x90
_atomic_dec_uint_nv:
Leh_func_begin69:
Lfunc_begin69:
Ltmp714:
	pushq	%rbp
Ltmp711:
	movq	%rsp, %rbp
Ltmp712:
	subq	$144, %rsp
Ltmp713:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp715:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB69_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp716:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$208, %esi
	leaq	___func__.6000(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp717:
LBB69_2:
Ltmp718:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	subl	$1, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -28(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB69_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp719:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$208, %esi
	leaq	___func__.6000(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp720:
LBB69_4:
Ltmp721:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movl	%eax, -20(%rbp)
	movl	-20(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB69_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB69_7:
	callq	___stack_chk_fail
Ltmp722:
Lfunc_end69:
Leh_func_end69:

	.globl	_atomic_dec_ulong_nv
	.align	4, 0x90
_atomic_dec_ulong_nv:
Leh_func_begin70:
Lfunc_begin70:
Ltmp726:
	pushq	%rbp
Ltmp723:
	movq	%rsp, %rbp
Ltmp724:
	subq	$160, %rsp
Ltmp725:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp727:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB70_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp728:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$209, %esi
	leaq	___func__.6029(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp729:
LBB70_2:
Ltmp730:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB70_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp731:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$209, %esi
	leaq	___func__.6029(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp732:
LBB70_4:
Ltmp733:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB70_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB70_7:
	callq	___stack_chk_fail
Ltmp734:
Lfunc_end70:
Leh_func_end70:

	.globl	_atomic_dec_64_nv
	.align	4, 0x90
_atomic_dec_64_nv:
Leh_func_begin71:
Lfunc_begin71:
Ltmp738:
	pushq	%rbp
Ltmp735:
	movq	%rsp, %rbp
Ltmp736:
	subq	$160, %rsp
Ltmp737:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
Ltmp739:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB71_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp740:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$210, %esi
	leaq	___func__.6058(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp741:
LBB71_2:
Ltmp742:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movabsq	$1, %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB71_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp743:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$210, %esi
	leaq	___func__.6058(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp744:
LBB71_4:
Ltmp745:
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	%rax, -24(%rbp)
	movq	-24(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -160(%rbp)
	jne	LBB71_7
	movq	-160(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB71_7:
	callq	___stack_chk_fail
Ltmp746:
Lfunc_end71:
Leh_func_end71:

	.globl	_atomic_add_8_nv
	.align	4, 0x90
_atomic_add_8_nv:
Leh_func_begin72:
Lfunc_begin72:
Ltmp750:
	pushq	%rbp
Ltmp747:
	movq	%rsp, %rbp
Ltmp748:
	subq	$144, %rsp
Ltmp749:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp751:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB72_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp752:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$223, %esi
	leaq	___func__.6088(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp753:
LBB72_2:
Ltmp754:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	addb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB72_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp755:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$223, %esi
	leaq	___func__.6088(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp756:
LBB72_4:
Ltmp757:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB72_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB72_7:
	callq	___stack_chk_fail
Ltmp758:
Lfunc_end72:
Leh_func_end72:

	.globl	_atomic_add_char_nv
	.align	4, 0x90
_atomic_add_char_nv:
Leh_func_begin73:
Lfunc_begin73:
Ltmp762:
	pushq	%rbp
Ltmp759:
	movq	%rsp, %rbp
Ltmp760:
	subq	$144, %rsp
Ltmp761:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp763:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB73_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp764:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$224, %esi
	leaq	___func__.6119(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp765:
LBB73_2:
Ltmp766:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	addb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB73_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp767:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$224, %esi
	leaq	___func__.6119(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp768:
LBB73_4:
Ltmp769:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB73_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB73_7:
	callq	___stack_chk_fail
Ltmp770:
Lfunc_end73:
Leh_func_end73:

	.globl	_atomic_add_16_nv
	.align	4, 0x90
_atomic_add_16_nv:
Leh_func_begin74:
Lfunc_begin74:
Ltmp774:
	pushq	%rbp
Ltmp771:
	movq	%rsp, %rbp
Ltmp772:
	subq	$144, %rsp
Ltmp773:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp775:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB74_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp776:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$225, %esi
	leaq	___func__.6150(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp777:
LBB74_2:
Ltmp778:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	addw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB74_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp779:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$225, %esi
	leaq	___func__.6150(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp780:
LBB74_4:
Ltmp781:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB74_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB74_7:
	callq	___stack_chk_fail
Ltmp782:
Lfunc_end74:
Leh_func_end74:

	.globl	_atomic_add_short_nv
	.align	4, 0x90
_atomic_add_short_nv:
Leh_func_begin75:
Lfunc_begin75:
Ltmp786:
	pushq	%rbp
Ltmp783:
	movq	%rsp, %rbp
Ltmp784:
	subq	$144, %rsp
Ltmp785:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp787:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB75_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp788:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$226, %esi
	leaq	___func__.6181(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp789:
LBB75_2:
Ltmp790:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	addw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB75_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp791:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$226, %esi
	leaq	___func__.6181(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp792:
LBB75_4:
Ltmp793:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB75_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB75_7:
	callq	___stack_chk_fail
Ltmp794:
Lfunc_end75:
Leh_func_end75:

	.globl	_atomic_add_32_nv
	.align	4, 0x90
_atomic_add_32_nv:
Leh_func_begin76:
Lfunc_begin76:
Ltmp798:
	pushq	%rbp
Ltmp795:
	movq	%rsp, %rbp
Ltmp796:
	subq	$144, %rsp
Ltmp797:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp799:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB76_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp800:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$227, %esi
	leaq	___func__.6212(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp801:
LBB76_2:
Ltmp802:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	addl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB76_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp803:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$227, %esi
	leaq	___func__.6212(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp804:
LBB76_4:
Ltmp805:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB76_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB76_7:
	callq	___stack_chk_fail
Ltmp806:
Lfunc_end76:
Leh_func_end76:

	.globl	_atomic_add_int_nv
	.align	4, 0x90
_atomic_add_int_nv:
Leh_func_begin77:
Lfunc_begin77:
Ltmp810:
	pushq	%rbp
Ltmp807:
	movq	%rsp, %rbp
Ltmp808:
	subq	$144, %rsp
Ltmp809:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp811:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB77_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp812:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$228, %esi
	leaq	___func__.6243(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp813:
LBB77_2:
Ltmp814:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	addl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB77_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp815:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$228, %esi
	leaq	___func__.6243(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp816:
LBB77_4:
Ltmp817:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB77_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB77_7:
	callq	___stack_chk_fail
Ltmp818:
Lfunc_end77:
Leh_func_end77:

	.globl	_atomic_add_long_nv
	.align	4, 0x90
_atomic_add_long_nv:
Leh_func_begin78:
Lfunc_begin78:
Ltmp822:
	pushq	%rbp
Ltmp819:
	movq	%rsp, %rbp
Ltmp820:
	subq	$176, %rsp
Ltmp821:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp823:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB78_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp824:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$229, %esi
	leaq	___func__.6274(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp825:
LBB78_2:
Ltmp826:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB78_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp827:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$229, %esi
	leaq	___func__.6274(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp828:
LBB78_4:
Ltmp829:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB78_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB78_7:
	callq	___stack_chk_fail
Ltmp830:
Lfunc_end78:
Leh_func_end78:

	.globl	_atomic_add_64_nv
	.align	4, 0x90
_atomic_add_64_nv:
Leh_func_begin79:
Lfunc_begin79:
Ltmp834:
	pushq	%rbp
Ltmp831:
	movq	%rsp, %rbp
Ltmp832:
	subq	$176, %rsp
Ltmp833:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp835:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB79_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp836:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$230, %esi
	leaq	___func__.6305(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp837:
LBB79_2:
Ltmp838:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	addq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB79_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp839:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$230, %esi
	leaq	___func__.6305(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp840:
LBB79_4:
Ltmp841:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB79_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB79_7:
	callq	___stack_chk_fail
Ltmp842:
Lfunc_end79:
Leh_func_end79:

	.globl	_atomic_add_ptr_nv
	.align	4, 0x90
_atomic_add_ptr_nv:
Leh_func_begin80:
Lfunc_begin80:
Ltmp846:
	pushq	%rbp
Ltmp843:
	movq	%rsp, %rbp
Ltmp844:
	subq	$176, %rsp
Ltmp845:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp847:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB80_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp848:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$236, %esi
	leaq	___func__.6336(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp849:
LBB80_2:
Ltmp850:
	movq	-16(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-24(%rbp), %rdx
	addq	%rdx, %rcx
	movq	%rcx, (%rax)
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
Ltmp851:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB80_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp852:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$238, %esi
	leaq	___func__.6336(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp853:
LBB80_4:
Ltmp854:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB80_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB80_7:
	callq	___stack_chk_fail
Ltmp855:
Lfunc_end80:
Leh_func_end80:

	.globl	_atomic_sub_8_nv
	.align	4, 0x90
_atomic_sub_8_nv:
Leh_func_begin81:
Lfunc_begin81:
Ltmp859:
	pushq	%rbp
Ltmp856:
	movq	%rsp, %rbp
Ltmp857:
	subq	$144, %rsp
Ltmp858:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp860:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB81_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp861:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$254, %esi
	leaq	___func__.6368(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp862:
LBB81_2:
Ltmp863:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	subb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB81_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp864:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$254, %esi
	leaq	___func__.6368(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp865:
LBB81_4:
Ltmp866:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB81_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB81_7:
	callq	___stack_chk_fail
Ltmp867:
Lfunc_end81:
Leh_func_end81:

	.globl	_atomic_sub_char_nv
	.align	4, 0x90
_atomic_sub_char_nv:
Leh_func_begin82:
Lfunc_begin82:
Ltmp871:
	pushq	%rbp
Ltmp868:
	movq	%rsp, %rbp
Ltmp869:
	subq	$144, %rsp
Ltmp870:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp872:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB82_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp873:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$255, %esi
	leaq	___func__.6399(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp874:
LBB82_2:
Ltmp875:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	subb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB82_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp876:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$255, %esi
	leaq	___func__.6399(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp877:
LBB82_4:
Ltmp878:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB82_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB82_7:
	callq	___stack_chk_fail
Ltmp879:
Lfunc_end82:
Leh_func_end82:

	.globl	_atomic_sub_16_nv
	.align	4, 0x90
_atomic_sub_16_nv:
Leh_func_begin83:
Lfunc_begin83:
Ltmp883:
	pushq	%rbp
Ltmp880:
	movq	%rsp, %rbp
Ltmp881:
	subq	$144, %rsp
Ltmp882:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp884:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB83_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp885:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$256, %esi
	leaq	___func__.6430(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp886:
LBB83_2:
Ltmp887:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	subw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB83_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp888:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$256, %esi
	leaq	___func__.6430(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp889:
LBB83_4:
Ltmp890:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB83_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB83_7:
	callq	___stack_chk_fail
Ltmp891:
Lfunc_end83:
Leh_func_end83:

	.globl	_atomic_sub_short_nv
	.align	4, 0x90
_atomic_sub_short_nv:
Leh_func_begin84:
Lfunc_begin84:
Ltmp895:
	pushq	%rbp
Ltmp892:
	movq	%rsp, %rbp
Ltmp893:
	subq	$144, %rsp
Ltmp894:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp896:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB84_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp897:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$257, %esi
	leaq	___func__.6461(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp898:
LBB84_2:
Ltmp899:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	subw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB84_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp900:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$257, %esi
	leaq	___func__.6461(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp901:
LBB84_4:
Ltmp902:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB84_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB84_7:
	callq	___stack_chk_fail
Ltmp903:
Lfunc_end84:
Leh_func_end84:

	.globl	_atomic_sub_32_nv
	.align	4, 0x90
_atomic_sub_32_nv:
Leh_func_begin85:
Lfunc_begin85:
Ltmp907:
	pushq	%rbp
Ltmp904:
	movq	%rsp, %rbp
Ltmp905:
	subq	$144, %rsp
Ltmp906:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp908:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB85_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp909:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$258, %esi
	leaq	___func__.6492(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp910:
LBB85_2:
Ltmp911:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	subl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB85_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp912:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$258, %esi
	leaq	___func__.6492(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp913:
LBB85_4:
Ltmp914:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB85_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB85_7:
	callq	___stack_chk_fail
Ltmp915:
Lfunc_end85:
Leh_func_end85:

	.globl	_atomic_sub_int_nv
	.align	4, 0x90
_atomic_sub_int_nv:
Leh_func_begin86:
Lfunc_begin86:
Ltmp919:
	pushq	%rbp
Ltmp916:
	movq	%rsp, %rbp
Ltmp917:
	subq	$144, %rsp
Ltmp918:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp920:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB86_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp921:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$259, %esi
	leaq	___func__.6523(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp922:
LBB86_2:
Ltmp923:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	subl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB86_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp924:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$259, %esi
	leaq	___func__.6523(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp925:
LBB86_4:
Ltmp926:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB86_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB86_7:
	callq	___stack_chk_fail
Ltmp927:
Lfunc_end86:
Leh_func_end86:

	.globl	_atomic_sub_long_nv
	.align	4, 0x90
_atomic_sub_long_nv:
Leh_func_begin87:
Lfunc_begin87:
Ltmp931:
	pushq	%rbp
Ltmp928:
	movq	%rsp, %rbp
Ltmp929:
	subq	$176, %rsp
Ltmp930:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp932:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB87_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp933:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$260, %esi
	leaq	___func__.6554(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp934:
LBB87_2:
Ltmp935:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB87_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp936:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$260, %esi
	leaq	___func__.6554(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp937:
LBB87_4:
Ltmp938:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB87_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB87_7:
	callq	___stack_chk_fail
Ltmp939:
Lfunc_end87:
Leh_func_end87:

	.globl	_atomic_sub_64_nv
	.align	4, 0x90
_atomic_sub_64_nv:
Leh_func_begin88:
Lfunc_begin88:
Ltmp943:
	pushq	%rbp
Ltmp940:
	movq	%rsp, %rbp
Ltmp941:
	subq	$176, %rsp
Ltmp942:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp944:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB88_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp945:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$261, %esi
	leaq	___func__.6585(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp946:
LBB88_2:
Ltmp947:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	subq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB88_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp948:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$261, %esi
	leaq	___func__.6585(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp949:
LBB88_4:
Ltmp950:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB88_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB88_7:
	callq	___stack_chk_fail
Ltmp951:
Lfunc_end88:
Leh_func_end88:

	.globl	_atomic_sub_ptr_nv
	.align	4, 0x90
_atomic_sub_ptr_nv:
Leh_func_begin89:
Lfunc_begin89:
Ltmp955:
	pushq	%rbp
Ltmp952:
	movq	%rsp, %rbp
Ltmp953:
	subq	$176, %rsp
Ltmp954:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp956:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB89_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp957:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$267, %esi
	leaq	___func__.6616(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp958:
LBB89_2:
Ltmp959:
	movq	-16(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	(%rcx), %rcx
	movq	-24(%rbp), %rdx
	movabsq	$0, %rsi
	subq	%rdx, %rsi
	addq	%rsi, %rcx
	movq	%rcx, (%rax)
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
Ltmp960:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB89_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp961:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$269, %esi
	leaq	___func__.6616(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp962:
LBB89_4:
Ltmp963:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB89_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB89_7:
	callq	___stack_chk_fail
Ltmp964:
Lfunc_end89:
Leh_func_end89:

	.globl	_atomic_or_long_nv
	.align	4, 0x90
_atomic_or_long_nv:
Leh_func_begin90:
Lfunc_begin90:
Ltmp968:
	pushq	%rbp
Ltmp965:
	movq	%rsp, %rbp
Ltmp966:
	subq	$176, %rsp
Ltmp967:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp969:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB90_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp970:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$285, %esi
	leaq	___func__.6649(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp971:
LBB90_2:
Ltmp972:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB90_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp973:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$285, %esi
	leaq	___func__.6649(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp974:
LBB90_4:
Ltmp975:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB90_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB90_7:
	callq	___stack_chk_fail
Ltmp976:
Lfunc_end90:
Leh_func_end90:

	.globl	_atomic_or_8_nv
	.align	4, 0x90
_atomic_or_8_nv:
Leh_func_begin91:
Lfunc_begin91:
Ltmp980:
	pushq	%rbp
Ltmp977:
	movq	%rsp, %rbp
Ltmp978:
	subq	$144, %rsp
Ltmp979:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp981:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB91_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp982:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$286, %esi
	leaq	___func__.6679(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp983:
LBB91_2:
Ltmp984:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	orb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB91_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp985:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$286, %esi
	leaq	___func__.6679(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp986:
LBB91_4:
Ltmp987:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB91_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB91_7:
	callq	___stack_chk_fail
Ltmp988:
Lfunc_end91:
Leh_func_end91:

	.globl	_atomic_or_uchar_nv
	.align	4, 0x90
_atomic_or_uchar_nv:
Leh_func_begin92:
Lfunc_begin92:
Ltmp992:
	pushq	%rbp
Ltmp989:
	movq	%rsp, %rbp
Ltmp990:
	subq	$144, %rsp
Ltmp991:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp993:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB92_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp994:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$287, %esi
	leaq	___func__.6709(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp995:
LBB92_2:
Ltmp996:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	orb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB92_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp997:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$287, %esi
	leaq	___func__.6709(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp998:
LBB92_4:
Ltmp999:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB92_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB92_7:
	callq	___stack_chk_fail
Ltmp1000:
Lfunc_end92:
Leh_func_end92:

	.globl	_atomic_or_16_nv
	.align	4, 0x90
_atomic_or_16_nv:
Leh_func_begin93:
Lfunc_begin93:
Ltmp1004:
	pushq	%rbp
Ltmp1001:
	movq	%rsp, %rbp
Ltmp1002:
	subq	$144, %rsp
Ltmp1003:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1005:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB93_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1006:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$288, %esi
	leaq	___func__.6739(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1007:
LBB93_2:
Ltmp1008:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	orw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB93_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1009:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$288, %esi
	leaq	___func__.6739(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1010:
LBB93_4:
Ltmp1011:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB93_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB93_7:
	callq	___stack_chk_fail
Ltmp1012:
Lfunc_end93:
Leh_func_end93:

	.globl	_atomic_or_ushort_nv
	.align	4, 0x90
_atomic_or_ushort_nv:
Leh_func_begin94:
Lfunc_begin94:
Ltmp1016:
	pushq	%rbp
Ltmp1013:
	movq	%rsp, %rbp
Ltmp1014:
	subq	$144, %rsp
Ltmp1015:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1017:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB94_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1018:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$289, %esi
	leaq	___func__.6769(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1019:
LBB94_2:
Ltmp1020:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	orw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB94_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1021:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$289, %esi
	leaq	___func__.6769(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1022:
LBB94_4:
Ltmp1023:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB94_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB94_7:
	callq	___stack_chk_fail
Ltmp1024:
Lfunc_end94:
Leh_func_end94:

	.globl	_atomic_or_32_nv
	.align	4, 0x90
_atomic_or_32_nv:
Leh_func_begin95:
Lfunc_begin95:
Ltmp1028:
	pushq	%rbp
Ltmp1025:
	movq	%rsp, %rbp
Ltmp1026:
	subq	$144, %rsp
Ltmp1027:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1029:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB95_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1030:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$290, %esi
	leaq	___func__.6799(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1031:
LBB95_2:
Ltmp1032:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	orl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB95_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1033:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$290, %esi
	leaq	___func__.6799(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1034:
LBB95_4:
Ltmp1035:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB95_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB95_7:
	callq	___stack_chk_fail
Ltmp1036:
Lfunc_end95:
Leh_func_end95:

	.globl	_atomic_or_uint_nv
	.align	4, 0x90
_atomic_or_uint_nv:
Leh_func_begin96:
Lfunc_begin96:
Ltmp1040:
	pushq	%rbp
Ltmp1037:
	movq	%rsp, %rbp
Ltmp1038:
	subq	$144, %rsp
Ltmp1039:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1041:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB96_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1042:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$291, %esi
	leaq	___func__.6829(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1043:
LBB96_2:
Ltmp1044:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	orl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB96_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1045:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$291, %esi
	leaq	___func__.6829(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1046:
LBB96_4:
Ltmp1047:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB96_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB96_7:
	callq	___stack_chk_fail
Ltmp1048:
Lfunc_end96:
Leh_func_end96:

	.globl	_atomic_or_ulong_nv
	.align	4, 0x90
_atomic_or_ulong_nv:
Leh_func_begin97:
Lfunc_begin97:
Ltmp1052:
	pushq	%rbp
Ltmp1049:
	movq	%rsp, %rbp
Ltmp1050:
	subq	$176, %rsp
Ltmp1051:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1053:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB97_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1054:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$292, %esi
	leaq	___func__.6859(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1055:
LBB97_2:
Ltmp1056:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB97_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1057:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$292, %esi
	leaq	___func__.6859(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1058:
LBB97_4:
Ltmp1059:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB97_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB97_7:
	callq	___stack_chk_fail
Ltmp1060:
Lfunc_end97:
Leh_func_end97:

	.globl	_atomic_or_64_nv
	.align	4, 0x90
_atomic_or_64_nv:
Leh_func_begin98:
Lfunc_begin98:
Ltmp1064:
	pushq	%rbp
Ltmp1061:
	movq	%rsp, %rbp
Ltmp1062:
	subq	$176, %rsp
Ltmp1063:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1065:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB98_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1066:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$293, %esi
	leaq	___func__.6889(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1067:
LBB98_2:
Ltmp1068:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB98_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1069:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$293, %esi
	leaq	___func__.6889(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1070:
LBB98_4:
Ltmp1071:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB98_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB98_7:
	callq	___stack_chk_fail
Ltmp1072:
Lfunc_end98:
Leh_func_end98:

	.globl	_atomic_and_long_nv
	.align	4, 0x90
_atomic_and_long_nv:
Leh_func_begin99:
Lfunc_begin99:
Ltmp1076:
	pushq	%rbp
Ltmp1073:
	movq	%rsp, %rbp
Ltmp1074:
	subq	$176, %rsp
Ltmp1075:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1077:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB99_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1078:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$306, %esi
	leaq	___func__.6919(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1079:
LBB99_2:
Ltmp1080:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB99_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1081:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$306, %esi
	leaq	___func__.6919(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1082:
LBB99_4:
Ltmp1083:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB99_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB99_7:
	callq	___stack_chk_fail
Ltmp1084:
Lfunc_end99:
Leh_func_end99:

	.globl	_atomic_and_8_nv
	.align	4, 0x90
_atomic_and_8_nv:
Leh_func_begin100:
Lfunc_begin100:
Ltmp1088:
	pushq	%rbp
Ltmp1085:
	movq	%rsp, %rbp
Ltmp1086:
	subq	$144, %rsp
Ltmp1087:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp1089:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB100_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1090:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$307, %esi
	leaq	___func__.6949(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1091:
LBB100_2:
Ltmp1092:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	andb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB100_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1093:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$307, %esi
	leaq	___func__.6949(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1094:
LBB100_4:
Ltmp1095:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB100_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB100_7:
	callq	___stack_chk_fail
Ltmp1096:
Lfunc_end100:
Leh_func_end100:

	.globl	_atomic_and_uchar_nv
	.align	4, 0x90
_atomic_and_uchar_nv:
Leh_func_begin101:
Lfunc_begin101:
Ltmp1100:
	pushq	%rbp
Ltmp1097:
	movq	%rsp, %rbp
Ltmp1098:
	subq	$144, %rsp
Ltmp1099:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp1101:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB101_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1102:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$308, %esi
	leaq	___func__.6979(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1103:
LBB101_2:
Ltmp1104:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	-17(%rbp), %cl
	andb	%cl, %al
	movq	-16(%rbp), %rcx
	movb	%al, (%rcx)
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB101_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1105:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$308, %esi
	leaq	___func__.6979(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1106:
LBB101_4:
Ltmp1107:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB101_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB101_7:
	callq	___stack_chk_fail
Ltmp1108:
Lfunc_end101:
Leh_func_end101:

	.globl	_atomic_and_16_nv
	.align	4, 0x90
_atomic_and_16_nv:
Leh_func_begin102:
Lfunc_begin102:
Ltmp1112:
	pushq	%rbp
Ltmp1109:
	movq	%rsp, %rbp
Ltmp1110:
	subq	$144, %rsp
Ltmp1111:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1113:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB102_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1114:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$309, %esi
	leaq	___func__.7009(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1115:
LBB102_2:
Ltmp1116:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	andw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB102_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1117:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$309, %esi
	leaq	___func__.7009(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1118:
LBB102_4:
Ltmp1119:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB102_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB102_7:
	callq	___stack_chk_fail
Ltmp1120:
Lfunc_end102:
Leh_func_end102:

	.globl	_atomic_and_ushort_nv
	.align	4, 0x90
_atomic_and_ushort_nv:
Leh_func_begin103:
Lfunc_begin103:
Ltmp1124:
	pushq	%rbp
Ltmp1121:
	movq	%rsp, %rbp
Ltmp1122:
	subq	$144, %rsp
Ltmp1123:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1125:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB103_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1126:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$310, %esi
	leaq	___func__.7039(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1127:
LBB103_2:
Ltmp1128:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	-18(%rbp), %cx
	andw	%cx, %ax
	movq	-16(%rbp), %rcx
	movw	%ax, (%rcx)
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB103_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1129:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$310, %esi
	leaq	___func__.7039(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1130:
LBB103_4:
Ltmp1131:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB103_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB103_7:
	callq	___stack_chk_fail
Ltmp1132:
Lfunc_end103:
Leh_func_end103:

	.globl	_atomic_and_32_nv
	.align	4, 0x90
_atomic_and_32_nv:
Leh_func_begin104:
Lfunc_begin104:
Ltmp1136:
	pushq	%rbp
Ltmp1133:
	movq	%rsp, %rbp
Ltmp1134:
	subq	$144, %rsp
Ltmp1135:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1137:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB104_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1138:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$311, %esi
	leaq	___func__.7069(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1139:
LBB104_2:
Ltmp1140:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	andl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB104_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1141:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$311, %esi
	leaq	___func__.7069(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1142:
LBB104_4:
Ltmp1143:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB104_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB104_7:
	callq	___stack_chk_fail
Ltmp1144:
Lfunc_end104:
Leh_func_end104:

	.globl	_atomic_and_uint_nv
	.align	4, 0x90
_atomic_and_uint_nv:
Leh_func_begin105:
Lfunc_begin105:
Ltmp1148:
	pushq	%rbp
Ltmp1145:
	movq	%rsp, %rbp
Ltmp1146:
	subq	$144, %rsp
Ltmp1147:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1149:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB105_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1150:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$312, %esi
	leaq	___func__.7099(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1151:
LBB105_2:
Ltmp1152:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	-20(%rbp), %ecx
	andl	%ecx, %eax
	movq	-16(%rbp), %rcx
	movl	%eax, (%rcx)
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB105_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1153:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$312, %esi
	leaq	___func__.7099(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1154:
LBB105_4:
Ltmp1155:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB105_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB105_7:
	callq	___stack_chk_fail
Ltmp1156:
Lfunc_end105:
Leh_func_end105:

	.globl	_atomic_and_ulong_nv
	.align	4, 0x90
_atomic_and_ulong_nv:
Leh_func_begin106:
Lfunc_begin106:
Ltmp1160:
	pushq	%rbp
Ltmp1157:
	movq	%rsp, %rbp
Ltmp1158:
	subq	$176, %rsp
Ltmp1159:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1161:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB106_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1162:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$313, %esi
	leaq	___func__.7129(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1163:
LBB106_2:
Ltmp1164:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB106_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1165:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$313, %esi
	leaq	___func__.7129(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1166:
LBB106_4:
Ltmp1167:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB106_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB106_7:
	callq	___stack_chk_fail
Ltmp1168:
Lfunc_end106:
Leh_func_end106:

	.globl	_atomic_and_64_nv
	.align	4, 0x90
_atomic_and_64_nv:
Leh_func_begin107:
Lfunc_begin107:
Ltmp1172:
	pushq	%rbp
Ltmp1169:
	movq	%rsp, %rbp
Ltmp1170:
	subq	$176, %rsp
Ltmp1171:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1173:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB107_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1174:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$314, %esi
	leaq	___func__.7159(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1175:
LBB107_2:
Ltmp1176:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-24(%rbp), %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB107_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1177:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$314, %esi
	leaq	___func__.7159(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1178:
LBB107_4:
Ltmp1179:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB107_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB107_7:
	callq	___stack_chk_fail
Ltmp1180:
Lfunc_end107:
Leh_func_end107:

	.globl	_atomic_cas_8
	.align	4, 0x90
_atomic_cas_8:
Leh_func_begin108:
Lfunc_begin108:
Ltmp1184:
	pushq	%rbp
Ltmp1181:
	movq	%rsp, %rbp
Ltmp1182:
	subq	$144, %rsp
Ltmp1183:
	movb	%dl, %al
	movb	%sil, %cl
	movq	___stack_chk_guard@GOTPCREL(%rip), %rdx
	movq	(%rdx), %rdx
	movq	%rdx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%cl, -17(%rbp)
	movb	%al, -18(%rbp)
Ltmp1185:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB108_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1186:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$333, %esi
	leaq	___func__.7190(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1187:
LBB108_2:
Ltmp1188:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	movb	-29(%rbp), %al
	movb	-17(%rbp), %cl
	cmpb	%cl, %al
	jne	LBB108_4
	movq	-16(%rbp), %rax
	movb	-18(%rbp), %cl
	movb	%cl, (%rax)
LBB108_4:
Ltmp1189:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB108_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1190:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$333, %esi
	leaq	___func__.7190(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1191:
LBB108_6:
Ltmp1192:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB108_9
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB108_9:
	callq	___stack_chk_fail
Ltmp1193:
Lfunc_end108:
Leh_func_end108:

	.globl	_atomic_cas_uchar
	.align	4, 0x90
_atomic_cas_uchar:
Leh_func_begin109:
Lfunc_begin109:
Ltmp1197:
	pushq	%rbp
Ltmp1194:
	movq	%rsp, %rbp
Ltmp1195:
	subq	$144, %rsp
Ltmp1196:
	movb	%dl, %al
	movb	%sil, %cl
	movq	___stack_chk_guard@GOTPCREL(%rip), %rdx
	movq	(%rdx), %rdx
	movq	%rdx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%cl, -17(%rbp)
	movb	%al, -18(%rbp)
Ltmp1198:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB109_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1199:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$334, %esi
	leaq	___func__.7221(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1200:
LBB109_2:
Ltmp1201:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	movb	-29(%rbp), %al
	movb	-17(%rbp), %cl
	cmpb	%cl, %al
	jne	LBB109_4
	movq	-16(%rbp), %rax
	movb	-18(%rbp), %cl
	movb	%cl, (%rax)
LBB109_4:
Ltmp1202:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB109_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1203:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$334, %esi
	leaq	___func__.7221(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1204:
LBB109_6:
Ltmp1205:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB109_9
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB109_9:
	callq	___stack_chk_fail
Ltmp1206:
Lfunc_end109:
Leh_func_end109:

	.globl	_atomic_cas_16
	.align	4, 0x90
_atomic_cas_16:
Leh_func_begin110:
Lfunc_begin110:
Ltmp1210:
	pushq	%rbp
Ltmp1207:
	movq	%rsp, %rbp
Ltmp1208:
	subq	$144, %rsp
Ltmp1209:
	movw	%dx, %ax
	movw	%si, %cx
	movq	___stack_chk_guard@GOTPCREL(%rip), %rdx
	movq	(%rdx), %rdx
	movq	%rdx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%cx, -18(%rbp)
	movw	%ax, -20(%rbp)
Ltmp1211:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB110_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1212:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$335, %esi
	leaq	___func__.7252(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1213:
LBB110_2:
Ltmp1214:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	movw	-30(%rbp), %ax
	movw	-18(%rbp), %cx
	cmpw	%cx, %ax
	jne	LBB110_4
	movq	-16(%rbp), %rax
	movw	-20(%rbp), %cx
	movw	%cx, (%rax)
LBB110_4:
Ltmp1215:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB110_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1216:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$335, %esi
	leaq	___func__.7252(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1217:
LBB110_6:
Ltmp1218:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB110_9
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB110_9:
	callq	___stack_chk_fail
Ltmp1219:
Lfunc_end110:
Leh_func_end110:

	.globl	_atomic_cas_ushort
	.align	4, 0x90
_atomic_cas_ushort:
Leh_func_begin111:
Lfunc_begin111:
Ltmp1223:
	pushq	%rbp
Ltmp1220:
	movq	%rsp, %rbp
Ltmp1221:
	subq	$144, %rsp
Ltmp1222:
	movw	%dx, %ax
	movw	%si, %cx
	movq	___stack_chk_guard@GOTPCREL(%rip), %rdx
	movq	(%rdx), %rdx
	movq	%rdx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%cx, -18(%rbp)
	movw	%ax, -20(%rbp)
Ltmp1224:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB111_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1225:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$336, %esi
	leaq	___func__.7283(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1226:
LBB111_2:
Ltmp1227:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	movw	-30(%rbp), %ax
	movw	-18(%rbp), %cx
	cmpw	%cx, %ax
	jne	LBB111_4
	movq	-16(%rbp), %rax
	movw	-20(%rbp), %cx
	movw	%cx, (%rax)
LBB111_4:
Ltmp1228:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB111_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1229:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$336, %esi
	leaq	___func__.7283(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1230:
LBB111_6:
Ltmp1231:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB111_9
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB111_9:
	callq	___stack_chk_fail
Ltmp1232:
Lfunc_end111:
Leh_func_end111:

	.globl	_atomic_cas_32
	.align	4, 0x90
_atomic_cas_32:
Leh_func_begin112:
Lfunc_begin112:
Ltmp1236:
	pushq	%rbp
Ltmp1233:
	movq	%rsp, %rbp
Ltmp1234:
	subq	$160, %rsp
Ltmp1235:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
	movl	%edx, -24(%rbp)
Ltmp1237:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB112_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1238:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$337, %esi
	leaq	___func__.7314(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp1239:
LBB112_2:
Ltmp1240:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -36(%rbp)
	movl	-36(%rbp), %eax
	movl	-20(%rbp), %ecx
	cmpl	%ecx, %eax
	jne	LBB112_4
	movq	-16(%rbp), %rax
	movl	-24(%rbp), %ecx
	movl	%ecx, (%rax)
LBB112_4:
Ltmp1241:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB112_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1242:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$337, %esi
	leaq	___func__.7314(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp1243:
LBB112_6:
Ltmp1244:
	movl	-36(%rbp), %eax
	movl	%eax, -32(%rbp)
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -152(%rbp)
	jne	LBB112_9
	movl	-152(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB112_9:
	callq	___stack_chk_fail
Ltmp1245:
Lfunc_end112:
Leh_func_end112:

	.globl	_atomic_cas_uint
	.align	4, 0x90
_atomic_cas_uint:
Leh_func_begin113:
Lfunc_begin113:
Ltmp1249:
	pushq	%rbp
Ltmp1246:
	movq	%rsp, %rbp
Ltmp1247:
	subq	$160, %rsp
Ltmp1248:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
	movl	%edx, -24(%rbp)
Ltmp1250:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB113_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1251:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -96(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -97(%rbp)
	movq	%rax, %rsi
	movq	-96(%rbp), %rcx
	movb	-97(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$338, %esi
	leaq	___func__.7345(%rip), %rdi
	movq	%rdi, -112(%rbp)
	movq	%rax, %rdi
	movl	%esi, -116(%rbp)
	movq	%rcx, %rsi
	movl	-116(%rbp), %eax
	movl	%eax, %edx
	movq	-112(%rbp), %rcx
	callq	___assert_c99
Ltmp1252:
LBB113_2:
Ltmp1253:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -36(%rbp)
	movl	-36(%rbp), %eax
	movl	-20(%rbp), %ecx
	cmpl	%ecx, %eax
	jne	LBB113_4
	movq	-16(%rbp), %rax
	movl	-24(%rbp), %ecx
	movl	%ecx, (%rax)
LBB113_4:
Ltmp1254:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB113_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1255:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -128(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -129(%rbp)
	movq	%rax, %rsi
	movq	-128(%rbp), %rcx
	movb	-129(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$338, %esi
	leaq	___func__.7345(%rip), %rdi
	movq	%rdi, -144(%rbp)
	movq	%rax, %rdi
	movl	%esi, -148(%rbp)
	movq	%rcx, %rsi
	movl	-148(%rbp), %eax
	movl	%eax, %edx
	movq	-144(%rbp), %rcx
	callq	___assert_c99
Ltmp1256:
LBB113_6:
Ltmp1257:
	movl	-36(%rbp), %eax
	movl	%eax, -32(%rbp)
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -152(%rbp)
	jne	LBB113_9
	movl	-152(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB113_9:
	callq	___stack_chk_fail
Ltmp1258:
Lfunc_end113:
Leh_func_end113:

	.globl	_atomic_cas_ulong
	.align	4, 0x90
_atomic_cas_ulong:
Leh_func_begin114:
Lfunc_begin114:
Ltmp1262:
	pushq	%rbp
Ltmp1259:
	movq	%rsp, %rbp
Ltmp1260:
	subq	$176, %rsp
Ltmp1261:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
	movq	%rdx, -32(%rbp)
Ltmp1263:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB114_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1264:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$339, %esi
	leaq	___func__.7376(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
Ltmp1265:
LBB114_2:
Ltmp1266:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -56(%rbp)
	movq	-56(%rbp), %rax
	movq	-24(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB114_4
	movq	-16(%rbp), %rax
	movq	-32(%rbp), %rcx
	movq	%rcx, (%rax)
LBB114_4:
Ltmp1267:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -88(%rbp)
	movq	$0, -96(%rbp)
	movq	-88(%rbp), %rcx
	movq	-96(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB114_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1268:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -104(%rbp)
	movq	-96(%rbp), %rdx
	movq	-88(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -144(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -145(%rbp)
	movq	%rax, %rsi
	movq	-144(%rbp), %rcx
	movb	-145(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-104(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$339, %esi
	leaq	___func__.7376(%rip), %rdi
	movq	%rdi, -160(%rbp)
	movq	%rax, %rdi
	movl	%esi, -164(%rbp)
	movq	%rcx, %rsi
	movl	-164(%rbp), %eax
	movl	%eax, %edx
	movq	-160(%rbp), %rcx
	callq	___assert_c99
Ltmp1269:
LBB114_6:
Ltmp1270:
	movq	-56(%rbp), %rax
	movq	%rax, -48(%rbp)
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -176(%rbp)
	jne	LBB114_9
	movq	-176(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB114_9:
	callq	___stack_chk_fail
Ltmp1271:
Lfunc_end114:
Leh_func_end114:

	.globl	_atomic_cas_64
	.align	4, 0x90
_atomic_cas_64:
Leh_func_begin115:
Lfunc_begin115:
Ltmp1275:
	pushq	%rbp
Ltmp1272:
	movq	%rsp, %rbp
Ltmp1273:
	subq	$176, %rsp
Ltmp1274:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
	movq	%rdx, -32(%rbp)
Ltmp1276:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB115_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1277:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$340, %esi
	leaq	___func__.7407(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
Ltmp1278:
LBB115_2:
Ltmp1279:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -56(%rbp)
	movq	-56(%rbp), %rax
	movq	-24(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB115_4
	movq	-16(%rbp), %rax
	movq	-32(%rbp), %rcx
	movq	%rcx, (%rax)
LBB115_4:
Ltmp1280:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -88(%rbp)
	movq	$0, -96(%rbp)
	movq	-88(%rbp), %rcx
	movq	-96(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB115_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1281:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -104(%rbp)
	movq	-96(%rbp), %rdx
	movq	-88(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -144(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -145(%rbp)
	movq	%rax, %rsi
	movq	-144(%rbp), %rcx
	movb	-145(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-104(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$340, %esi
	leaq	___func__.7407(%rip), %rdi
	movq	%rdi, -160(%rbp)
	movq	%rax, %rdi
	movl	%esi, -164(%rbp)
	movq	%rcx, %rsi
	movl	-164(%rbp), %eax
	movl	%eax, %edx
	movq	-160(%rbp), %rcx
	callq	___assert_c99
Ltmp1282:
LBB115_6:
Ltmp1283:
	movq	-56(%rbp), %rax
	movq	%rax, -48(%rbp)
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -176(%rbp)
	jne	LBB115_9
	movq	-176(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB115_9:
	callq	___stack_chk_fail
Ltmp1284:
Lfunc_end115:
Leh_func_end115:

	.globl	_atomic_cas_ptr
	.align	4, 0x90
_atomic_cas_ptr:
Leh_func_begin116:
Lfunc_begin116:
Ltmp1288:
	pushq	%rbp
Ltmp1285:
	movq	%rsp, %rbp
Ltmp1286:
	subq	$176, %rsp
Ltmp1287:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
	movq	%rdx, -32(%rbp)
Ltmp1289:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB116_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1290:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -112(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -113(%rbp)
	movq	%rax, %rsi
	movq	-112(%rbp), %rcx
	movb	-113(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$346, %esi
	leaq	___func__.7438(%rip), %rdi
	movq	%rdi, -128(%rbp)
	movq	%rax, %rdi
	movl	%esi, -132(%rbp)
	movq	%rcx, %rsi
	movl	-132(%rbp), %eax
	movl	%eax, %edx
	movq	-128(%rbp), %rcx
	callq	___assert_c99
Ltmp1291:
LBB116_2:
Ltmp1292:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -56(%rbp)
Ltmp1293:
	movq	-56(%rbp), %rax
	movq	-24(%rbp), %rcx
	cmpq	%rcx, %rax
	jne	LBB116_4
Ltmp1294:
	movq	-16(%rbp), %rax
	movq	-32(%rbp), %rcx
	movq	%rcx, (%rax)
LBB116_4:
Ltmp1295:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -88(%rbp)
	movq	$0, -96(%rbp)
	movq	-88(%rbp), %rcx
	movq	-96(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB116_6
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1296:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -104(%rbp)
	movq	-96(%rbp), %rdx
	movq	-88(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -144(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -145(%rbp)
	movq	%rax, %rsi
	movq	-144(%rbp), %rcx
	movb	-145(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-104(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$350, %esi
	leaq	___func__.7438(%rip), %rdi
	movq	%rdi, -160(%rbp)
	movq	%rax, %rdi
	movl	%esi, -164(%rbp)
	movq	%rcx, %rsi
	movl	-164(%rbp), %eax
	movl	%eax, %edx
	movq	-160(%rbp), %rcx
	callq	___assert_c99
Ltmp1297:
LBB116_6:
Ltmp1298:
	movq	-56(%rbp), %rax
	movq	%rax, -48(%rbp)
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -176(%rbp)
	jne	LBB116_9
	movq	-176(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB116_9:
	callq	___stack_chk_fail
Ltmp1299:
Lfunc_end116:
Leh_func_end116:

	.globl	_atomic_swap_8
	.align	4, 0x90
_atomic_swap_8:
Leh_func_begin117:
Lfunc_begin117:
Ltmp1303:
	pushq	%rbp
Ltmp1300:
	movq	%rsp, %rbp
Ltmp1301:
	subq	$144, %rsp
Ltmp1302:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp1304:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB117_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1305:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$371, %esi
	leaq	___func__.7470(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1306:
LBB117_2:
Ltmp1307:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	movq	-16(%rbp), %rax
	movb	-17(%rbp), %cl
	movb	%cl, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB117_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1308:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$371, %esi
	leaq	___func__.7470(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1309:
LBB117_4:
Ltmp1310:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB117_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB117_7:
	callq	___stack_chk_fail
Ltmp1311:
Lfunc_end117:
Leh_func_end117:

	.globl	_atomic_swap_uchar
	.align	4, 0x90
_atomic_swap_uchar:
Leh_func_begin118:
Lfunc_begin118:
Ltmp1315:
	pushq	%rbp
Ltmp1312:
	movq	%rsp, %rbp
Ltmp1313:
	subq	$144, %rsp
Ltmp1314:
	movb	%sil, %al
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movb	%al, -17(%rbp)
Ltmp1316:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB118_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1317:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$372, %esi
	leaq	___func__.7498(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1318:
LBB118_2:
Ltmp1319:
	movq	-16(%rbp), %rax
	movb	(%rax), %al
	movb	%al, -29(%rbp)
	movq	-16(%rbp), %rax
	movb	-17(%rbp), %cl
	movb	%cl, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB118_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1320:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$372, %esi
	leaq	___func__.7498(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1321:
LBB118_4:
Ltmp1322:
	movb	-29(%rbp), %al
	movzbl	%al, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movb	%al, -141(%rbp)
	jne	LBB118_7
	movb	-141(%rbp), %al
	movzbl	%al, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB118_7:
	callq	___stack_chk_fail
Ltmp1323:
Lfunc_end118:
Leh_func_end118:

	.globl	_atomic_swap_16
	.align	4, 0x90
_atomic_swap_16:
Leh_func_begin119:
Lfunc_begin119:
Ltmp1327:
	pushq	%rbp
Ltmp1324:
	movq	%rsp, %rbp
Ltmp1325:
	subq	$144, %rsp
Ltmp1326:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1328:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB119_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1329:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$373, %esi
	leaq	___func__.7526(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1330:
LBB119_2:
Ltmp1331:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	movq	-16(%rbp), %rax
	movw	-18(%rbp), %cx
	movw	%cx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB119_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1332:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$373, %esi
	leaq	___func__.7526(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1333:
LBB119_4:
Ltmp1334:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB119_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB119_7:
	callq	___stack_chk_fail
Ltmp1335:
Lfunc_end119:
Leh_func_end119:

	.globl	_atomic_swap_ushort
	.align	4, 0x90
_atomic_swap_ushort:
Leh_func_begin120:
Lfunc_begin120:
Ltmp1339:
	pushq	%rbp
Ltmp1336:
	movq	%rsp, %rbp
Ltmp1337:
	subq	$144, %rsp
Ltmp1338:
	movw	%si, %ax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	%rcx, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movw	%ax, -18(%rbp)
Ltmp1340:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB120_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1341:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$374, %esi
	leaq	___func__.7554(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1342:
LBB120_2:
Ltmp1343:
	movq	-16(%rbp), %rax
	movw	(%rax), %ax
	movw	%ax, -30(%rbp)
	movq	-16(%rbp), %rax
	movw	-18(%rbp), %cx
	movw	%cx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB120_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1344:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$374, %esi
	leaq	___func__.7554(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1345:
LBB120_4:
Ltmp1346:
	movw	-30(%rbp), %ax
	movzwl	%ax, %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movw	%ax, -142(%rbp)
	jne	LBB120_7
	movw	-142(%rbp), %ax
	movzwl	%ax, %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB120_7:
	callq	___stack_chk_fail
Ltmp1347:
Lfunc_end120:
Leh_func_end120:

	.globl	_atomic_swap_32
	.align	4, 0x90
_atomic_swap_32:
Leh_func_begin121:
Lfunc_begin121:
Ltmp1351:
	pushq	%rbp
Ltmp1348:
	movq	%rsp, %rbp
Ltmp1349:
	subq	$144, %rsp
Ltmp1350:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1352:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB121_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1353:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$375, %esi
	leaq	___func__.7582(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1354:
LBB121_2:
Ltmp1355:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	movq	-16(%rbp), %rax
	movl	-20(%rbp), %ecx
	movl	%ecx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB121_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1356:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$375, %esi
	leaq	___func__.7582(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1357:
LBB121_4:
Ltmp1358:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB121_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB121_7:
	callq	___stack_chk_fail
Ltmp1359:
Lfunc_end121:
Leh_func_end121:

	.globl	_atomic_swap_uint
	.align	4, 0x90
_atomic_swap_uint:
Leh_func_begin122:
Lfunc_begin122:
Ltmp1363:
	pushq	%rbp
Ltmp1360:
	movq	%rsp, %rbp
Ltmp1361:
	subq	$144, %rsp
Ltmp1362:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1364:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -40(%rbp)
	movq	$0, -48(%rbp)
	movq	-40(%rbp), %rcx
	movq	-48(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB122_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1365:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -56(%rbp)
	movq	-48(%rbp), %rdx
	movq	-40(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -88(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -89(%rbp)
	movq	%rax, %rsi
	movq	-88(%rbp), %rcx
	movb	-89(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-56(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$376, %esi
	leaq	___func__.7610(%rip), %rdi
	movq	%rdi, -104(%rbp)
	movq	%rax, %rdi
	movl	%esi, -108(%rbp)
	movq	%rcx, %rsi
	movl	-108(%rbp), %eax
	movl	%eax, %edx
	movq	-104(%rbp), %rcx
	callq	___assert_c99
Ltmp1366:
LBB122_2:
Ltmp1367:
	movq	-16(%rbp), %rax
	movl	(%rax), %eax
	movl	%eax, -32(%rbp)
	movq	-16(%rbp), %rax
	movl	-20(%rbp), %ecx
	movl	%ecx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -64(%rbp)
	movq	$0, -72(%rbp)
	movq	-64(%rbp), %rcx
	movq	-72(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB122_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1368:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -80(%rbp)
	movq	-72(%rbp), %rdx
	movq	-64(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-80(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$376, %esi
	leaq	___func__.7610(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1369:
LBB122_4:
Ltmp1370:
	movl	-32(%rbp), %eax
	movl	%eax, -28(%rbp)
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -144(%rbp)
	jne	LBB122_7
	movl	-144(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB122_7:
	callq	___stack_chk_fail
Ltmp1371:
Lfunc_end122:
Leh_func_end122:

	.globl	_atomic_swap_ulong
	.align	4, 0x90
_atomic_swap_ulong:
Leh_func_begin123:
Lfunc_begin123:
Ltmp1375:
	pushq	%rbp
Ltmp1372:
	movq	%rsp, %rbp
Ltmp1373:
	subq	$176, %rsp
Ltmp1374:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1376:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB123_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1377:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$377, %esi
	leaq	___func__.7638(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1378:
LBB123_2:
Ltmp1379:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	movq	-16(%rbp), %rax
	movq	-24(%rbp), %rcx
	movq	%rcx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB123_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1380:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$377, %esi
	leaq	___func__.7638(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1381:
LBB123_4:
Ltmp1382:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB123_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB123_7:
	callq	___stack_chk_fail
Ltmp1383:
Lfunc_end123:
Leh_func_end123:

	.globl	_atomic_swap_64
	.align	4, 0x90
_atomic_swap_64:
Leh_func_begin124:
Lfunc_begin124:
Ltmp1387:
	pushq	%rbp
Ltmp1384:
	movq	%rsp, %rbp
Ltmp1385:
	subq	$176, %rsp
Ltmp1386:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1388:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB124_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1389:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$378, %esi
	leaq	___func__.7666(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1390:
LBB124_2:
Ltmp1391:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
	movq	-16(%rbp), %rax
	movq	-24(%rbp), %rcx
	movq	%rcx, (%rax)
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB124_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1392:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$378, %esi
	leaq	___func__.7666(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1393:
LBB124_4:
Ltmp1394:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB124_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB124_7:
	callq	___stack_chk_fail
Ltmp1395:
Lfunc_end124:
Leh_func_end124:

	.globl	_atomic_swap_ptr
	.align	4, 0x90
_atomic_swap_ptr:
Leh_func_begin125:
Lfunc_begin125:
Ltmp1399:
	pushq	%rbp
Ltmp1396:
	movq	%rsp, %rbp
Ltmp1397:
	subq	$176, %rsp
Ltmp1398:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movq	%rsi, -24(%rbp)
Ltmp1400:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -56(%rbp)
	movq	$0, -64(%rbp)
	movq	-56(%rbp), %rcx
	movq	-64(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB125_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1401:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -72(%rbp)
	movq	-64(%rbp), %rdx
	movq	-56(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -104(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -105(%rbp)
	movq	%rax, %rsi
	movq	-104(%rbp), %rcx
	movb	-105(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-72(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$384, %esi
	leaq	___func__.7694(%rip), %rdi
	movq	%rdi, -120(%rbp)
	movq	%rax, %rdi
	movl	%esi, -124(%rbp)
	movq	%rcx, %rsi
	movl	-124(%rbp), %eax
	movl	%eax, %edx
	movq	-120(%rbp), %rcx
	callq	___assert_c99
Ltmp1402:
LBB125_2:
Ltmp1403:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -48(%rbp)
Ltmp1404:
	movq	-16(%rbp), %rax
	movq	-24(%rbp), %rcx
	movq	%rcx, (%rax)
Ltmp1405:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -80(%rbp)
	movq	$0, -88(%rbp)
	movq	-80(%rbp), %rcx
	movq	-88(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB125_4
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1406:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -96(%rbp)
	movq	-88(%rbp), %rdx
	movq	-80(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -136(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -137(%rbp)
	movq	%rax, %rsi
	movq	-136(%rbp), %rcx
	movb	-137(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-96(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$387, %esi
	leaq	___func__.7694(%rip), %rdi
	movq	%rdi, -152(%rbp)
	movq	%rax, %rdi
	movl	%esi, -156(%rbp)
	movq	%rcx, %rsi
	movl	-156(%rbp), %eax
	movl	%eax, %edx
	movq	-152(%rbp), %rcx
	callq	___assert_c99
Ltmp1407:
LBB125_4:
Ltmp1408:
	movq	-48(%rbp), %rax
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movq	%rax, -168(%rbp)
	jne	LBB125_7
	movq	-168(%rbp), %rax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB125_7:
	callq	___stack_chk_fail
Ltmp1409:
Lfunc_end125:
Leh_func_end125:

	.globl	_atomic_set_long_excl
	.align	4, 0x90
_atomic_set_long_excl:
Leh_func_begin126:
Lfunc_begin126:
Ltmp1413:
	pushq	%rbp
Ltmp1410:
	movq	%rsp, %rbp
Ltmp1411:
	subq	$208, %rsp
Ltmp1412:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1414:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB126_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1415:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$397, %esi
	leaq	___func__.7724(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1416:
LBB126_2:
Ltmp1417:
	movl	-20(%rbp), %eax
	movl	%eax, %eax
	movq	%rax, %rcx
	movabsq	$1, %rax
	shlq	%cl, %rax
	movq	%rax, -40(%rbp)
Ltmp1418:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-40(%rbp), %rdx
	andq	%rdx, %rax
	cmpq	$0, %rax
	je	LBB126_6
Ltmp1419:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB126_5
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1420:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -152(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -153(%rbp)
	movq	%rax, %rsi
	movq	-152(%rbp), %rcx
	movb	-153(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$400, %esi
	leaq	___func__.7724(%rip), %rdi
	movq	%rdi, -168(%rbp)
	movq	%rax, %rdi
	movl	%esi, -172(%rbp)
	movq	%rcx, %rsi
	movl	-172(%rbp), %eax
	movl	%eax, %edx
	movq	-168(%rbp), %rcx
	callq	___assert_c99
Ltmp1421:
LBB126_5:
Ltmp1422:
	movl	$-1, -28(%rbp)
	jmp	LBB126_9
LBB126_6:
Ltmp1423:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-40(%rbp), %rcx
	orq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
Ltmp1424:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -96(%rbp)
	movq	$0, -104(%rbp)
	movq	-96(%rbp), %rcx
	movq	-104(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB126_8
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1425:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -112(%rbp)
	movq	-104(%rbp), %rdx
	movq	-96(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -184(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -185(%rbp)
	movq	%rax, %rsi
	movq	-184(%rbp), %rcx
	movb	-185(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-112(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$404, %esi
	leaq	___func__.7724(%rip), %rdi
	movq	%rdi, -200(%rbp)
	movq	%rax, %rdi
	movl	%esi, -204(%rbp)
	movq	%rcx, %rsi
	movl	-204(%rbp), %eax
	movl	%eax, %edx
	movq	-200(%rbp), %rcx
	callq	___assert_c99
Ltmp1426:
LBB126_8:
Ltmp1427:
	movl	$0, -28(%rbp)
LBB126_9:
Ltmp1428:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -208(%rbp)
	jne	LBB126_12
	movl	-208(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB126_12:
	callq	___stack_chk_fail
Ltmp1429:
Lfunc_end126:
Leh_func_end126:

	.globl	_atomic_clear_long_excl
	.align	4, 0x90
_atomic_clear_long_excl:
Leh_func_begin127:
Lfunc_begin127:
Ltmp1433:
	pushq	%rbp
Ltmp1430:
	movq	%rsp, %rbp
Ltmp1431:
	subq	$208, %rsp
Ltmp1432:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -8(%rbp)
	movq	%rdi, -16(%rbp)
	movl	%esi, -20(%rbp)
Ltmp1434:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_lock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -48(%rbp)
	movq	$0, -56(%rbp)
	movq	-48(%rbp), %rcx
	movq	-56(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB127_2
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1435:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -64(%rbp)
	movq	-56(%rbp), %rdx
	movq	-48(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	movq	%rdi, -120(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -121(%rbp)
	movq	%rax, %rsi
	movq	-120(%rbp), %rcx
	movb	-121(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-64(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$413, %esi
	leaq	___func__.7769(%rip), %rdi
	movq	%rdi, -136(%rbp)
	movq	%rax, %rdi
	movl	%esi, -140(%rbp)
	movq	%rcx, %rsi
	movl	-140(%rbp), %eax
	movl	%eax, %edx
	movq	-136(%rbp), %rcx
	callq	___assert_c99
Ltmp1436:
LBB127_2:
Ltmp1437:
	movl	-20(%rbp), %eax
	movl	%eax, %eax
	movq	%rax, %rcx
	movabsq	$1, %rax
	shlq	%cl, %rax
	movq	%rax, -40(%rbp)
Ltmp1438:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-40(%rbp), %rdx
	andq	%rdx, %rax
	cmpq	$0, %rax
	je	LBB127_6
Ltmp1439:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -72(%rbp)
	movq	$0, -80(%rbp)
	movq	-72(%rbp), %rcx
	movq	-80(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB127_5
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1440:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -88(%rbp)
	movq	-80(%rbp), %rdx
	movq	-72(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -152(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -153(%rbp)
	movq	%rax, %rsi
	movq	-152(%rbp), %rcx
	movb	-153(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-88(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$416, %esi
	leaq	___func__.7769(%rip), %rdi
	movq	%rdi, -168(%rbp)
	movq	%rax, %rdi
	movl	%esi, -172(%rbp)
	movq	%rcx, %rsi
	movl	-172(%rbp), %eax
	movl	%eax, %edx
	movq	-168(%rbp), %rcx
	callq	___assert_c99
Ltmp1441:
LBB127_5:
Ltmp1442:
	movl	$-1, -28(%rbp)
	jmp	LBB127_9
LBB127_6:
Ltmp1443:
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	-40(%rbp), %rcx
	movabsq	$-1, %rdx
	xorq	%rdx, %rcx
	andq	%rcx, %rax
	movq	-16(%rbp), %rcx
	movq	%rax, (%rcx)
Ltmp1444:
	leaq	_atomic_lock(%rip), %rax
	movq	%rax, %rdi
	callq	_pthread_mutex_unlock
	movl	%eax, %ecx
	movslq	%ecx, %rcx
	movq	%rcx, -96(%rbp)
	movq	$0, -104(%rbp)
	movq	-96(%rbp), %rcx
	movq	-104(%rbp), %rdx
	cmpq	%rdx, %rcx
	je	LBB127_8
	movl	$256, %eax
	movq	%rsp, %rcx
Ltmp1445:
	leaq	-256(%rcx), %rcx
	movq	%rcx, %rsp
	movq	%rcx, -112(%rbp)
	movq	-104(%rbp), %rdx
	movq	-96(%rbp), %rsi
	movq	$-1, %rdi
	subq	$48, %rsp
	movq	%rsp, %r8
	movq	%rdx, 32(%r8)
	leaq	L_.str2(%rip), %rdx
	movq	%rdx, 24(%r8)
	movq	%rsi, 16(%r8)
	leaq	L_.str3(%rip), %rsi
	movq	%rsi, 8(%r8)
	movq	%rdx, (%r8)
	xorl	%edx, %edx
	xorb	%sil, %sil
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	movq	%rdi, -184(%rbp)
	movq	%rcx, %rdi
	movb	%sil, -185(%rbp)
	movq	%rax, %rsi
	movq	-184(%rbp), %rcx
	movb	-185(%rbp), %al
	callq	___snprintf_chk
	addq	$48, %rsp
	movq	-112(%rbp), %rax
	leaq	L_.str4(%rip), %rcx
	movl	$420, %esi
	leaq	___func__.7769(%rip), %rdi
	movq	%rdi, -200(%rbp)
	movq	%rax, %rdi
	movl	%esi, -204(%rbp)
	movq	%rcx, %rsi
	movl	-204(%rbp), %eax
	movl	%eax, %edx
	movq	-200(%rbp), %rcx
	callq	___assert_c99
Ltmp1446:
LBB127_8:
Ltmp1447:
	movl	$0, -28(%rbp)
LBB127_9:
Ltmp1448:
	movl	-28(%rbp), %eax
	movl	%eax, -24(%rbp)
	movl	-24(%rbp), %eax
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	movq	-8(%rbp), %rdx
	cmpq	%rdx, %rcx
	movl	%eax, -208(%rbp)
	jne	LBB127_12
	movl	-208(%rbp), %eax
	movq	%rbp, %rsp
	popq	%rbp
	ret
LBB127_12:
	callq	___stack_chk_fail
Ltmp1449:
Lfunc_end127:
Leh_func_end127:

	.globl	_membar_enter
	.align	4, 0x90
_membar_enter:
Leh_func_begin128:
Lfunc_begin128:
Ltmp1452:
	pushq	%rbp
Ltmp1450:
	movq	%rsp, %rbp
Ltmp1451:
Ltmp1453:
	popq	%rbp
	ret
Ltmp1454:
Lfunc_end128:
Leh_func_end128:

	.globl	_membar_exit
	.align	4, 0x90
_membar_exit:
Leh_func_begin129:
Lfunc_begin129:
Ltmp1457:
	pushq	%rbp
Ltmp1455:
	movq	%rsp, %rbp
Ltmp1456:
Ltmp1458:
	popq	%rbp
	ret
Ltmp1459:
Lfunc_end129:
Leh_func_end129:

	.globl	_membar_producer
	.align	4, 0x90
_membar_producer:
Leh_func_begin130:
Lfunc_begin130:
Ltmp1462:
	pushq	%rbp
Ltmp1460:
	movq	%rsp, %rbp
Ltmp1461:
Ltmp1463:
	popq	%rbp
	ret
Ltmp1464:
Lfunc_end130:
Leh_func_end130:

	.globl	_membar_consumer
	.align	4, 0x90
_membar_consumer:
Leh_func_begin131:
Lfunc_begin131:
Ltmp1467:
	pushq	%rbp
Ltmp1465:
	movq	%rsp, %rbp
Ltmp1466:
Ltmp1468:
	popq	%rbp
	ret
Ltmp1469:
Lfunc_end131:
Leh_func_end131:

	.globl	_cas8
	.align	4, 0x90
_cas8:
Leh_func_begin132:
Lfunc_begin132:
Ltmp1473:
	pushq	%rbp
Ltmp1470:
	movq	%rsp, %rbp
Ltmp1471:
	subq	$32, %rsp
Ltmp1472:
	movb	%dl, %al
	movb	%sil, %cl
	movq	%rdi, -8(%rbp)
	movb	%cl, -9(%rbp)
	movb	%al, -10(%rbp)
Ltmp1474:
	movb	-10(%rbp), %al
	movzbl	%al, %eax
	movb	-9(%rbp), %cl
	movzbl	%cl, %ecx
	movq	-8(%rbp), %rdx
	movq	%rdx, %rdi
	movzbl	%cl, %ecx
	movl	%ecx, %esi
	movzbl	%al, %eax
	movl	%eax, %edx
	callq	_atomic_cas_8
	movb	%al, %cl
	movzbl	%cl, %ecx
	movl	%ecx, -20(%rbp)
	movl	-20(%rbp), %ecx
	movl	%ecx, -16(%rbp)
	movl	-16(%rbp), %eax
	movzbl	%al, %eax
	addq	$32, %rsp
	popq	%rbp
	ret
Ltmp1475:
Lfunc_end132:
Leh_func_end132:

	.globl	_cas32
	.align	4, 0x90
_cas32:
Leh_func_begin133:
Lfunc_begin133:
Ltmp1479:
	pushq	%rbp
Ltmp1476:
	movq	%rsp, %rbp
Ltmp1477:
	subq	$32, %rsp
Ltmp1478:
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
Ltmp1480:
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %ecx
	movl	-16(%rbp), %edx
	movq	%rax, %rdi
	movl	%ecx, %esi
	callq	_atomic_cas_32
	movl	%eax, %ecx
	movl	%ecx, -24(%rbp)
	movl	-24(%rbp), %ecx
	movl	%ecx, -20(%rbp)
	movl	-20(%rbp), %eax
	addq	$32, %rsp
	popq	%rbp
	ret
Ltmp1481:
Lfunc_end133:
Leh_func_end133:

	.globl	_cas64
	.align	4, 0x90
_cas64:
Leh_func_begin134:
Lfunc_begin134:
Ltmp1485:
	pushq	%rbp
Ltmp1482:
	movq	%rsp, %rbp
Ltmp1483:
	subq	$48, %rsp
Ltmp1484:
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
Ltmp1486:
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	-24(%rbp), %rdx
	movq	%rax, %rdi
	movq	%rcx, %rsi
	callq	_atomic_cas_64
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	addq	$48, %rsp
	popq	%rbp
	ret
Ltmp1487:
Lfunc_end134:
Leh_func_end134:

	.globl	_caslong
	.align	4, 0x90
_caslong:
Leh_func_begin135:
Lfunc_begin135:
Ltmp1491:
	pushq	%rbp
Ltmp1488:
	movq	%rsp, %rbp
Ltmp1489:
	subq	$48, %rsp
Ltmp1490:
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
Ltmp1492:
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	-24(%rbp), %rdx
	movq	%rax, %rdi
	movq	%rcx, %rsi
	callq	_atomic_cas_ulong
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	addq	$48, %rsp
	popq	%rbp
	ret
Ltmp1493:
Lfunc_end135:
Leh_func_end135:

	.globl	_casptr
	.align	4, 0x90
_casptr:
Leh_func_begin136:
Lfunc_begin136:
Ltmp1497:
	pushq	%rbp
Ltmp1494:
	movq	%rsp, %rbp
Ltmp1495:
	subq	$48, %rsp
Ltmp1496:
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
Ltmp1498:
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	-24(%rbp), %rdx
	movq	%rax, %rdi
	movq	%rcx, %rsi
	callq	_atomic_cas_ptr
	movq	%rax, -40(%rbp)
	movq	-40(%rbp), %rax
	movq	%rax, -32(%rbp)
	movq	-32(%rbp), %rax
	addq	$48, %rsp
	popq	%rbp
	ret
Ltmp1499:
Lfunc_end136:
Leh_func_end136:

	.globl	_atomic_and_long
	.align	4, 0x90
_atomic_and_long:
Leh_func_begin137:
Lfunc_begin137:
Ltmp1503:
	pushq	%rbp
Ltmp1500:
	movq	%rsp, %rbp
Ltmp1501:
	subq	$16, %rsp
Ltmp1502:
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
Ltmp1504:
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	%rax, %rdi
	movq	%rcx, %rsi
	callq	_atomic_and_ulong
	addq	$16, %rsp
	popq	%rbp
	ret
Ltmp1505:
Lfunc_end137:
Leh_func_end137:

	.globl	_atomic_or_long
	.align	4, 0x90
_atomic_or_long:
Leh_func_begin138:
Lfunc_begin138:
Ltmp1509:
	pushq	%rbp
Ltmp1506:
	movq	%rsp, %rbp
Ltmp1507:
	subq	$16, %rsp
Ltmp1508:
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
Ltmp1510:
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rcx
	movq	%rax, %rdi
	movq	%rcx, %rsi
	callq	_atomic_or_ulong
	addq	$16, %rsp
	popq	%rbp
	ret
Ltmp1511:
Lfunc_end138:
Leh_func_end138:

	.section	__DATA,__data
	.globl	_atomic_lock
	.align	5
_atomic_lock:
	.quad	850045863
	.space	56

	.section	__TEXT,__cstring,cstring_literals
L_.str:
	.asciz	 "%s %s %s (0x%llx %s 0x%llx)"

	.align	3
L_.str1:
	.asciz	 "pthread_mutex_lock(&atomic_lock)"

L_.str2:
	.asciz	 "=="

L_.str3:
	.asciz	 "0"

L_.str4:
	.asciz	 "atomic.c"

	.align	3
___func__.4157:
	.asciz	 "atomic_inc_long"

	.align	3
L_.str5:
	.asciz	 "pthread_mutex_unlock(&atomic_lock)"

	.align	3
L_.str6:
	.asciz	 "%s:%i: %s: Assertion `%s` failed.\n"

	.align	3
___func__.4183:
	.asciz	 "atomic_inc_8"

	.align	3
___func__.4209:
	.asciz	 "atomic_inc_uchar"

	.align	3
___func__.4235:
	.asciz	 "atomic_inc_16"

	.align	3
___func__.4261:
	.asciz	 "atomic_inc_ushort"

	.align	3
___func__.4287:
	.asciz	 "atomic_inc_32"

	.align	3
___func__.4313:
	.asciz	 "atomic_inc_uint"

	.align	3
___func__.4339:
	.asciz	 "atomic_inc_ulong"

	.align	3
___func__.4365:
	.asciz	 "atomic_inc_64"

	.align	3
___func__.4391:
	.asciz	 "atomic_dec_long"

	.align	3
___func__.4417:
	.asciz	 "atomic_dec_8"

	.align	3
___func__.4443:
	.asciz	 "atomic_dec_uchar"

	.align	3
___func__.4469:
	.asciz	 "atomic_dec_16"

	.align	3
___func__.4495:
	.asciz	 "atomic_dec_ushort"

	.align	3
___func__.4521:
	.asciz	 "atomic_dec_32"

	.align	3
___func__.4547:
	.asciz	 "atomic_dec_uint"

	.align	3
___func__.4573:
	.asciz	 "atomic_dec_ulong"

	.align	3
___func__.4599:
	.asciz	 "atomic_dec_64"

	.align	3
___func__.4626:
	.asciz	 "atomic_add_8"

	.align	3
___func__.4654:
	.asciz	 "atomic_add_char"

	.align	3
___func__.4682:
	.asciz	 "atomic_add_16"

	.align	3
___func__.4710:
	.asciz	 "atomic_add_short"

	.align	3
___func__.4738:
	.asciz	 "atomic_add_32"

	.align	3
___func__.4766:
	.asciz	 "atomic_add_int"

	.align	3
___func__.4794:
	.asciz	 "atomic_add_long"

	.align	3
___func__.4822:
	.asciz	 "atomic_add_64"

	.align	3
___func__.4850:
	.asciz	 "atomic_add_ptr"

	.align	3
___func__.4879:
	.asciz	 "atomic_sub_8"

	.align	3
___func__.4907:
	.asciz	 "atomic_sub_char"

	.align	3
___func__.4935:
	.asciz	 "atomic_sub_16"

	.align	3
___func__.4963:
	.asciz	 "atomic_sub_short"

	.align	3
___func__.4991:
	.asciz	 "atomic_sub_32"

	.align	3
___func__.5019:
	.asciz	 "atomic_sub_int"

	.align	3
___func__.5047:
	.asciz	 "atomic_sub_long"

	.align	3
___func__.5075:
	.asciz	 "atomic_sub_64"

	.align	3
___func__.5103:
	.asciz	 "atomic_sub_ptr"

	.align	3
___func__.5133:
	.asciz	 "atomic_or_8"

	.align	3
___func__.5160:
	.asciz	 "atomic_or_uchar"

	.align	3
___func__.5187:
	.asciz	 "atomic_or_16"

	.align	3
___func__.5214:
	.asciz	 "atomic_or_ushort"

	.align	3
___func__.5241:
	.asciz	 "atomic_or_32"

	.align	3
___func__.5268:
	.asciz	 "atomic_or_uint"

	.align	3
___func__.5295:
	.asciz	 "atomic_or_ulong"

	.align	3
___func__.5322:
	.asciz	 "atomic_or_64"

	.align	3
___func__.5349:
	.asciz	 "atomic_and_8"

	.align	3
___func__.5376:
	.asciz	 "atomic_and_uchar"

	.align	3
___func__.5403:
	.asciz	 "atomic_and_16"

	.align	3
___func__.5430:
	.asciz	 "atomic_and_ushort"

	.align	3
___func__.5457:
	.asciz	 "atomic_and_32"

	.align	3
___func__.5484:
	.asciz	 "atomic_and_uint"

	.align	3
___func__.5511:
	.asciz	 "atomic_and_ulong"

	.align	3
___func__.5538:
	.asciz	 "atomic_and_64"

	.align	3
___func__.5565:
	.asciz	 "atomic_inc_long_nv"

	.align	3
___func__.5594:
	.asciz	 "atomic_inc_8_nv"

	.align	3
___func__.5623:
	.asciz	 "atomic_inc_uchar_nv"

	.align	3
___func__.5652:
	.asciz	 "atomic_inc_16_nv"

	.align	3
___func__.5681:
	.asciz	 "atomic_inc_ushort_nv"

	.align	3
___func__.5710:
	.asciz	 "atomic_inc_32_nv"

	.align	3
___func__.5739:
	.asciz	 "atomic_inc_uint_nv"

	.align	3
___func__.5768:
	.asciz	 "atomic_inc_ulong_nv"

	.align	3
___func__.5797:
	.asciz	 "atomic_inc_64_nv"

	.align	3
___func__.5826:
	.asciz	 "atomic_dec_long_nv"

	.align	3
___func__.5855:
	.asciz	 "atomic_dec_8_nv"

	.align	3
___func__.5884:
	.asciz	 "atomic_dec_uchar_nv"

	.align	3
___func__.5913:
	.asciz	 "atomic_dec_16_nv"

	.align	3
___func__.5942:
	.asciz	 "atomic_dec_ushort_nv"

	.align	3
___func__.5971:
	.asciz	 "atomic_dec_32_nv"

	.align	3
___func__.6000:
	.asciz	 "atomic_dec_uint_nv"

	.align	3
___func__.6029:
	.asciz	 "atomic_dec_ulong_nv"

	.align	3
___func__.6058:
	.asciz	 "atomic_dec_64_nv"

	.align	3
___func__.6088:
	.asciz	 "atomic_add_8_nv"

	.align	3
___func__.6119:
	.asciz	 "atomic_add_char_nv"

	.align	3
___func__.6150:
	.asciz	 "atomic_add_16_nv"

	.align	3
___func__.6181:
	.asciz	 "atomic_add_short_nv"

	.align	3
___func__.6212:
	.asciz	 "atomic_add_32_nv"

	.align	3
___func__.6243:
	.asciz	 "atomic_add_int_nv"

	.align	3
___func__.6274:
	.asciz	 "atomic_add_long_nv"

	.align	3
___func__.6305:
	.asciz	 "atomic_add_64_nv"

	.align	3
___func__.6336:
	.asciz	 "atomic_add_ptr_nv"

	.align	3
___func__.6368:
	.asciz	 "atomic_sub_8_nv"

	.align	3
___func__.6399:
	.asciz	 "atomic_sub_char_nv"

	.align	3
___func__.6430:
	.asciz	 "atomic_sub_16_nv"

	.align	3
___func__.6461:
	.asciz	 "atomic_sub_short_nv"

	.align	3
___func__.6492:
	.asciz	 "atomic_sub_32_nv"

	.align	3
___func__.6523:
	.asciz	 "atomic_sub_int_nv"

	.align	3
___func__.6554:
	.asciz	 "atomic_sub_long_nv"

	.align	3
___func__.6585:
	.asciz	 "atomic_sub_64_nv"

	.align	3
___func__.6616:
	.asciz	 "atomic_sub_ptr_nv"

	.align	3
___func__.6649:
	.asciz	 "atomic_or_long_nv"

	.align	3
___func__.6679:
	.asciz	 "atomic_or_8_nv"

	.align	3
___func__.6709:
	.asciz	 "atomic_or_uchar_nv"

	.align	3
___func__.6739:
	.asciz	 "atomic_or_16_nv"

	.align	3
___func__.6769:
	.asciz	 "atomic_or_ushort_nv"

	.align	3
___func__.6799:
	.asciz	 "atomic_or_32_nv"

	.align	3
___func__.6829:
	.asciz	 "atomic_or_uint_nv"

	.align	3
___func__.6859:
	.asciz	 "atomic_or_ulong_nv"

	.align	3
___func__.6889:
	.asciz	 "atomic_or_64_nv"

	.align	3
___func__.6919:
	.asciz	 "atomic_and_long_nv"

	.align	3
___func__.6949:
	.asciz	 "atomic_and_8_nv"

	.align	3
___func__.6979:
	.asciz	 "atomic_and_uchar_nv"

	.align	3
___func__.7009:
	.asciz	 "atomic_and_16_nv"

	.align	3
___func__.7039:
	.asciz	 "atomic_and_ushort_nv"

	.align	3
___func__.7069:
	.asciz	 "atomic_and_32_nv"

	.align	3
___func__.7099:
	.asciz	 "atomic_and_uint_nv"

	.align	3
___func__.7129:
	.asciz	 "atomic_and_ulong_nv"

	.align	3
___func__.7159:
	.asciz	 "atomic_and_64_nv"

	.align	3
___func__.7190:
	.asciz	 "atomic_cas_8"

	.align	3
___func__.7221:
	.asciz	 "atomic_cas_uchar"

	.align	3
___func__.7252:
	.asciz	 "atomic_cas_16"

	.align	3
___func__.7283:
	.asciz	 "atomic_cas_ushort"

	.align	3
___func__.7314:
	.asciz	 "atomic_cas_32"

	.align	3
___func__.7345:
	.asciz	 "atomic_cas_uint"

	.align	3
___func__.7376:
	.asciz	 "atomic_cas_ulong"

	.align	3
___func__.7407:
	.asciz	 "atomic_cas_64"

	.align	3
___func__.7438:
	.asciz	 "atomic_cas_ptr"

	.align	3
___func__.7470:
	.asciz	 "atomic_swap_8"

	.align	3
___func__.7498:
	.asciz	 "atomic_swap_uchar"

	.align	3
___func__.7526:
	.asciz	 "atomic_swap_16"

	.align	3
___func__.7554:
	.asciz	 "atomic_swap_ushort"

	.align	3
___func__.7582:
	.asciz	 "atomic_swap_32"

	.align	3
___func__.7610:
	.asciz	 "atomic_swap_uint"

	.align	3
___func__.7638:
	.asciz	 "atomic_swap_ulong"

	.align	3
___func__.7666:
	.asciz	 "atomic_swap_64"

	.align	3
___func__.7694:
	.asciz	 "atomic_swap_ptr"

	.align	3
___func__.7724:
	.asciz	 "atomic_set_long_excl"

	.align	3
___func__.7769:
	.asciz	 "atomic_clear_long_excl"

	.section	__TEXT,__eh_frame,coalesced,no_toc+strip_static_syms+live_support
EH_frame0:
Lsection_eh_frame:
Leh_frame_common:
Lset0 = Leh_frame_common_end-Leh_frame_common_begin
	.long	Lset0
Leh_frame_common_begin:
	.long	0
	.byte	1
	.asciz	 "zR"
	.byte	1
	.byte	120
	.byte	16
	.byte	1
	.byte	16
	.byte	12
	.byte	7
	.byte	8
	.byte	144
	.byte	1
	.align	3
Leh_frame_common_end:
	.globl	_atomic_inc_long.eh
_atomic_inc_long.eh:
Lset1 = Leh_frame_end1-Leh_frame_begin1
	.long	Lset1
Leh_frame_begin1:
Lset2 = Leh_frame_begin1-Leh_frame_common
	.long	Lset2
Ltmp1512:
	.quad	Leh_func_begin1-Ltmp1512
Lset3 = Leh_func_end1-Leh_func_begin1
	.quad	Lset3
	.byte	0
	.byte	4
Lset4 = Ltmp0-Leh_func_begin1
	.long	Lset4
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset5 = Ltmp1-Ltmp0
	.long	Lset5
	.byte	13
	.byte	6
	.align	3
Leh_frame_end1:

___assert_c99.eh:
Lset6 = Leh_frame_end2-Leh_frame_begin2
	.long	Lset6
Leh_frame_begin2:
Lset7 = Leh_frame_begin2-Leh_frame_common
	.long	Lset7
Ltmp1513:
	.quad	Leh_func_begin2-Ltmp1513
Lset8 = Leh_func_end2-Leh_func_begin2
	.quad	Lset8
	.byte	0
	.byte	4
Lset9 = Ltmp10-Leh_func_begin2
	.long	Lset9
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset10 = Ltmp11-Ltmp10
	.long	Lset10
	.byte	13
	.byte	6
	.align	3
Leh_frame_end2:

	.globl	_atomic_inc_8.eh
_atomic_inc_8.eh:
Lset11 = Leh_frame_end3-Leh_frame_begin3
	.long	Lset11
Leh_frame_begin3:
Lset12 = Leh_frame_begin3-Leh_frame_common
	.long	Lset12
Ltmp1514:
	.quad	Leh_func_begin3-Ltmp1514
Lset13 = Leh_func_end3-Leh_func_begin3
	.quad	Lset13
	.byte	0
	.byte	4
Lset14 = Ltmp17-Leh_func_begin3
	.long	Lset14
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset15 = Ltmp18-Ltmp17
	.long	Lset15
	.byte	13
	.byte	6
	.align	3
Leh_frame_end3:

	.globl	_atomic_inc_uchar.eh
_atomic_inc_uchar.eh:
Lset16 = Leh_frame_end4-Leh_frame_begin4
	.long	Lset16
Leh_frame_begin4:
Lset17 = Leh_frame_begin4-Leh_frame_common
	.long	Lset17
Ltmp1515:
	.quad	Leh_func_begin4-Ltmp1515
Lset18 = Leh_func_end4-Leh_func_begin4
	.quad	Lset18
	.byte	0
	.byte	4
Lset19 = Ltmp27-Leh_func_begin4
	.long	Lset19
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset20 = Ltmp28-Ltmp27
	.long	Lset20
	.byte	13
	.byte	6
	.align	3
Leh_frame_end4:

	.globl	_atomic_inc_16.eh
_atomic_inc_16.eh:
Lset21 = Leh_frame_end5-Leh_frame_begin5
	.long	Lset21
Leh_frame_begin5:
Lset22 = Leh_frame_begin5-Leh_frame_common
	.long	Lset22
Ltmp1516:
	.quad	Leh_func_begin5-Ltmp1516
Lset23 = Leh_func_end5-Leh_func_begin5
	.quad	Lset23
	.byte	0
	.byte	4
Lset24 = Ltmp37-Leh_func_begin5
	.long	Lset24
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset25 = Ltmp38-Ltmp37
	.long	Lset25
	.byte	13
	.byte	6
	.align	3
Leh_frame_end5:

	.globl	_atomic_inc_ushort.eh
_atomic_inc_ushort.eh:
Lset26 = Leh_frame_end6-Leh_frame_begin6
	.long	Lset26
Leh_frame_begin6:
Lset27 = Leh_frame_begin6-Leh_frame_common
	.long	Lset27
Ltmp1517:
	.quad	Leh_func_begin6-Ltmp1517
Lset28 = Leh_func_end6-Leh_func_begin6
	.quad	Lset28
	.byte	0
	.byte	4
Lset29 = Ltmp47-Leh_func_begin6
	.long	Lset29
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset30 = Ltmp48-Ltmp47
	.long	Lset30
	.byte	13
	.byte	6
	.align	3
Leh_frame_end6:

	.globl	_atomic_inc_32.eh
_atomic_inc_32.eh:
Lset31 = Leh_frame_end7-Leh_frame_begin7
	.long	Lset31
Leh_frame_begin7:
Lset32 = Leh_frame_begin7-Leh_frame_common
	.long	Lset32
Ltmp1518:
	.quad	Leh_func_begin7-Ltmp1518
Lset33 = Leh_func_end7-Leh_func_begin7
	.quad	Lset33
	.byte	0
	.byte	4
Lset34 = Ltmp57-Leh_func_begin7
	.long	Lset34
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset35 = Ltmp58-Ltmp57
	.long	Lset35
	.byte	13
	.byte	6
	.align	3
Leh_frame_end7:

	.globl	_atomic_inc_uint.eh
_atomic_inc_uint.eh:
Lset36 = Leh_frame_end8-Leh_frame_begin8
	.long	Lset36
Leh_frame_begin8:
Lset37 = Leh_frame_begin8-Leh_frame_common
	.long	Lset37
Ltmp1519:
	.quad	Leh_func_begin8-Ltmp1519
Lset38 = Leh_func_end8-Leh_func_begin8
	.quad	Lset38
	.byte	0
	.byte	4
Lset39 = Ltmp67-Leh_func_begin8
	.long	Lset39
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset40 = Ltmp68-Ltmp67
	.long	Lset40
	.byte	13
	.byte	6
	.align	3
Leh_frame_end8:

	.globl	_atomic_inc_ulong.eh
_atomic_inc_ulong.eh:
Lset41 = Leh_frame_end9-Leh_frame_begin9
	.long	Lset41
Leh_frame_begin9:
Lset42 = Leh_frame_begin9-Leh_frame_common
	.long	Lset42
Ltmp1520:
	.quad	Leh_func_begin9-Ltmp1520
Lset43 = Leh_func_end9-Leh_func_begin9
	.quad	Lset43
	.byte	0
	.byte	4
Lset44 = Ltmp77-Leh_func_begin9
	.long	Lset44
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset45 = Ltmp78-Ltmp77
	.long	Lset45
	.byte	13
	.byte	6
	.align	3
Leh_frame_end9:

	.globl	_atomic_inc_64.eh
_atomic_inc_64.eh:
Lset46 = Leh_frame_end10-Leh_frame_begin10
	.long	Lset46
Leh_frame_begin10:
Lset47 = Leh_frame_begin10-Leh_frame_common
	.long	Lset47
Ltmp1521:
	.quad	Leh_func_begin10-Ltmp1521
Lset48 = Leh_func_end10-Leh_func_begin10
	.quad	Lset48
	.byte	0
	.byte	4
Lset49 = Ltmp87-Leh_func_begin10
	.long	Lset49
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset50 = Ltmp88-Ltmp87
	.long	Lset50
	.byte	13
	.byte	6
	.align	3
Leh_frame_end10:

	.globl	_atomic_dec_long.eh
_atomic_dec_long.eh:
Lset51 = Leh_frame_end11-Leh_frame_begin11
	.long	Lset51
Leh_frame_begin11:
Lset52 = Leh_frame_begin11-Leh_frame_common
	.long	Lset52
Ltmp1522:
	.quad	Leh_func_begin11-Ltmp1522
Lset53 = Leh_func_end11-Leh_func_begin11
	.quad	Lset53
	.byte	0
	.byte	4
Lset54 = Ltmp97-Leh_func_begin11
	.long	Lset54
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset55 = Ltmp98-Ltmp97
	.long	Lset55
	.byte	13
	.byte	6
	.align	3
Leh_frame_end11:

	.globl	_atomic_dec_8.eh
_atomic_dec_8.eh:
Lset56 = Leh_frame_end12-Leh_frame_begin12
	.long	Lset56
Leh_frame_begin12:
Lset57 = Leh_frame_begin12-Leh_frame_common
	.long	Lset57
Ltmp1523:
	.quad	Leh_func_begin12-Ltmp1523
Lset58 = Leh_func_end12-Leh_func_begin12
	.quad	Lset58
	.byte	0
	.byte	4
Lset59 = Ltmp107-Leh_func_begin12
	.long	Lset59
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset60 = Ltmp108-Ltmp107
	.long	Lset60
	.byte	13
	.byte	6
	.align	3
Leh_frame_end12:

	.globl	_atomic_dec_uchar.eh
_atomic_dec_uchar.eh:
Lset61 = Leh_frame_end13-Leh_frame_begin13
	.long	Lset61
Leh_frame_begin13:
Lset62 = Leh_frame_begin13-Leh_frame_common
	.long	Lset62
Ltmp1524:
	.quad	Leh_func_begin13-Ltmp1524
Lset63 = Leh_func_end13-Leh_func_begin13
	.quad	Lset63
	.byte	0
	.byte	4
Lset64 = Ltmp117-Leh_func_begin13
	.long	Lset64
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset65 = Ltmp118-Ltmp117
	.long	Lset65
	.byte	13
	.byte	6
	.align	3
Leh_frame_end13:

	.globl	_atomic_dec_16.eh
_atomic_dec_16.eh:
Lset66 = Leh_frame_end14-Leh_frame_begin14
	.long	Lset66
Leh_frame_begin14:
Lset67 = Leh_frame_begin14-Leh_frame_common
	.long	Lset67
Ltmp1525:
	.quad	Leh_func_begin14-Ltmp1525
Lset68 = Leh_func_end14-Leh_func_begin14
	.quad	Lset68
	.byte	0
	.byte	4
Lset69 = Ltmp127-Leh_func_begin14
	.long	Lset69
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset70 = Ltmp128-Ltmp127
	.long	Lset70
	.byte	13
	.byte	6
	.align	3
Leh_frame_end14:

	.globl	_atomic_dec_ushort.eh
_atomic_dec_ushort.eh:
Lset71 = Leh_frame_end15-Leh_frame_begin15
	.long	Lset71
Leh_frame_begin15:
Lset72 = Leh_frame_begin15-Leh_frame_common
	.long	Lset72
Ltmp1526:
	.quad	Leh_func_begin15-Ltmp1526
Lset73 = Leh_func_end15-Leh_func_begin15
	.quad	Lset73
	.byte	0
	.byte	4
Lset74 = Ltmp137-Leh_func_begin15
	.long	Lset74
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset75 = Ltmp138-Ltmp137
	.long	Lset75
	.byte	13
	.byte	6
	.align	3
Leh_frame_end15:

	.globl	_atomic_dec_32.eh
_atomic_dec_32.eh:
Lset76 = Leh_frame_end16-Leh_frame_begin16
	.long	Lset76
Leh_frame_begin16:
Lset77 = Leh_frame_begin16-Leh_frame_common
	.long	Lset77
Ltmp1527:
	.quad	Leh_func_begin16-Ltmp1527
Lset78 = Leh_func_end16-Leh_func_begin16
	.quad	Lset78
	.byte	0
	.byte	4
Lset79 = Ltmp147-Leh_func_begin16
	.long	Lset79
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset80 = Ltmp148-Ltmp147
	.long	Lset80
	.byte	13
	.byte	6
	.align	3
Leh_frame_end16:

	.globl	_atomic_dec_uint.eh
_atomic_dec_uint.eh:
Lset81 = Leh_frame_end17-Leh_frame_begin17
	.long	Lset81
Leh_frame_begin17:
Lset82 = Leh_frame_begin17-Leh_frame_common
	.long	Lset82
Ltmp1528:
	.quad	Leh_func_begin17-Ltmp1528
Lset83 = Leh_func_end17-Leh_func_begin17
	.quad	Lset83
	.byte	0
	.byte	4
Lset84 = Ltmp157-Leh_func_begin17
	.long	Lset84
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset85 = Ltmp158-Ltmp157
	.long	Lset85
	.byte	13
	.byte	6
	.align	3
Leh_frame_end17:

	.globl	_atomic_dec_ulong.eh
_atomic_dec_ulong.eh:
Lset86 = Leh_frame_end18-Leh_frame_begin18
	.long	Lset86
Leh_frame_begin18:
Lset87 = Leh_frame_begin18-Leh_frame_common
	.long	Lset87
Ltmp1529:
	.quad	Leh_func_begin18-Ltmp1529
Lset88 = Leh_func_end18-Leh_func_begin18
	.quad	Lset88
	.byte	0
	.byte	4
Lset89 = Ltmp167-Leh_func_begin18
	.long	Lset89
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset90 = Ltmp168-Ltmp167
	.long	Lset90
	.byte	13
	.byte	6
	.align	3
Leh_frame_end18:

	.globl	_atomic_dec_64.eh
_atomic_dec_64.eh:
Lset91 = Leh_frame_end19-Leh_frame_begin19
	.long	Lset91
Leh_frame_begin19:
Lset92 = Leh_frame_begin19-Leh_frame_common
	.long	Lset92
Ltmp1530:
	.quad	Leh_func_begin19-Ltmp1530
Lset93 = Leh_func_end19-Leh_func_begin19
	.quad	Lset93
	.byte	0
	.byte	4
Lset94 = Ltmp177-Leh_func_begin19
	.long	Lset94
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset95 = Ltmp178-Ltmp177
	.long	Lset95
	.byte	13
	.byte	6
	.align	3
Leh_frame_end19:

	.globl	_atomic_add_8.eh
_atomic_add_8.eh:
Lset96 = Leh_frame_end20-Leh_frame_begin20
	.long	Lset96
Leh_frame_begin20:
Lset97 = Leh_frame_begin20-Leh_frame_common
	.long	Lset97
Ltmp1531:
	.quad	Leh_func_begin20-Ltmp1531
Lset98 = Leh_func_end20-Leh_func_begin20
	.quad	Lset98
	.byte	0
	.byte	4
Lset99 = Ltmp187-Leh_func_begin20
	.long	Lset99
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset100 = Ltmp188-Ltmp187
	.long	Lset100
	.byte	13
	.byte	6
	.align	3
Leh_frame_end20:

	.globl	_atomic_add_char.eh
_atomic_add_char.eh:
Lset101 = Leh_frame_end21-Leh_frame_begin21
	.long	Lset101
Leh_frame_begin21:
Lset102 = Leh_frame_begin21-Leh_frame_common
	.long	Lset102
Ltmp1532:
	.quad	Leh_func_begin21-Ltmp1532
Lset103 = Leh_func_end21-Leh_func_begin21
	.quad	Lset103
	.byte	0
	.byte	4
Lset104 = Ltmp197-Leh_func_begin21
	.long	Lset104
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset105 = Ltmp198-Ltmp197
	.long	Lset105
	.byte	13
	.byte	6
	.align	3
Leh_frame_end21:

	.globl	_atomic_add_16.eh
_atomic_add_16.eh:
Lset106 = Leh_frame_end22-Leh_frame_begin22
	.long	Lset106
Leh_frame_begin22:
Lset107 = Leh_frame_begin22-Leh_frame_common
	.long	Lset107
Ltmp1533:
	.quad	Leh_func_begin22-Ltmp1533
Lset108 = Leh_func_end22-Leh_func_begin22
	.quad	Lset108
	.byte	0
	.byte	4
Lset109 = Ltmp207-Leh_func_begin22
	.long	Lset109
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset110 = Ltmp208-Ltmp207
	.long	Lset110
	.byte	13
	.byte	6
	.align	3
Leh_frame_end22:

	.globl	_atomic_add_short.eh
_atomic_add_short.eh:
Lset111 = Leh_frame_end23-Leh_frame_begin23
	.long	Lset111
Leh_frame_begin23:
Lset112 = Leh_frame_begin23-Leh_frame_common
	.long	Lset112
Ltmp1534:
	.quad	Leh_func_begin23-Ltmp1534
Lset113 = Leh_func_end23-Leh_func_begin23
	.quad	Lset113
	.byte	0
	.byte	4
Lset114 = Ltmp217-Leh_func_begin23
	.long	Lset114
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset115 = Ltmp218-Ltmp217
	.long	Lset115
	.byte	13
	.byte	6
	.align	3
Leh_frame_end23:

	.globl	_atomic_add_32.eh
_atomic_add_32.eh:
Lset116 = Leh_frame_end24-Leh_frame_begin24
	.long	Lset116
Leh_frame_begin24:
Lset117 = Leh_frame_begin24-Leh_frame_common
	.long	Lset117
Ltmp1535:
	.quad	Leh_func_begin24-Ltmp1535
Lset118 = Leh_func_end24-Leh_func_begin24
	.quad	Lset118
	.byte	0
	.byte	4
Lset119 = Ltmp227-Leh_func_begin24
	.long	Lset119
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset120 = Ltmp228-Ltmp227
	.long	Lset120
	.byte	13
	.byte	6
	.align	3
Leh_frame_end24:

	.globl	_atomic_add_int.eh
_atomic_add_int.eh:
Lset121 = Leh_frame_end25-Leh_frame_begin25
	.long	Lset121
Leh_frame_begin25:
Lset122 = Leh_frame_begin25-Leh_frame_common
	.long	Lset122
Ltmp1536:
	.quad	Leh_func_begin25-Ltmp1536
Lset123 = Leh_func_end25-Leh_func_begin25
	.quad	Lset123
	.byte	0
	.byte	4
Lset124 = Ltmp237-Leh_func_begin25
	.long	Lset124
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset125 = Ltmp238-Ltmp237
	.long	Lset125
	.byte	13
	.byte	6
	.align	3
Leh_frame_end25:

	.globl	_atomic_add_long.eh
_atomic_add_long.eh:
Lset126 = Leh_frame_end26-Leh_frame_begin26
	.long	Lset126
Leh_frame_begin26:
Lset127 = Leh_frame_begin26-Leh_frame_common
	.long	Lset127
Ltmp1537:
	.quad	Leh_func_begin26-Ltmp1537
Lset128 = Leh_func_end26-Leh_func_begin26
	.quad	Lset128
	.byte	0
	.byte	4
Lset129 = Ltmp247-Leh_func_begin26
	.long	Lset129
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset130 = Ltmp248-Ltmp247
	.long	Lset130
	.byte	13
	.byte	6
	.align	3
Leh_frame_end26:

	.globl	_atomic_add_64.eh
_atomic_add_64.eh:
Lset131 = Leh_frame_end27-Leh_frame_begin27
	.long	Lset131
Leh_frame_begin27:
Lset132 = Leh_frame_begin27-Leh_frame_common
	.long	Lset132
Ltmp1538:
	.quad	Leh_func_begin27-Ltmp1538
Lset133 = Leh_func_end27-Leh_func_begin27
	.quad	Lset133
	.byte	0
	.byte	4
Lset134 = Ltmp257-Leh_func_begin27
	.long	Lset134
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset135 = Ltmp258-Ltmp257
	.long	Lset135
	.byte	13
	.byte	6
	.align	3
Leh_frame_end27:

	.globl	_atomic_add_ptr.eh
_atomic_add_ptr.eh:
Lset136 = Leh_frame_end28-Leh_frame_begin28
	.long	Lset136
Leh_frame_begin28:
Lset137 = Leh_frame_begin28-Leh_frame_common
	.long	Lset137
Ltmp1539:
	.quad	Leh_func_begin28-Ltmp1539
Lset138 = Leh_func_end28-Leh_func_begin28
	.quad	Lset138
	.byte	0
	.byte	4
Lset139 = Ltmp267-Leh_func_begin28
	.long	Lset139
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset140 = Ltmp268-Ltmp267
	.long	Lset140
	.byte	13
	.byte	6
	.align	3
Leh_frame_end28:

	.globl	_atomic_sub_8.eh
_atomic_sub_8.eh:
Lset141 = Leh_frame_end29-Leh_frame_begin29
	.long	Lset141
Leh_frame_begin29:
Lset142 = Leh_frame_begin29-Leh_frame_common
	.long	Lset142
Ltmp1540:
	.quad	Leh_func_begin29-Ltmp1540
Lset143 = Leh_func_end29-Leh_func_begin29
	.quad	Lset143
	.byte	0
	.byte	4
Lset144 = Ltmp279-Leh_func_begin29
	.long	Lset144
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset145 = Ltmp280-Ltmp279
	.long	Lset145
	.byte	13
	.byte	6
	.align	3
Leh_frame_end29:

	.globl	_atomic_sub_char.eh
_atomic_sub_char.eh:
Lset146 = Leh_frame_end30-Leh_frame_begin30
	.long	Lset146
Leh_frame_begin30:
Lset147 = Leh_frame_begin30-Leh_frame_common
	.long	Lset147
Ltmp1541:
	.quad	Leh_func_begin30-Ltmp1541
Lset148 = Leh_func_end30-Leh_func_begin30
	.quad	Lset148
	.byte	0
	.byte	4
Lset149 = Ltmp289-Leh_func_begin30
	.long	Lset149
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset150 = Ltmp290-Ltmp289
	.long	Lset150
	.byte	13
	.byte	6
	.align	3
Leh_frame_end30:

	.globl	_atomic_sub_16.eh
_atomic_sub_16.eh:
Lset151 = Leh_frame_end31-Leh_frame_begin31
	.long	Lset151
Leh_frame_begin31:
Lset152 = Leh_frame_begin31-Leh_frame_common
	.long	Lset152
Ltmp1542:
	.quad	Leh_func_begin31-Ltmp1542
Lset153 = Leh_func_end31-Leh_func_begin31
	.quad	Lset153
	.byte	0
	.byte	4
Lset154 = Ltmp299-Leh_func_begin31
	.long	Lset154
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset155 = Ltmp300-Ltmp299
	.long	Lset155
	.byte	13
	.byte	6
	.align	3
Leh_frame_end31:

	.globl	_atomic_sub_short.eh
_atomic_sub_short.eh:
Lset156 = Leh_frame_end32-Leh_frame_begin32
	.long	Lset156
Leh_frame_begin32:
Lset157 = Leh_frame_begin32-Leh_frame_common
	.long	Lset157
Ltmp1543:
	.quad	Leh_func_begin32-Ltmp1543
Lset158 = Leh_func_end32-Leh_func_begin32
	.quad	Lset158
	.byte	0
	.byte	4
Lset159 = Ltmp309-Leh_func_begin32
	.long	Lset159
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset160 = Ltmp310-Ltmp309
	.long	Lset160
	.byte	13
	.byte	6
	.align	3
Leh_frame_end32:

	.globl	_atomic_sub_32.eh
_atomic_sub_32.eh:
Lset161 = Leh_frame_end33-Leh_frame_begin33
	.long	Lset161
Leh_frame_begin33:
Lset162 = Leh_frame_begin33-Leh_frame_common
	.long	Lset162
Ltmp1544:
	.quad	Leh_func_begin33-Ltmp1544
Lset163 = Leh_func_end33-Leh_func_begin33
	.quad	Lset163
	.byte	0
	.byte	4
Lset164 = Ltmp319-Leh_func_begin33
	.long	Lset164
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset165 = Ltmp320-Ltmp319
	.long	Lset165
	.byte	13
	.byte	6
	.align	3
Leh_frame_end33:

	.globl	_atomic_sub_int.eh
_atomic_sub_int.eh:
Lset166 = Leh_frame_end34-Leh_frame_begin34
	.long	Lset166
Leh_frame_begin34:
Lset167 = Leh_frame_begin34-Leh_frame_common
	.long	Lset167
Ltmp1545:
	.quad	Leh_func_begin34-Ltmp1545
Lset168 = Leh_func_end34-Leh_func_begin34
	.quad	Lset168
	.byte	0
	.byte	4
Lset169 = Ltmp329-Leh_func_begin34
	.long	Lset169
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset170 = Ltmp330-Ltmp329
	.long	Lset170
	.byte	13
	.byte	6
	.align	3
Leh_frame_end34:

	.globl	_atomic_sub_long.eh
_atomic_sub_long.eh:
Lset171 = Leh_frame_end35-Leh_frame_begin35
	.long	Lset171
Leh_frame_begin35:
Lset172 = Leh_frame_begin35-Leh_frame_common
	.long	Lset172
Ltmp1546:
	.quad	Leh_func_begin35-Ltmp1546
Lset173 = Leh_func_end35-Leh_func_begin35
	.quad	Lset173
	.byte	0
	.byte	4
Lset174 = Ltmp339-Leh_func_begin35
	.long	Lset174
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset175 = Ltmp340-Ltmp339
	.long	Lset175
	.byte	13
	.byte	6
	.align	3
Leh_frame_end35:

	.globl	_atomic_sub_64.eh
_atomic_sub_64.eh:
Lset176 = Leh_frame_end36-Leh_frame_begin36
	.long	Lset176
Leh_frame_begin36:
Lset177 = Leh_frame_begin36-Leh_frame_common
	.long	Lset177
Ltmp1547:
	.quad	Leh_func_begin36-Ltmp1547
Lset178 = Leh_func_end36-Leh_func_begin36
	.quad	Lset178
	.byte	0
	.byte	4
Lset179 = Ltmp349-Leh_func_begin36
	.long	Lset179
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset180 = Ltmp350-Ltmp349
	.long	Lset180
	.byte	13
	.byte	6
	.align	3
Leh_frame_end36:

	.globl	_atomic_sub_ptr.eh
_atomic_sub_ptr.eh:
Lset181 = Leh_frame_end37-Leh_frame_begin37
	.long	Lset181
Leh_frame_begin37:
Lset182 = Leh_frame_begin37-Leh_frame_common
	.long	Lset182
Ltmp1548:
	.quad	Leh_func_begin37-Ltmp1548
Lset183 = Leh_func_end37-Leh_func_begin37
	.quad	Lset183
	.byte	0
	.byte	4
Lset184 = Ltmp359-Leh_func_begin37
	.long	Lset184
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset185 = Ltmp360-Ltmp359
	.long	Lset185
	.byte	13
	.byte	6
	.align	3
Leh_frame_end37:

	.globl	_atomic_or_8.eh
_atomic_or_8.eh:
Lset186 = Leh_frame_end38-Leh_frame_begin38
	.long	Lset186
Leh_frame_begin38:
Lset187 = Leh_frame_begin38-Leh_frame_common
	.long	Lset187
Ltmp1549:
	.quad	Leh_func_begin38-Ltmp1549
Lset188 = Leh_func_end38-Leh_func_begin38
	.quad	Lset188
	.byte	0
	.byte	4
Lset189 = Ltmp371-Leh_func_begin38
	.long	Lset189
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset190 = Ltmp372-Ltmp371
	.long	Lset190
	.byte	13
	.byte	6
	.align	3
Leh_frame_end38:

	.globl	_atomic_or_uchar.eh
_atomic_or_uchar.eh:
Lset191 = Leh_frame_end39-Leh_frame_begin39
	.long	Lset191
Leh_frame_begin39:
Lset192 = Leh_frame_begin39-Leh_frame_common
	.long	Lset192
Ltmp1550:
	.quad	Leh_func_begin39-Ltmp1550
Lset193 = Leh_func_end39-Leh_func_begin39
	.quad	Lset193
	.byte	0
	.byte	4
Lset194 = Ltmp381-Leh_func_begin39
	.long	Lset194
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset195 = Ltmp382-Ltmp381
	.long	Lset195
	.byte	13
	.byte	6
	.align	3
Leh_frame_end39:

	.globl	_atomic_or_16.eh
_atomic_or_16.eh:
Lset196 = Leh_frame_end40-Leh_frame_begin40
	.long	Lset196
Leh_frame_begin40:
Lset197 = Leh_frame_begin40-Leh_frame_common
	.long	Lset197
Ltmp1551:
	.quad	Leh_func_begin40-Ltmp1551
Lset198 = Leh_func_end40-Leh_func_begin40
	.quad	Lset198
	.byte	0
	.byte	4
Lset199 = Ltmp391-Leh_func_begin40
	.long	Lset199
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset200 = Ltmp392-Ltmp391
	.long	Lset200
	.byte	13
	.byte	6
	.align	3
Leh_frame_end40:

	.globl	_atomic_or_ushort.eh
_atomic_or_ushort.eh:
Lset201 = Leh_frame_end41-Leh_frame_begin41
	.long	Lset201
Leh_frame_begin41:
Lset202 = Leh_frame_begin41-Leh_frame_common
	.long	Lset202
Ltmp1552:
	.quad	Leh_func_begin41-Ltmp1552
Lset203 = Leh_func_end41-Leh_func_begin41
	.quad	Lset203
	.byte	0
	.byte	4
Lset204 = Ltmp401-Leh_func_begin41
	.long	Lset204
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset205 = Ltmp402-Ltmp401
	.long	Lset205
	.byte	13
	.byte	6
	.align	3
Leh_frame_end41:

	.globl	_atomic_or_32.eh
_atomic_or_32.eh:
Lset206 = Leh_frame_end42-Leh_frame_begin42
	.long	Lset206
Leh_frame_begin42:
Lset207 = Leh_frame_begin42-Leh_frame_common
	.long	Lset207
Ltmp1553:
	.quad	Leh_func_begin42-Ltmp1553
Lset208 = Leh_func_end42-Leh_func_begin42
	.quad	Lset208
	.byte	0
	.byte	4
Lset209 = Ltmp411-Leh_func_begin42
	.long	Lset209
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset210 = Ltmp412-Ltmp411
	.long	Lset210
	.byte	13
	.byte	6
	.align	3
Leh_frame_end42:

	.globl	_atomic_or_uint.eh
_atomic_or_uint.eh:
Lset211 = Leh_frame_end43-Leh_frame_begin43
	.long	Lset211
Leh_frame_begin43:
Lset212 = Leh_frame_begin43-Leh_frame_common
	.long	Lset212
Ltmp1554:
	.quad	Leh_func_begin43-Ltmp1554
Lset213 = Leh_func_end43-Leh_func_begin43
	.quad	Lset213
	.byte	0
	.byte	4
Lset214 = Ltmp421-Leh_func_begin43
	.long	Lset214
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset215 = Ltmp422-Ltmp421
	.long	Lset215
	.byte	13
	.byte	6
	.align	3
Leh_frame_end43:

	.globl	_atomic_or_ulong.eh
_atomic_or_ulong.eh:
Lset216 = Leh_frame_end44-Leh_frame_begin44
	.long	Lset216
Leh_frame_begin44:
Lset217 = Leh_frame_begin44-Leh_frame_common
	.long	Lset217
Ltmp1555:
	.quad	Leh_func_begin44-Ltmp1555
Lset218 = Leh_func_end44-Leh_func_begin44
	.quad	Lset218
	.byte	0
	.byte	4
Lset219 = Ltmp431-Leh_func_begin44
	.long	Lset219
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset220 = Ltmp432-Ltmp431
	.long	Lset220
	.byte	13
	.byte	6
	.align	3
Leh_frame_end44:

	.globl	_atomic_or_64.eh
_atomic_or_64.eh:
Lset221 = Leh_frame_end45-Leh_frame_begin45
	.long	Lset221
Leh_frame_begin45:
Lset222 = Leh_frame_begin45-Leh_frame_common
	.long	Lset222
Ltmp1556:
	.quad	Leh_func_begin45-Ltmp1556
Lset223 = Leh_func_end45-Leh_func_begin45
	.quad	Lset223
	.byte	0
	.byte	4
Lset224 = Ltmp441-Leh_func_begin45
	.long	Lset224
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset225 = Ltmp442-Ltmp441
	.long	Lset225
	.byte	13
	.byte	6
	.align	3
Leh_frame_end45:

	.globl	_atomic_and_8.eh
_atomic_and_8.eh:
Lset226 = Leh_frame_end46-Leh_frame_begin46
	.long	Lset226
Leh_frame_begin46:
Lset227 = Leh_frame_begin46-Leh_frame_common
	.long	Lset227
Ltmp1557:
	.quad	Leh_func_begin46-Ltmp1557
Lset228 = Leh_func_end46-Leh_func_begin46
	.quad	Lset228
	.byte	0
	.byte	4
Lset229 = Ltmp451-Leh_func_begin46
	.long	Lset229
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset230 = Ltmp452-Ltmp451
	.long	Lset230
	.byte	13
	.byte	6
	.align	3
Leh_frame_end46:

	.globl	_atomic_and_uchar.eh
_atomic_and_uchar.eh:
Lset231 = Leh_frame_end47-Leh_frame_begin47
	.long	Lset231
Leh_frame_begin47:
Lset232 = Leh_frame_begin47-Leh_frame_common
	.long	Lset232
Ltmp1558:
	.quad	Leh_func_begin47-Ltmp1558
Lset233 = Leh_func_end47-Leh_func_begin47
	.quad	Lset233
	.byte	0
	.byte	4
Lset234 = Ltmp461-Leh_func_begin47
	.long	Lset234
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset235 = Ltmp462-Ltmp461
	.long	Lset235
	.byte	13
	.byte	6
	.align	3
Leh_frame_end47:

	.globl	_atomic_and_16.eh
_atomic_and_16.eh:
Lset236 = Leh_frame_end48-Leh_frame_begin48
	.long	Lset236
Leh_frame_begin48:
Lset237 = Leh_frame_begin48-Leh_frame_common
	.long	Lset237
Ltmp1559:
	.quad	Leh_func_begin48-Ltmp1559
Lset238 = Leh_func_end48-Leh_func_begin48
	.quad	Lset238
	.byte	0
	.byte	4
Lset239 = Ltmp471-Leh_func_begin48
	.long	Lset239
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset240 = Ltmp472-Ltmp471
	.long	Lset240
	.byte	13
	.byte	6
	.align	3
Leh_frame_end48:

	.globl	_atomic_and_ushort.eh
_atomic_and_ushort.eh:
Lset241 = Leh_frame_end49-Leh_frame_begin49
	.long	Lset241
Leh_frame_begin49:
Lset242 = Leh_frame_begin49-Leh_frame_common
	.long	Lset242
Ltmp1560:
	.quad	Leh_func_begin49-Ltmp1560
Lset243 = Leh_func_end49-Leh_func_begin49
	.quad	Lset243
	.byte	0
	.byte	4
Lset244 = Ltmp481-Leh_func_begin49
	.long	Lset244
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset245 = Ltmp482-Ltmp481
	.long	Lset245
	.byte	13
	.byte	6
	.align	3
Leh_frame_end49:

	.globl	_atomic_and_32.eh
_atomic_and_32.eh:
Lset246 = Leh_frame_end50-Leh_frame_begin50
	.long	Lset246
Leh_frame_begin50:
Lset247 = Leh_frame_begin50-Leh_frame_common
	.long	Lset247
Ltmp1561:
	.quad	Leh_func_begin50-Ltmp1561
Lset248 = Leh_func_end50-Leh_func_begin50
	.quad	Lset248
	.byte	0
	.byte	4
Lset249 = Ltmp491-Leh_func_begin50
	.long	Lset249
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset250 = Ltmp492-Ltmp491
	.long	Lset250
	.byte	13
	.byte	6
	.align	3
Leh_frame_end50:

	.globl	_atomic_and_uint.eh
_atomic_and_uint.eh:
Lset251 = Leh_frame_end51-Leh_frame_begin51
	.long	Lset251
Leh_frame_begin51:
Lset252 = Leh_frame_begin51-Leh_frame_common
	.long	Lset252
Ltmp1562:
	.quad	Leh_func_begin51-Ltmp1562
Lset253 = Leh_func_end51-Leh_func_begin51
	.quad	Lset253
	.byte	0
	.byte	4
Lset254 = Ltmp501-Leh_func_begin51
	.long	Lset254
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset255 = Ltmp502-Ltmp501
	.long	Lset255
	.byte	13
	.byte	6
	.align	3
Leh_frame_end51:

	.globl	_atomic_and_ulong.eh
_atomic_and_ulong.eh:
Lset256 = Leh_frame_end52-Leh_frame_begin52
	.long	Lset256
Leh_frame_begin52:
Lset257 = Leh_frame_begin52-Leh_frame_common
	.long	Lset257
Ltmp1563:
	.quad	Leh_func_begin52-Ltmp1563
Lset258 = Leh_func_end52-Leh_func_begin52
	.quad	Lset258
	.byte	0
	.byte	4
Lset259 = Ltmp511-Leh_func_begin52
	.long	Lset259
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset260 = Ltmp512-Ltmp511
	.long	Lset260
	.byte	13
	.byte	6
	.align	3
Leh_frame_end52:

	.globl	_atomic_and_64.eh
_atomic_and_64.eh:
Lset261 = Leh_frame_end53-Leh_frame_begin53
	.long	Lset261
Leh_frame_begin53:
Lset262 = Leh_frame_begin53-Leh_frame_common
	.long	Lset262
Ltmp1564:
	.quad	Leh_func_begin53-Ltmp1564
Lset263 = Leh_func_end53-Leh_func_begin53
	.quad	Lset263
	.byte	0
	.byte	4
Lset264 = Ltmp521-Leh_func_begin53
	.long	Lset264
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset265 = Ltmp522-Ltmp521
	.long	Lset265
	.byte	13
	.byte	6
	.align	3
Leh_frame_end53:

	.globl	_atomic_inc_long_nv.eh
_atomic_inc_long_nv.eh:
Lset266 = Leh_frame_end54-Leh_frame_begin54
	.long	Lset266
Leh_frame_begin54:
Lset267 = Leh_frame_begin54-Leh_frame_common
	.long	Lset267
Ltmp1565:
	.quad	Leh_func_begin54-Ltmp1565
Lset268 = Leh_func_end54-Leh_func_begin54
	.quad	Lset268
	.byte	0
	.byte	4
Lset269 = Ltmp531-Leh_func_begin54
	.long	Lset269
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset270 = Ltmp532-Ltmp531
	.long	Lset270
	.byte	13
	.byte	6
	.align	3
Leh_frame_end54:

	.globl	_atomic_inc_8_nv.eh
_atomic_inc_8_nv.eh:
Lset271 = Leh_frame_end55-Leh_frame_begin55
	.long	Lset271
Leh_frame_begin55:
Lset272 = Leh_frame_begin55-Leh_frame_common
	.long	Lset272
Ltmp1566:
	.quad	Leh_func_begin55-Ltmp1566
Lset273 = Leh_func_end55-Leh_func_begin55
	.quad	Lset273
	.byte	0
	.byte	4
Lset274 = Ltmp543-Leh_func_begin55
	.long	Lset274
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset275 = Ltmp544-Ltmp543
	.long	Lset275
	.byte	13
	.byte	6
	.align	3
Leh_frame_end55:

	.globl	_atomic_inc_uchar_nv.eh
_atomic_inc_uchar_nv.eh:
Lset276 = Leh_frame_end56-Leh_frame_begin56
	.long	Lset276
Leh_frame_begin56:
Lset277 = Leh_frame_begin56-Leh_frame_common
	.long	Lset277
Ltmp1567:
	.quad	Leh_func_begin56-Ltmp1567
Lset278 = Leh_func_end56-Leh_func_begin56
	.quad	Lset278
	.byte	0
	.byte	4
Lset279 = Ltmp555-Leh_func_begin56
	.long	Lset279
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset280 = Ltmp556-Ltmp555
	.long	Lset280
	.byte	13
	.byte	6
	.align	3
Leh_frame_end56:

	.globl	_atomic_inc_16_nv.eh
_atomic_inc_16_nv.eh:
Lset281 = Leh_frame_end57-Leh_frame_begin57
	.long	Lset281
Leh_frame_begin57:
Lset282 = Leh_frame_begin57-Leh_frame_common
	.long	Lset282
Ltmp1568:
	.quad	Leh_func_begin57-Ltmp1568
Lset283 = Leh_func_end57-Leh_func_begin57
	.quad	Lset283
	.byte	0
	.byte	4
Lset284 = Ltmp567-Leh_func_begin57
	.long	Lset284
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset285 = Ltmp568-Ltmp567
	.long	Lset285
	.byte	13
	.byte	6
	.align	3
Leh_frame_end57:

	.globl	_atomic_inc_ushort_nv.eh
_atomic_inc_ushort_nv.eh:
Lset286 = Leh_frame_end58-Leh_frame_begin58
	.long	Lset286
Leh_frame_begin58:
Lset287 = Leh_frame_begin58-Leh_frame_common
	.long	Lset287
Ltmp1569:
	.quad	Leh_func_begin58-Ltmp1569
Lset288 = Leh_func_end58-Leh_func_begin58
	.quad	Lset288
	.byte	0
	.byte	4
Lset289 = Ltmp579-Leh_func_begin58
	.long	Lset289
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset290 = Ltmp580-Ltmp579
	.long	Lset290
	.byte	13
	.byte	6
	.align	3
Leh_frame_end58:

	.globl	_atomic_inc_32_nv.eh
_atomic_inc_32_nv.eh:
Lset291 = Leh_frame_end59-Leh_frame_begin59
	.long	Lset291
Leh_frame_begin59:
Lset292 = Leh_frame_begin59-Leh_frame_common
	.long	Lset292
Ltmp1570:
	.quad	Leh_func_begin59-Ltmp1570
Lset293 = Leh_func_end59-Leh_func_begin59
	.quad	Lset293
	.byte	0
	.byte	4
Lset294 = Ltmp591-Leh_func_begin59
	.long	Lset294
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset295 = Ltmp592-Ltmp591
	.long	Lset295
	.byte	13
	.byte	6
	.align	3
Leh_frame_end59:

	.globl	_atomic_inc_uint_nv.eh
_atomic_inc_uint_nv.eh:
Lset296 = Leh_frame_end60-Leh_frame_begin60
	.long	Lset296
Leh_frame_begin60:
Lset297 = Leh_frame_begin60-Leh_frame_common
	.long	Lset297
Ltmp1571:
	.quad	Leh_func_begin60-Ltmp1571
Lset298 = Leh_func_end60-Leh_func_begin60
	.quad	Lset298
	.byte	0
	.byte	4
Lset299 = Ltmp603-Leh_func_begin60
	.long	Lset299
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset300 = Ltmp604-Ltmp603
	.long	Lset300
	.byte	13
	.byte	6
	.align	3
Leh_frame_end60:

	.globl	_atomic_inc_ulong_nv.eh
_atomic_inc_ulong_nv.eh:
Lset301 = Leh_frame_end61-Leh_frame_begin61
	.long	Lset301
Leh_frame_begin61:
Lset302 = Leh_frame_begin61-Leh_frame_common
	.long	Lset302
Ltmp1572:
	.quad	Leh_func_begin61-Ltmp1572
Lset303 = Leh_func_end61-Leh_func_begin61
	.quad	Lset303
	.byte	0
	.byte	4
Lset304 = Ltmp615-Leh_func_begin61
	.long	Lset304
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset305 = Ltmp616-Ltmp615
	.long	Lset305
	.byte	13
	.byte	6
	.align	3
Leh_frame_end61:

	.globl	_atomic_inc_64_nv.eh
_atomic_inc_64_nv.eh:
Lset306 = Leh_frame_end62-Leh_frame_begin62
	.long	Lset306
Leh_frame_begin62:
Lset307 = Leh_frame_begin62-Leh_frame_common
	.long	Lset307
Ltmp1573:
	.quad	Leh_func_begin62-Ltmp1573
Lset308 = Leh_func_end62-Leh_func_begin62
	.quad	Lset308
	.byte	0
	.byte	4
Lset309 = Ltmp627-Leh_func_begin62
	.long	Lset309
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset310 = Ltmp628-Ltmp627
	.long	Lset310
	.byte	13
	.byte	6
	.align	3
Leh_frame_end62:

	.globl	_atomic_dec_long_nv.eh
_atomic_dec_long_nv.eh:
Lset311 = Leh_frame_end63-Leh_frame_begin63
	.long	Lset311
Leh_frame_begin63:
Lset312 = Leh_frame_begin63-Leh_frame_common
	.long	Lset312
Ltmp1574:
	.quad	Leh_func_begin63-Ltmp1574
Lset313 = Leh_func_end63-Leh_func_begin63
	.quad	Lset313
	.byte	0
	.byte	4
Lset314 = Ltmp639-Leh_func_begin63
	.long	Lset314
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset315 = Ltmp640-Ltmp639
	.long	Lset315
	.byte	13
	.byte	6
	.align	3
Leh_frame_end63:

	.globl	_atomic_dec_8_nv.eh
_atomic_dec_8_nv.eh:
Lset316 = Leh_frame_end64-Leh_frame_begin64
	.long	Lset316
Leh_frame_begin64:
Lset317 = Leh_frame_begin64-Leh_frame_common
	.long	Lset317
Ltmp1575:
	.quad	Leh_func_begin64-Ltmp1575
Lset318 = Leh_func_end64-Leh_func_begin64
	.quad	Lset318
	.byte	0
	.byte	4
Lset319 = Ltmp651-Leh_func_begin64
	.long	Lset319
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset320 = Ltmp652-Ltmp651
	.long	Lset320
	.byte	13
	.byte	6
	.align	3
Leh_frame_end64:

	.globl	_atomic_dec_uchar_nv.eh
_atomic_dec_uchar_nv.eh:
Lset321 = Leh_frame_end65-Leh_frame_begin65
	.long	Lset321
Leh_frame_begin65:
Lset322 = Leh_frame_begin65-Leh_frame_common
	.long	Lset322
Ltmp1576:
	.quad	Leh_func_begin65-Ltmp1576
Lset323 = Leh_func_end65-Leh_func_begin65
	.quad	Lset323
	.byte	0
	.byte	4
Lset324 = Ltmp663-Leh_func_begin65
	.long	Lset324
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset325 = Ltmp664-Ltmp663
	.long	Lset325
	.byte	13
	.byte	6
	.align	3
Leh_frame_end65:

	.globl	_atomic_dec_16_nv.eh
_atomic_dec_16_nv.eh:
Lset326 = Leh_frame_end66-Leh_frame_begin66
	.long	Lset326
Leh_frame_begin66:
Lset327 = Leh_frame_begin66-Leh_frame_common
	.long	Lset327
Ltmp1577:
	.quad	Leh_func_begin66-Ltmp1577
Lset328 = Leh_func_end66-Leh_func_begin66
	.quad	Lset328
	.byte	0
	.byte	4
Lset329 = Ltmp675-Leh_func_begin66
	.long	Lset329
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset330 = Ltmp676-Ltmp675
	.long	Lset330
	.byte	13
	.byte	6
	.align	3
Leh_frame_end66:

	.globl	_atomic_dec_ushort_nv.eh
_atomic_dec_ushort_nv.eh:
Lset331 = Leh_frame_end67-Leh_frame_begin67
	.long	Lset331
Leh_frame_begin67:
Lset332 = Leh_frame_begin67-Leh_frame_common
	.long	Lset332
Ltmp1578:
	.quad	Leh_func_begin67-Ltmp1578
Lset333 = Leh_func_end67-Leh_func_begin67
	.quad	Lset333
	.byte	0
	.byte	4
Lset334 = Ltmp687-Leh_func_begin67
	.long	Lset334
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset335 = Ltmp688-Ltmp687
	.long	Lset335
	.byte	13
	.byte	6
	.align	3
Leh_frame_end67:

	.globl	_atomic_dec_32_nv.eh
_atomic_dec_32_nv.eh:
Lset336 = Leh_frame_end68-Leh_frame_begin68
	.long	Lset336
Leh_frame_begin68:
Lset337 = Leh_frame_begin68-Leh_frame_common
	.long	Lset337
Ltmp1579:
	.quad	Leh_func_begin68-Ltmp1579
Lset338 = Leh_func_end68-Leh_func_begin68
	.quad	Lset338
	.byte	0
	.byte	4
Lset339 = Ltmp699-Leh_func_begin68
	.long	Lset339
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset340 = Ltmp700-Ltmp699
	.long	Lset340
	.byte	13
	.byte	6
	.align	3
Leh_frame_end68:

	.globl	_atomic_dec_uint_nv.eh
_atomic_dec_uint_nv.eh:
Lset341 = Leh_frame_end69-Leh_frame_begin69
	.long	Lset341
Leh_frame_begin69:
Lset342 = Leh_frame_begin69-Leh_frame_common
	.long	Lset342
Ltmp1580:
	.quad	Leh_func_begin69-Ltmp1580
Lset343 = Leh_func_end69-Leh_func_begin69
	.quad	Lset343
	.byte	0
	.byte	4
Lset344 = Ltmp711-Leh_func_begin69
	.long	Lset344
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset345 = Ltmp712-Ltmp711
	.long	Lset345
	.byte	13
	.byte	6
	.align	3
Leh_frame_end69:

	.globl	_atomic_dec_ulong_nv.eh
_atomic_dec_ulong_nv.eh:
Lset346 = Leh_frame_end70-Leh_frame_begin70
	.long	Lset346
Leh_frame_begin70:
Lset347 = Leh_frame_begin70-Leh_frame_common
	.long	Lset347
Ltmp1581:
	.quad	Leh_func_begin70-Ltmp1581
Lset348 = Leh_func_end70-Leh_func_begin70
	.quad	Lset348
	.byte	0
	.byte	4
Lset349 = Ltmp723-Leh_func_begin70
	.long	Lset349
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset350 = Ltmp724-Ltmp723
	.long	Lset350
	.byte	13
	.byte	6
	.align	3
Leh_frame_end70:

	.globl	_atomic_dec_64_nv.eh
_atomic_dec_64_nv.eh:
Lset351 = Leh_frame_end71-Leh_frame_begin71
	.long	Lset351
Leh_frame_begin71:
Lset352 = Leh_frame_begin71-Leh_frame_common
	.long	Lset352
Ltmp1582:
	.quad	Leh_func_begin71-Ltmp1582
Lset353 = Leh_func_end71-Leh_func_begin71
	.quad	Lset353
	.byte	0
	.byte	4
Lset354 = Ltmp735-Leh_func_begin71
	.long	Lset354
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset355 = Ltmp736-Ltmp735
	.long	Lset355
	.byte	13
	.byte	6
	.align	3
Leh_frame_end71:

	.globl	_atomic_add_8_nv.eh
_atomic_add_8_nv.eh:
Lset356 = Leh_frame_end72-Leh_frame_begin72
	.long	Lset356
Leh_frame_begin72:
Lset357 = Leh_frame_begin72-Leh_frame_common
	.long	Lset357
Ltmp1583:
	.quad	Leh_func_begin72-Ltmp1583
Lset358 = Leh_func_end72-Leh_func_begin72
	.quad	Lset358
	.byte	0
	.byte	4
Lset359 = Ltmp747-Leh_func_begin72
	.long	Lset359
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset360 = Ltmp748-Ltmp747
	.long	Lset360
	.byte	13
	.byte	6
	.align	3
Leh_frame_end72:

	.globl	_atomic_add_char_nv.eh
_atomic_add_char_nv.eh:
Lset361 = Leh_frame_end73-Leh_frame_begin73
	.long	Lset361
Leh_frame_begin73:
Lset362 = Leh_frame_begin73-Leh_frame_common
	.long	Lset362
Ltmp1584:
	.quad	Leh_func_begin73-Ltmp1584
Lset363 = Leh_func_end73-Leh_func_begin73
	.quad	Lset363
	.byte	0
	.byte	4
Lset364 = Ltmp759-Leh_func_begin73
	.long	Lset364
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset365 = Ltmp760-Ltmp759
	.long	Lset365
	.byte	13
	.byte	6
	.align	3
Leh_frame_end73:

	.globl	_atomic_add_16_nv.eh
_atomic_add_16_nv.eh:
Lset366 = Leh_frame_end74-Leh_frame_begin74
	.long	Lset366
Leh_frame_begin74:
Lset367 = Leh_frame_begin74-Leh_frame_common
	.long	Lset367
Ltmp1585:
	.quad	Leh_func_begin74-Ltmp1585
Lset368 = Leh_func_end74-Leh_func_begin74
	.quad	Lset368
	.byte	0
	.byte	4
Lset369 = Ltmp771-Leh_func_begin74
	.long	Lset369
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset370 = Ltmp772-Ltmp771
	.long	Lset370
	.byte	13
	.byte	6
	.align	3
Leh_frame_end74:

	.globl	_atomic_add_short_nv.eh
_atomic_add_short_nv.eh:
Lset371 = Leh_frame_end75-Leh_frame_begin75
	.long	Lset371
Leh_frame_begin75:
Lset372 = Leh_frame_begin75-Leh_frame_common
	.long	Lset372
Ltmp1586:
	.quad	Leh_func_begin75-Ltmp1586
Lset373 = Leh_func_end75-Leh_func_begin75
	.quad	Lset373
	.byte	0
	.byte	4
Lset374 = Ltmp783-Leh_func_begin75
	.long	Lset374
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset375 = Ltmp784-Ltmp783
	.long	Lset375
	.byte	13
	.byte	6
	.align	3
Leh_frame_end75:

	.globl	_atomic_add_32_nv.eh
_atomic_add_32_nv.eh:
Lset376 = Leh_frame_end76-Leh_frame_begin76
	.long	Lset376
Leh_frame_begin76:
Lset377 = Leh_frame_begin76-Leh_frame_common
	.long	Lset377
Ltmp1587:
	.quad	Leh_func_begin76-Ltmp1587
Lset378 = Leh_func_end76-Leh_func_begin76
	.quad	Lset378
	.byte	0
	.byte	4
Lset379 = Ltmp795-Leh_func_begin76
	.long	Lset379
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset380 = Ltmp796-Ltmp795
	.long	Lset380
	.byte	13
	.byte	6
	.align	3
Leh_frame_end76:

	.globl	_atomic_add_int_nv.eh
_atomic_add_int_nv.eh:
Lset381 = Leh_frame_end77-Leh_frame_begin77
	.long	Lset381
Leh_frame_begin77:
Lset382 = Leh_frame_begin77-Leh_frame_common
	.long	Lset382
Ltmp1588:
	.quad	Leh_func_begin77-Ltmp1588
Lset383 = Leh_func_end77-Leh_func_begin77
	.quad	Lset383
	.byte	0
	.byte	4
Lset384 = Ltmp807-Leh_func_begin77
	.long	Lset384
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset385 = Ltmp808-Ltmp807
	.long	Lset385
	.byte	13
	.byte	6
	.align	3
Leh_frame_end77:

	.globl	_atomic_add_long_nv.eh
_atomic_add_long_nv.eh:
Lset386 = Leh_frame_end78-Leh_frame_begin78
	.long	Lset386
Leh_frame_begin78:
Lset387 = Leh_frame_begin78-Leh_frame_common
	.long	Lset387
Ltmp1589:
	.quad	Leh_func_begin78-Ltmp1589
Lset388 = Leh_func_end78-Leh_func_begin78
	.quad	Lset388
	.byte	0
	.byte	4
Lset389 = Ltmp819-Leh_func_begin78
	.long	Lset389
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset390 = Ltmp820-Ltmp819
	.long	Lset390
	.byte	13
	.byte	6
	.align	3
Leh_frame_end78:

	.globl	_atomic_add_64_nv.eh
_atomic_add_64_nv.eh:
Lset391 = Leh_frame_end79-Leh_frame_begin79
	.long	Lset391
Leh_frame_begin79:
Lset392 = Leh_frame_begin79-Leh_frame_common
	.long	Lset392
Ltmp1590:
	.quad	Leh_func_begin79-Ltmp1590
Lset393 = Leh_func_end79-Leh_func_begin79
	.quad	Lset393
	.byte	0
	.byte	4
Lset394 = Ltmp831-Leh_func_begin79
	.long	Lset394
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset395 = Ltmp832-Ltmp831
	.long	Lset395
	.byte	13
	.byte	6
	.align	3
Leh_frame_end79:

	.globl	_atomic_add_ptr_nv.eh
_atomic_add_ptr_nv.eh:
Lset396 = Leh_frame_end80-Leh_frame_begin80
	.long	Lset396
Leh_frame_begin80:
Lset397 = Leh_frame_begin80-Leh_frame_common
	.long	Lset397
Ltmp1591:
	.quad	Leh_func_begin80-Ltmp1591
Lset398 = Leh_func_end80-Leh_func_begin80
	.quad	Lset398
	.byte	0
	.byte	4
Lset399 = Ltmp843-Leh_func_begin80
	.long	Lset399
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset400 = Ltmp844-Ltmp843
	.long	Lset400
	.byte	13
	.byte	6
	.align	3
Leh_frame_end80:

	.globl	_atomic_sub_8_nv.eh
_atomic_sub_8_nv.eh:
Lset401 = Leh_frame_end81-Leh_frame_begin81
	.long	Lset401
Leh_frame_begin81:
Lset402 = Leh_frame_begin81-Leh_frame_common
	.long	Lset402
Ltmp1592:
	.quad	Leh_func_begin81-Ltmp1592
Lset403 = Leh_func_end81-Leh_func_begin81
	.quad	Lset403
	.byte	0
	.byte	4
Lset404 = Ltmp856-Leh_func_begin81
	.long	Lset404
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset405 = Ltmp857-Ltmp856
	.long	Lset405
	.byte	13
	.byte	6
	.align	3
Leh_frame_end81:

	.globl	_atomic_sub_char_nv.eh
_atomic_sub_char_nv.eh:
Lset406 = Leh_frame_end82-Leh_frame_begin82
	.long	Lset406
Leh_frame_begin82:
Lset407 = Leh_frame_begin82-Leh_frame_common
	.long	Lset407
Ltmp1593:
	.quad	Leh_func_begin82-Ltmp1593
Lset408 = Leh_func_end82-Leh_func_begin82
	.quad	Lset408
	.byte	0
	.byte	4
Lset409 = Ltmp868-Leh_func_begin82
	.long	Lset409
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset410 = Ltmp869-Ltmp868
	.long	Lset410
	.byte	13
	.byte	6
	.align	3
Leh_frame_end82:

	.globl	_atomic_sub_16_nv.eh
_atomic_sub_16_nv.eh:
Lset411 = Leh_frame_end83-Leh_frame_begin83
	.long	Lset411
Leh_frame_begin83:
Lset412 = Leh_frame_begin83-Leh_frame_common
	.long	Lset412
Ltmp1594:
	.quad	Leh_func_begin83-Ltmp1594
Lset413 = Leh_func_end83-Leh_func_begin83
	.quad	Lset413
	.byte	0
	.byte	4
Lset414 = Ltmp880-Leh_func_begin83
	.long	Lset414
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset415 = Ltmp881-Ltmp880
	.long	Lset415
	.byte	13
	.byte	6
	.align	3
Leh_frame_end83:

	.globl	_atomic_sub_short_nv.eh
_atomic_sub_short_nv.eh:
Lset416 = Leh_frame_end84-Leh_frame_begin84
	.long	Lset416
Leh_frame_begin84:
Lset417 = Leh_frame_begin84-Leh_frame_common
	.long	Lset417
Ltmp1595:
	.quad	Leh_func_begin84-Ltmp1595
Lset418 = Leh_func_end84-Leh_func_begin84
	.quad	Lset418
	.byte	0
	.byte	4
Lset419 = Ltmp892-Leh_func_begin84
	.long	Lset419
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset420 = Ltmp893-Ltmp892
	.long	Lset420
	.byte	13
	.byte	6
	.align	3
Leh_frame_end84:

	.globl	_atomic_sub_32_nv.eh
_atomic_sub_32_nv.eh:
Lset421 = Leh_frame_end85-Leh_frame_begin85
	.long	Lset421
Leh_frame_begin85:
Lset422 = Leh_frame_begin85-Leh_frame_common
	.long	Lset422
Ltmp1596:
	.quad	Leh_func_begin85-Ltmp1596
Lset423 = Leh_func_end85-Leh_func_begin85
	.quad	Lset423
	.byte	0
	.byte	4
Lset424 = Ltmp904-Leh_func_begin85
	.long	Lset424
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset425 = Ltmp905-Ltmp904
	.long	Lset425
	.byte	13
	.byte	6
	.align	3
Leh_frame_end85:

	.globl	_atomic_sub_int_nv.eh
_atomic_sub_int_nv.eh:
Lset426 = Leh_frame_end86-Leh_frame_begin86
	.long	Lset426
Leh_frame_begin86:
Lset427 = Leh_frame_begin86-Leh_frame_common
	.long	Lset427
Ltmp1597:
	.quad	Leh_func_begin86-Ltmp1597
Lset428 = Leh_func_end86-Leh_func_begin86
	.quad	Lset428
	.byte	0
	.byte	4
Lset429 = Ltmp916-Leh_func_begin86
	.long	Lset429
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset430 = Ltmp917-Ltmp916
	.long	Lset430
	.byte	13
	.byte	6
	.align	3
Leh_frame_end86:

	.globl	_atomic_sub_long_nv.eh
_atomic_sub_long_nv.eh:
Lset431 = Leh_frame_end87-Leh_frame_begin87
	.long	Lset431
Leh_frame_begin87:
Lset432 = Leh_frame_begin87-Leh_frame_common
	.long	Lset432
Ltmp1598:
	.quad	Leh_func_begin87-Ltmp1598
Lset433 = Leh_func_end87-Leh_func_begin87
	.quad	Lset433
	.byte	0
	.byte	4
Lset434 = Ltmp928-Leh_func_begin87
	.long	Lset434
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset435 = Ltmp929-Ltmp928
	.long	Lset435
	.byte	13
	.byte	6
	.align	3
Leh_frame_end87:

	.globl	_atomic_sub_64_nv.eh
_atomic_sub_64_nv.eh:
Lset436 = Leh_frame_end88-Leh_frame_begin88
	.long	Lset436
Leh_frame_begin88:
Lset437 = Leh_frame_begin88-Leh_frame_common
	.long	Lset437
Ltmp1599:
	.quad	Leh_func_begin88-Ltmp1599
Lset438 = Leh_func_end88-Leh_func_begin88
	.quad	Lset438
	.byte	0
	.byte	4
Lset439 = Ltmp940-Leh_func_begin88
	.long	Lset439
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset440 = Ltmp941-Ltmp940
	.long	Lset440
	.byte	13
	.byte	6
	.align	3
Leh_frame_end88:

	.globl	_atomic_sub_ptr_nv.eh
_atomic_sub_ptr_nv.eh:
Lset441 = Leh_frame_end89-Leh_frame_begin89
	.long	Lset441
Leh_frame_begin89:
Lset442 = Leh_frame_begin89-Leh_frame_common
	.long	Lset442
Ltmp1600:
	.quad	Leh_func_begin89-Ltmp1600
Lset443 = Leh_func_end89-Leh_func_begin89
	.quad	Lset443
	.byte	0
	.byte	4
Lset444 = Ltmp952-Leh_func_begin89
	.long	Lset444
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset445 = Ltmp953-Ltmp952
	.long	Lset445
	.byte	13
	.byte	6
	.align	3
Leh_frame_end89:

	.globl	_atomic_or_long_nv.eh
_atomic_or_long_nv.eh:
Lset446 = Leh_frame_end90-Leh_frame_begin90
	.long	Lset446
Leh_frame_begin90:
Lset447 = Leh_frame_begin90-Leh_frame_common
	.long	Lset447
Ltmp1601:
	.quad	Leh_func_begin90-Ltmp1601
Lset448 = Leh_func_end90-Leh_func_begin90
	.quad	Lset448
	.byte	0
	.byte	4
Lset449 = Ltmp965-Leh_func_begin90
	.long	Lset449
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset450 = Ltmp966-Ltmp965
	.long	Lset450
	.byte	13
	.byte	6
	.align	3
Leh_frame_end90:

	.globl	_atomic_or_8_nv.eh
_atomic_or_8_nv.eh:
Lset451 = Leh_frame_end91-Leh_frame_begin91
	.long	Lset451
Leh_frame_begin91:
Lset452 = Leh_frame_begin91-Leh_frame_common
	.long	Lset452
Ltmp1602:
	.quad	Leh_func_begin91-Ltmp1602
Lset453 = Leh_func_end91-Leh_func_begin91
	.quad	Lset453
	.byte	0
	.byte	4
Lset454 = Ltmp977-Leh_func_begin91
	.long	Lset454
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset455 = Ltmp978-Ltmp977
	.long	Lset455
	.byte	13
	.byte	6
	.align	3
Leh_frame_end91:

	.globl	_atomic_or_uchar_nv.eh
_atomic_or_uchar_nv.eh:
Lset456 = Leh_frame_end92-Leh_frame_begin92
	.long	Lset456
Leh_frame_begin92:
Lset457 = Leh_frame_begin92-Leh_frame_common
	.long	Lset457
Ltmp1603:
	.quad	Leh_func_begin92-Ltmp1603
Lset458 = Leh_func_end92-Leh_func_begin92
	.quad	Lset458
	.byte	0
	.byte	4
Lset459 = Ltmp989-Leh_func_begin92
	.long	Lset459
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset460 = Ltmp990-Ltmp989
	.long	Lset460
	.byte	13
	.byte	6
	.align	3
Leh_frame_end92:

	.globl	_atomic_or_16_nv.eh
_atomic_or_16_nv.eh:
Lset461 = Leh_frame_end93-Leh_frame_begin93
	.long	Lset461
Leh_frame_begin93:
Lset462 = Leh_frame_begin93-Leh_frame_common
	.long	Lset462
Ltmp1604:
	.quad	Leh_func_begin93-Ltmp1604
Lset463 = Leh_func_end93-Leh_func_begin93
	.quad	Lset463
	.byte	0
	.byte	4
Lset464 = Ltmp1001-Leh_func_begin93
	.long	Lset464
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset465 = Ltmp1002-Ltmp1001
	.long	Lset465
	.byte	13
	.byte	6
	.align	3
Leh_frame_end93:

	.globl	_atomic_or_ushort_nv.eh
_atomic_or_ushort_nv.eh:
Lset466 = Leh_frame_end94-Leh_frame_begin94
	.long	Lset466
Leh_frame_begin94:
Lset467 = Leh_frame_begin94-Leh_frame_common
	.long	Lset467
Ltmp1605:
	.quad	Leh_func_begin94-Ltmp1605
Lset468 = Leh_func_end94-Leh_func_begin94
	.quad	Lset468
	.byte	0
	.byte	4
Lset469 = Ltmp1013-Leh_func_begin94
	.long	Lset469
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset470 = Ltmp1014-Ltmp1013
	.long	Lset470
	.byte	13
	.byte	6
	.align	3
Leh_frame_end94:

	.globl	_atomic_or_32_nv.eh
_atomic_or_32_nv.eh:
Lset471 = Leh_frame_end95-Leh_frame_begin95
	.long	Lset471
Leh_frame_begin95:
Lset472 = Leh_frame_begin95-Leh_frame_common
	.long	Lset472
Ltmp1606:
	.quad	Leh_func_begin95-Ltmp1606
Lset473 = Leh_func_end95-Leh_func_begin95
	.quad	Lset473
	.byte	0
	.byte	4
Lset474 = Ltmp1025-Leh_func_begin95
	.long	Lset474
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset475 = Ltmp1026-Ltmp1025
	.long	Lset475
	.byte	13
	.byte	6
	.align	3
Leh_frame_end95:

	.globl	_atomic_or_uint_nv.eh
_atomic_or_uint_nv.eh:
Lset476 = Leh_frame_end96-Leh_frame_begin96
	.long	Lset476
Leh_frame_begin96:
Lset477 = Leh_frame_begin96-Leh_frame_common
	.long	Lset477
Ltmp1607:
	.quad	Leh_func_begin96-Ltmp1607
Lset478 = Leh_func_end96-Leh_func_begin96
	.quad	Lset478
	.byte	0
	.byte	4
Lset479 = Ltmp1037-Leh_func_begin96
	.long	Lset479
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset480 = Ltmp1038-Ltmp1037
	.long	Lset480
	.byte	13
	.byte	6
	.align	3
Leh_frame_end96:

	.globl	_atomic_or_ulong_nv.eh
_atomic_or_ulong_nv.eh:
Lset481 = Leh_frame_end97-Leh_frame_begin97
	.long	Lset481
Leh_frame_begin97:
Lset482 = Leh_frame_begin97-Leh_frame_common
	.long	Lset482
Ltmp1608:
	.quad	Leh_func_begin97-Ltmp1608
Lset483 = Leh_func_end97-Leh_func_begin97
	.quad	Lset483
	.byte	0
	.byte	4
Lset484 = Ltmp1049-Leh_func_begin97
	.long	Lset484
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset485 = Ltmp1050-Ltmp1049
	.long	Lset485
	.byte	13
	.byte	6
	.align	3
Leh_frame_end97:

	.globl	_atomic_or_64_nv.eh
_atomic_or_64_nv.eh:
Lset486 = Leh_frame_end98-Leh_frame_begin98
	.long	Lset486
Leh_frame_begin98:
Lset487 = Leh_frame_begin98-Leh_frame_common
	.long	Lset487
Ltmp1609:
	.quad	Leh_func_begin98-Ltmp1609
Lset488 = Leh_func_end98-Leh_func_begin98
	.quad	Lset488
	.byte	0
	.byte	4
Lset489 = Ltmp1061-Leh_func_begin98
	.long	Lset489
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset490 = Ltmp1062-Ltmp1061
	.long	Lset490
	.byte	13
	.byte	6
	.align	3
Leh_frame_end98:

	.globl	_atomic_and_long_nv.eh
_atomic_and_long_nv.eh:
Lset491 = Leh_frame_end99-Leh_frame_begin99
	.long	Lset491
Leh_frame_begin99:
Lset492 = Leh_frame_begin99-Leh_frame_common
	.long	Lset492
Ltmp1610:
	.quad	Leh_func_begin99-Ltmp1610
Lset493 = Leh_func_end99-Leh_func_begin99
	.quad	Lset493
	.byte	0
	.byte	4
Lset494 = Ltmp1073-Leh_func_begin99
	.long	Lset494
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset495 = Ltmp1074-Ltmp1073
	.long	Lset495
	.byte	13
	.byte	6
	.align	3
Leh_frame_end99:

	.globl	_atomic_and_8_nv.eh
_atomic_and_8_nv.eh:
Lset496 = Leh_frame_end100-Leh_frame_begin100
	.long	Lset496
Leh_frame_begin100:
Lset497 = Leh_frame_begin100-Leh_frame_common
	.long	Lset497
Ltmp1611:
	.quad	Leh_func_begin100-Ltmp1611
Lset498 = Leh_func_end100-Leh_func_begin100
	.quad	Lset498
	.byte	0
	.byte	4
Lset499 = Ltmp1085-Leh_func_begin100
	.long	Lset499
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset500 = Ltmp1086-Ltmp1085
	.long	Lset500
	.byte	13
	.byte	6
	.align	3
Leh_frame_end100:

	.globl	_atomic_and_uchar_nv.eh
_atomic_and_uchar_nv.eh:
Lset501 = Leh_frame_end101-Leh_frame_begin101
	.long	Lset501
Leh_frame_begin101:
Lset502 = Leh_frame_begin101-Leh_frame_common
	.long	Lset502
Ltmp1612:
	.quad	Leh_func_begin101-Ltmp1612
Lset503 = Leh_func_end101-Leh_func_begin101
	.quad	Lset503
	.byte	0
	.byte	4
Lset504 = Ltmp1097-Leh_func_begin101
	.long	Lset504
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset505 = Ltmp1098-Ltmp1097
	.long	Lset505
	.byte	13
	.byte	6
	.align	3
Leh_frame_end101:

	.globl	_atomic_and_16_nv.eh
_atomic_and_16_nv.eh:
Lset506 = Leh_frame_end102-Leh_frame_begin102
	.long	Lset506
Leh_frame_begin102:
Lset507 = Leh_frame_begin102-Leh_frame_common
	.long	Lset507
Ltmp1613:
	.quad	Leh_func_begin102-Ltmp1613
Lset508 = Leh_func_end102-Leh_func_begin102
	.quad	Lset508
	.byte	0
	.byte	4
Lset509 = Ltmp1109-Leh_func_begin102
	.long	Lset509
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset510 = Ltmp1110-Ltmp1109
	.long	Lset510
	.byte	13
	.byte	6
	.align	3
Leh_frame_end102:

	.globl	_atomic_and_ushort_nv.eh
_atomic_and_ushort_nv.eh:
Lset511 = Leh_frame_end103-Leh_frame_begin103
	.long	Lset511
Leh_frame_begin103:
Lset512 = Leh_frame_begin103-Leh_frame_common
	.long	Lset512
Ltmp1614:
	.quad	Leh_func_begin103-Ltmp1614
Lset513 = Leh_func_end103-Leh_func_begin103
	.quad	Lset513
	.byte	0
	.byte	4
Lset514 = Ltmp1121-Leh_func_begin103
	.long	Lset514
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset515 = Ltmp1122-Ltmp1121
	.long	Lset515
	.byte	13
	.byte	6
	.align	3
Leh_frame_end103:

	.globl	_atomic_and_32_nv.eh
_atomic_and_32_nv.eh:
Lset516 = Leh_frame_end104-Leh_frame_begin104
	.long	Lset516
Leh_frame_begin104:
Lset517 = Leh_frame_begin104-Leh_frame_common
	.long	Lset517
Ltmp1615:
	.quad	Leh_func_begin104-Ltmp1615
Lset518 = Leh_func_end104-Leh_func_begin104
	.quad	Lset518
	.byte	0
	.byte	4
Lset519 = Ltmp1133-Leh_func_begin104
	.long	Lset519
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset520 = Ltmp1134-Ltmp1133
	.long	Lset520
	.byte	13
	.byte	6
	.align	3
Leh_frame_end104:

	.globl	_atomic_and_uint_nv.eh
_atomic_and_uint_nv.eh:
Lset521 = Leh_frame_end105-Leh_frame_begin105
	.long	Lset521
Leh_frame_begin105:
Lset522 = Leh_frame_begin105-Leh_frame_common
	.long	Lset522
Ltmp1616:
	.quad	Leh_func_begin105-Ltmp1616
Lset523 = Leh_func_end105-Leh_func_begin105
	.quad	Lset523
	.byte	0
	.byte	4
Lset524 = Ltmp1145-Leh_func_begin105
	.long	Lset524
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset525 = Ltmp1146-Ltmp1145
	.long	Lset525
	.byte	13
	.byte	6
	.align	3
Leh_frame_end105:

	.globl	_atomic_and_ulong_nv.eh
_atomic_and_ulong_nv.eh:
Lset526 = Leh_frame_end106-Leh_frame_begin106
	.long	Lset526
Leh_frame_begin106:
Lset527 = Leh_frame_begin106-Leh_frame_common
	.long	Lset527
Ltmp1617:
	.quad	Leh_func_begin106-Ltmp1617
Lset528 = Leh_func_end106-Leh_func_begin106
	.quad	Lset528
	.byte	0
	.byte	4
Lset529 = Ltmp1157-Leh_func_begin106
	.long	Lset529
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset530 = Ltmp1158-Ltmp1157
	.long	Lset530
	.byte	13
	.byte	6
	.align	3
Leh_frame_end106:

	.globl	_atomic_and_64_nv.eh
_atomic_and_64_nv.eh:
Lset531 = Leh_frame_end107-Leh_frame_begin107
	.long	Lset531
Leh_frame_begin107:
Lset532 = Leh_frame_begin107-Leh_frame_common
	.long	Lset532
Ltmp1618:
	.quad	Leh_func_begin107-Ltmp1618
Lset533 = Leh_func_end107-Leh_func_begin107
	.quad	Lset533
	.byte	0
	.byte	4
Lset534 = Ltmp1169-Leh_func_begin107
	.long	Lset534
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset535 = Ltmp1170-Ltmp1169
	.long	Lset535
	.byte	13
	.byte	6
	.align	3
Leh_frame_end107:

	.globl	_atomic_cas_8.eh
_atomic_cas_8.eh:
Lset536 = Leh_frame_end108-Leh_frame_begin108
	.long	Lset536
Leh_frame_begin108:
Lset537 = Leh_frame_begin108-Leh_frame_common
	.long	Lset537
Ltmp1619:
	.quad	Leh_func_begin108-Ltmp1619
Lset538 = Leh_func_end108-Leh_func_begin108
	.quad	Lset538
	.byte	0
	.byte	4
Lset539 = Ltmp1181-Leh_func_begin108
	.long	Lset539
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset540 = Ltmp1182-Ltmp1181
	.long	Lset540
	.byte	13
	.byte	6
	.align	3
Leh_frame_end108:

	.globl	_atomic_cas_uchar.eh
_atomic_cas_uchar.eh:
Lset541 = Leh_frame_end109-Leh_frame_begin109
	.long	Lset541
Leh_frame_begin109:
Lset542 = Leh_frame_begin109-Leh_frame_common
	.long	Lset542
Ltmp1620:
	.quad	Leh_func_begin109-Ltmp1620
Lset543 = Leh_func_end109-Leh_func_begin109
	.quad	Lset543
	.byte	0
	.byte	4
Lset544 = Ltmp1194-Leh_func_begin109
	.long	Lset544
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset545 = Ltmp1195-Ltmp1194
	.long	Lset545
	.byte	13
	.byte	6
	.align	3
Leh_frame_end109:

	.globl	_atomic_cas_16.eh
_atomic_cas_16.eh:
Lset546 = Leh_frame_end110-Leh_frame_begin110
	.long	Lset546
Leh_frame_begin110:
Lset547 = Leh_frame_begin110-Leh_frame_common
	.long	Lset547
Ltmp1621:
	.quad	Leh_func_begin110-Ltmp1621
Lset548 = Leh_func_end110-Leh_func_begin110
	.quad	Lset548
	.byte	0
	.byte	4
Lset549 = Ltmp1207-Leh_func_begin110
	.long	Lset549
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset550 = Ltmp1208-Ltmp1207
	.long	Lset550
	.byte	13
	.byte	6
	.align	3
Leh_frame_end110:

	.globl	_atomic_cas_ushort.eh
_atomic_cas_ushort.eh:
Lset551 = Leh_frame_end111-Leh_frame_begin111
	.long	Lset551
Leh_frame_begin111:
Lset552 = Leh_frame_begin111-Leh_frame_common
	.long	Lset552
Ltmp1622:
	.quad	Leh_func_begin111-Ltmp1622
Lset553 = Leh_func_end111-Leh_func_begin111
	.quad	Lset553
	.byte	0
	.byte	4
Lset554 = Ltmp1220-Leh_func_begin111
	.long	Lset554
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset555 = Ltmp1221-Ltmp1220
	.long	Lset555
	.byte	13
	.byte	6
	.align	3
Leh_frame_end111:

	.globl	_atomic_cas_32.eh
_atomic_cas_32.eh:
Lset556 = Leh_frame_end112-Leh_frame_begin112
	.long	Lset556
Leh_frame_begin112:
Lset557 = Leh_frame_begin112-Leh_frame_common
	.long	Lset557
Ltmp1623:
	.quad	Leh_func_begin112-Ltmp1623
Lset558 = Leh_func_end112-Leh_func_begin112
	.quad	Lset558
	.byte	0
	.byte	4
Lset559 = Ltmp1233-Leh_func_begin112
	.long	Lset559
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset560 = Ltmp1234-Ltmp1233
	.long	Lset560
	.byte	13
	.byte	6
	.align	3
Leh_frame_end112:

	.globl	_atomic_cas_uint.eh
_atomic_cas_uint.eh:
Lset561 = Leh_frame_end113-Leh_frame_begin113
	.long	Lset561
Leh_frame_begin113:
Lset562 = Leh_frame_begin113-Leh_frame_common
	.long	Lset562
Ltmp1624:
	.quad	Leh_func_begin113-Ltmp1624
Lset563 = Leh_func_end113-Leh_func_begin113
	.quad	Lset563
	.byte	0
	.byte	4
Lset564 = Ltmp1246-Leh_func_begin113
	.long	Lset564
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset565 = Ltmp1247-Ltmp1246
	.long	Lset565
	.byte	13
	.byte	6
	.align	3
Leh_frame_end113:

	.globl	_atomic_cas_ulong.eh
_atomic_cas_ulong.eh:
Lset566 = Leh_frame_end114-Leh_frame_begin114
	.long	Lset566
Leh_frame_begin114:
Lset567 = Leh_frame_begin114-Leh_frame_common
	.long	Lset567
Ltmp1625:
	.quad	Leh_func_begin114-Ltmp1625
Lset568 = Leh_func_end114-Leh_func_begin114
	.quad	Lset568
	.byte	0
	.byte	4
Lset569 = Ltmp1259-Leh_func_begin114
	.long	Lset569
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset570 = Ltmp1260-Ltmp1259
	.long	Lset570
	.byte	13
	.byte	6
	.align	3
Leh_frame_end114:

	.globl	_atomic_cas_64.eh
_atomic_cas_64.eh:
Lset571 = Leh_frame_end115-Leh_frame_begin115
	.long	Lset571
Leh_frame_begin115:
Lset572 = Leh_frame_begin115-Leh_frame_common
	.long	Lset572
Ltmp1626:
	.quad	Leh_func_begin115-Ltmp1626
Lset573 = Leh_func_end115-Leh_func_begin115
	.quad	Lset573
	.byte	0
	.byte	4
Lset574 = Ltmp1272-Leh_func_begin115
	.long	Lset574
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset575 = Ltmp1273-Ltmp1272
	.long	Lset575
	.byte	13
	.byte	6
	.align	3
Leh_frame_end115:

	.globl	_atomic_cas_ptr.eh
_atomic_cas_ptr.eh:
Lset576 = Leh_frame_end116-Leh_frame_begin116
	.long	Lset576
Leh_frame_begin116:
Lset577 = Leh_frame_begin116-Leh_frame_common
	.long	Lset577
Ltmp1627:
	.quad	Leh_func_begin116-Ltmp1627
Lset578 = Leh_func_end116-Leh_func_begin116
	.quad	Lset578
	.byte	0
	.byte	4
Lset579 = Ltmp1285-Leh_func_begin116
	.long	Lset579
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset580 = Ltmp1286-Ltmp1285
	.long	Lset580
	.byte	13
	.byte	6
	.align	3
Leh_frame_end116:

	.globl	_atomic_swap_8.eh
_atomic_swap_8.eh:
Lset581 = Leh_frame_end117-Leh_frame_begin117
	.long	Lset581
Leh_frame_begin117:
Lset582 = Leh_frame_begin117-Leh_frame_common
	.long	Lset582
Ltmp1628:
	.quad	Leh_func_begin117-Ltmp1628
Lset583 = Leh_func_end117-Leh_func_begin117
	.quad	Lset583
	.byte	0
	.byte	4
Lset584 = Ltmp1300-Leh_func_begin117
	.long	Lset584
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset585 = Ltmp1301-Ltmp1300
	.long	Lset585
	.byte	13
	.byte	6
	.align	3
Leh_frame_end117:

	.globl	_atomic_swap_uchar.eh
_atomic_swap_uchar.eh:
Lset586 = Leh_frame_end118-Leh_frame_begin118
	.long	Lset586
Leh_frame_begin118:
Lset587 = Leh_frame_begin118-Leh_frame_common
	.long	Lset587
Ltmp1629:
	.quad	Leh_func_begin118-Ltmp1629
Lset588 = Leh_func_end118-Leh_func_begin118
	.quad	Lset588
	.byte	0
	.byte	4
Lset589 = Ltmp1312-Leh_func_begin118
	.long	Lset589
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset590 = Ltmp1313-Ltmp1312
	.long	Lset590
	.byte	13
	.byte	6
	.align	3
Leh_frame_end118:

	.globl	_atomic_swap_16.eh
_atomic_swap_16.eh:
Lset591 = Leh_frame_end119-Leh_frame_begin119
	.long	Lset591
Leh_frame_begin119:
Lset592 = Leh_frame_begin119-Leh_frame_common
	.long	Lset592
Ltmp1630:
	.quad	Leh_func_begin119-Ltmp1630
Lset593 = Leh_func_end119-Leh_func_begin119
	.quad	Lset593
	.byte	0
	.byte	4
Lset594 = Ltmp1324-Leh_func_begin119
	.long	Lset594
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset595 = Ltmp1325-Ltmp1324
	.long	Lset595
	.byte	13
	.byte	6
	.align	3
Leh_frame_end119:

	.globl	_atomic_swap_ushort.eh
_atomic_swap_ushort.eh:
Lset596 = Leh_frame_end120-Leh_frame_begin120
	.long	Lset596
Leh_frame_begin120:
Lset597 = Leh_frame_begin120-Leh_frame_common
	.long	Lset597
Ltmp1631:
	.quad	Leh_func_begin120-Ltmp1631
Lset598 = Leh_func_end120-Leh_func_begin120
	.quad	Lset598
	.byte	0
	.byte	4
Lset599 = Ltmp1336-Leh_func_begin120
	.long	Lset599
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset600 = Ltmp1337-Ltmp1336
	.long	Lset600
	.byte	13
	.byte	6
	.align	3
Leh_frame_end120:

	.globl	_atomic_swap_32.eh
_atomic_swap_32.eh:
Lset601 = Leh_frame_end121-Leh_frame_begin121
	.long	Lset601
Leh_frame_begin121:
Lset602 = Leh_frame_begin121-Leh_frame_common
	.long	Lset602
Ltmp1632:
	.quad	Leh_func_begin121-Ltmp1632
Lset603 = Leh_func_end121-Leh_func_begin121
	.quad	Lset603
	.byte	0
	.byte	4
Lset604 = Ltmp1348-Leh_func_begin121
	.long	Lset604
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset605 = Ltmp1349-Ltmp1348
	.long	Lset605
	.byte	13
	.byte	6
	.align	3
Leh_frame_end121:

	.globl	_atomic_swap_uint.eh
_atomic_swap_uint.eh:
Lset606 = Leh_frame_end122-Leh_frame_begin122
	.long	Lset606
Leh_frame_begin122:
Lset607 = Leh_frame_begin122-Leh_frame_common
	.long	Lset607
Ltmp1633:
	.quad	Leh_func_begin122-Ltmp1633
Lset608 = Leh_func_end122-Leh_func_begin122
	.quad	Lset608
	.byte	0
	.byte	4
Lset609 = Ltmp1360-Leh_func_begin122
	.long	Lset609
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset610 = Ltmp1361-Ltmp1360
	.long	Lset610
	.byte	13
	.byte	6
	.align	3
Leh_frame_end122:

	.globl	_atomic_swap_ulong.eh
_atomic_swap_ulong.eh:
Lset611 = Leh_frame_end123-Leh_frame_begin123
	.long	Lset611
Leh_frame_begin123:
Lset612 = Leh_frame_begin123-Leh_frame_common
	.long	Lset612
Ltmp1634:
	.quad	Leh_func_begin123-Ltmp1634
Lset613 = Leh_func_end123-Leh_func_begin123
	.quad	Lset613
	.byte	0
	.byte	4
Lset614 = Ltmp1372-Leh_func_begin123
	.long	Lset614
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset615 = Ltmp1373-Ltmp1372
	.long	Lset615
	.byte	13
	.byte	6
	.align	3
Leh_frame_end123:

	.globl	_atomic_swap_64.eh
_atomic_swap_64.eh:
Lset616 = Leh_frame_end124-Leh_frame_begin124
	.long	Lset616
Leh_frame_begin124:
Lset617 = Leh_frame_begin124-Leh_frame_common
	.long	Lset617
Ltmp1635:
	.quad	Leh_func_begin124-Ltmp1635
Lset618 = Leh_func_end124-Leh_func_begin124
	.quad	Lset618
	.byte	0
	.byte	4
Lset619 = Ltmp1384-Leh_func_begin124
	.long	Lset619
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset620 = Ltmp1385-Ltmp1384
	.long	Lset620
	.byte	13
	.byte	6
	.align	3
Leh_frame_end124:

	.globl	_atomic_swap_ptr.eh
_atomic_swap_ptr.eh:
Lset621 = Leh_frame_end125-Leh_frame_begin125
	.long	Lset621
Leh_frame_begin125:
Lset622 = Leh_frame_begin125-Leh_frame_common
	.long	Lset622
Ltmp1636:
	.quad	Leh_func_begin125-Ltmp1636
Lset623 = Leh_func_end125-Leh_func_begin125
	.quad	Lset623
	.byte	0
	.byte	4
Lset624 = Ltmp1396-Leh_func_begin125
	.long	Lset624
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset625 = Ltmp1397-Ltmp1396
	.long	Lset625
	.byte	13
	.byte	6
	.align	3
Leh_frame_end125:

	.globl	_atomic_set_long_excl.eh
_atomic_set_long_excl.eh:
Lset626 = Leh_frame_end126-Leh_frame_begin126
	.long	Lset626
Leh_frame_begin126:
Lset627 = Leh_frame_begin126-Leh_frame_common
	.long	Lset627
Ltmp1637:
	.quad	Leh_func_begin126-Ltmp1637
Lset628 = Leh_func_end126-Leh_func_begin126
	.quad	Lset628
	.byte	0
	.byte	4
Lset629 = Ltmp1410-Leh_func_begin126
	.long	Lset629
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset630 = Ltmp1411-Ltmp1410
	.long	Lset630
	.byte	13
	.byte	6
	.align	3
Leh_frame_end126:

	.globl	_atomic_clear_long_excl.eh
_atomic_clear_long_excl.eh:
Lset631 = Leh_frame_end127-Leh_frame_begin127
	.long	Lset631
Leh_frame_begin127:
Lset632 = Leh_frame_begin127-Leh_frame_common
	.long	Lset632
Ltmp1638:
	.quad	Leh_func_begin127-Ltmp1638
Lset633 = Leh_func_end127-Leh_func_begin127
	.quad	Lset633
	.byte	0
	.byte	4
Lset634 = Ltmp1430-Leh_func_begin127
	.long	Lset634
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset635 = Ltmp1431-Ltmp1430
	.long	Lset635
	.byte	13
	.byte	6
	.align	3
Leh_frame_end127:

	.globl	_membar_enter.eh
_membar_enter.eh:
Lset636 = Leh_frame_end128-Leh_frame_begin128
	.long	Lset636
Leh_frame_begin128:
Lset637 = Leh_frame_begin128-Leh_frame_common
	.long	Lset637
Ltmp1639:
	.quad	Leh_func_begin128-Ltmp1639
Lset638 = Leh_func_end128-Leh_func_begin128
	.quad	Lset638
	.byte	0
	.byte	4
Lset639 = Ltmp1450-Leh_func_begin128
	.long	Lset639
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset640 = Ltmp1451-Ltmp1450
	.long	Lset640
	.byte	13
	.byte	6
	.align	3
Leh_frame_end128:

	.globl	_membar_exit.eh
_membar_exit.eh:
Lset641 = Leh_frame_end129-Leh_frame_begin129
	.long	Lset641
Leh_frame_begin129:
Lset642 = Leh_frame_begin129-Leh_frame_common
	.long	Lset642
Ltmp1640:
	.quad	Leh_func_begin129-Ltmp1640
Lset643 = Leh_func_end129-Leh_func_begin129
	.quad	Lset643
	.byte	0
	.byte	4
Lset644 = Ltmp1455-Leh_func_begin129
	.long	Lset644
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset645 = Ltmp1456-Ltmp1455
	.long	Lset645
	.byte	13
	.byte	6
	.align	3
Leh_frame_end129:

	.globl	_membar_producer.eh
_membar_producer.eh:
Lset646 = Leh_frame_end130-Leh_frame_begin130
	.long	Lset646
Leh_frame_begin130:
Lset647 = Leh_frame_begin130-Leh_frame_common
	.long	Lset647
Ltmp1641:
	.quad	Leh_func_begin130-Ltmp1641
Lset648 = Leh_func_end130-Leh_func_begin130
	.quad	Lset648
	.byte	0
	.byte	4
Lset649 = Ltmp1460-Leh_func_begin130
	.long	Lset649
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset650 = Ltmp1461-Ltmp1460
	.long	Lset650
	.byte	13
	.byte	6
	.align	3
Leh_frame_end130:

	.globl	_membar_consumer.eh
_membar_consumer.eh:
Lset651 = Leh_frame_end131-Leh_frame_begin131
	.long	Lset651
Leh_frame_begin131:
Lset652 = Leh_frame_begin131-Leh_frame_common
	.long	Lset652
Ltmp1642:
	.quad	Leh_func_begin131-Ltmp1642
Lset653 = Leh_func_end131-Leh_func_begin131
	.quad	Lset653
	.byte	0
	.byte	4
Lset654 = Ltmp1465-Leh_func_begin131
	.long	Lset654
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset655 = Ltmp1466-Ltmp1465
	.long	Lset655
	.byte	13
	.byte	6
	.align	3
Leh_frame_end131:

	.globl	_cas8.eh
_cas8.eh:
Lset656 = Leh_frame_end132-Leh_frame_begin132
	.long	Lset656
Leh_frame_begin132:
Lset657 = Leh_frame_begin132-Leh_frame_common
	.long	Lset657
Ltmp1643:
	.quad	Leh_func_begin132-Ltmp1643
Lset658 = Leh_func_end132-Leh_func_begin132
	.quad	Lset658
	.byte	0
	.byte	4
Lset659 = Ltmp1470-Leh_func_begin132
	.long	Lset659
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset660 = Ltmp1471-Ltmp1470
	.long	Lset660
	.byte	13
	.byte	6
	.align	3
Leh_frame_end132:

	.globl	_cas32.eh
_cas32.eh:
Lset661 = Leh_frame_end133-Leh_frame_begin133
	.long	Lset661
Leh_frame_begin133:
Lset662 = Leh_frame_begin133-Leh_frame_common
	.long	Lset662
Ltmp1644:
	.quad	Leh_func_begin133-Ltmp1644
Lset663 = Leh_func_end133-Leh_func_begin133
	.quad	Lset663
	.byte	0
	.byte	4
Lset664 = Ltmp1476-Leh_func_begin133
	.long	Lset664
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset665 = Ltmp1477-Ltmp1476
	.long	Lset665
	.byte	13
	.byte	6
	.align	3
Leh_frame_end133:

	.globl	_cas64.eh
_cas64.eh:
Lset666 = Leh_frame_end134-Leh_frame_begin134
	.long	Lset666
Leh_frame_begin134:
Lset667 = Leh_frame_begin134-Leh_frame_common
	.long	Lset667
Ltmp1645:
	.quad	Leh_func_begin134-Ltmp1645
Lset668 = Leh_func_end134-Leh_func_begin134
	.quad	Lset668
	.byte	0
	.byte	4
Lset669 = Ltmp1482-Leh_func_begin134
	.long	Lset669
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset670 = Ltmp1483-Ltmp1482
	.long	Lset670
	.byte	13
	.byte	6
	.align	3
Leh_frame_end134:

	.globl	_caslong.eh
_caslong.eh:
Lset671 = Leh_frame_end135-Leh_frame_begin135
	.long	Lset671
Leh_frame_begin135:
Lset672 = Leh_frame_begin135-Leh_frame_common
	.long	Lset672
Ltmp1646:
	.quad	Leh_func_begin135-Ltmp1646
Lset673 = Leh_func_end135-Leh_func_begin135
	.quad	Lset673
	.byte	0
	.byte	4
Lset674 = Ltmp1488-Leh_func_begin135
	.long	Lset674
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset675 = Ltmp1489-Ltmp1488
	.long	Lset675
	.byte	13
	.byte	6
	.align	3
Leh_frame_end135:

	.globl	_casptr.eh
_casptr.eh:
Lset676 = Leh_frame_end136-Leh_frame_begin136
	.long	Lset676
Leh_frame_begin136:
Lset677 = Leh_frame_begin136-Leh_frame_common
	.long	Lset677
Ltmp1647:
	.quad	Leh_func_begin136-Ltmp1647
Lset678 = Leh_func_end136-Leh_func_begin136
	.quad	Lset678
	.byte	0
	.byte	4
Lset679 = Ltmp1494-Leh_func_begin136
	.long	Lset679
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset680 = Ltmp1495-Ltmp1494
	.long	Lset680
	.byte	13
	.byte	6
	.align	3
Leh_frame_end136:

	.globl	_atomic_and_long.eh
_atomic_and_long.eh:
Lset681 = Leh_frame_end137-Leh_frame_begin137
	.long	Lset681
Leh_frame_begin137:
Lset682 = Leh_frame_begin137-Leh_frame_common
	.long	Lset682
Ltmp1648:
	.quad	Leh_func_begin137-Ltmp1648
Lset683 = Leh_func_end137-Leh_func_begin137
	.quad	Lset683
	.byte	0
	.byte	4
Lset684 = Ltmp1500-Leh_func_begin137
	.long	Lset684
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset685 = Ltmp1501-Ltmp1500
	.long	Lset685
	.byte	13
	.byte	6
	.align	3
Leh_frame_end137:

	.globl	_atomic_or_long.eh
_atomic_or_long.eh:
Lset686 = Leh_frame_end138-Leh_frame_begin138
	.long	Lset686
Leh_frame_begin138:
Lset687 = Leh_frame_begin138-Leh_frame_common
	.long	Lset687
Ltmp1649:
	.quad	Leh_func_begin138-Ltmp1649
Lset688 = Leh_func_end138-Leh_func_begin138
	.quad	Lset688
	.byte	0
	.byte	4
Lset689 = Ltmp1506-Leh_func_begin138
	.long	Lset689
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset690 = Ltmp1507-Ltmp1506
	.long	Lset690
	.byte	13
	.byte	6
	.align	3
Leh_frame_end138:

	.section	__TEXT,__text,regular,pure_instructions
Ltext_end:
	.section	__DATA,__data
Ldata_end:
	.section	__TEXT,__text,regular,pure_instructions
Lsection_end1:
	.section	__DWARF,__debug_frame,regular,debug
Ldebug_frame_common:
Lset691 = Ldebug_frame_common_end-Ldebug_frame_common_begin
	.long	Lset691
Ldebug_frame_common_begin:
	.long	4294967295
	.byte	1
	.byte	0
	.byte	1
	.byte	120
	.byte	16
	.byte	12
	.byte	7
	.byte	8
	.byte	144
	.byte	1
	.align	2
Ldebug_frame_common_end:
Lset692 = Ldebug_frame_end1-Ldebug_frame_begin1
	.long	Lset692
Ldebug_frame_begin1:
Lset693 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset693
	.quad	Lfunc_begin1
Lset694 = Lfunc_end1-Lfunc_begin1
	.quad	Lset694
	.byte	4
Lset695 = Ltmp0-Lfunc_begin1
	.long	Lset695
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset696 = Ltmp1-Ltmp0
	.long	Lset696
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end1:
Lset697 = Ldebug_frame_end2-Ldebug_frame_begin2
	.long	Lset697
Ldebug_frame_begin2:
Lset698 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset698
	.quad	Lfunc_begin2
Lset699 = Lfunc_end2-Lfunc_begin2
	.quad	Lset699
	.byte	4
Lset700 = Ltmp10-Lfunc_begin2
	.long	Lset700
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset701 = Ltmp11-Ltmp10
	.long	Lset701
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end2:
Lset702 = Ldebug_frame_end3-Ldebug_frame_begin3
	.long	Lset702
Ldebug_frame_begin3:
Lset703 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset703
	.quad	Lfunc_begin3
Lset704 = Lfunc_end3-Lfunc_begin3
	.quad	Lset704
	.byte	4
Lset705 = Ltmp17-Lfunc_begin3
	.long	Lset705
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset706 = Ltmp18-Ltmp17
	.long	Lset706
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end3:
Lset707 = Ldebug_frame_end4-Ldebug_frame_begin4
	.long	Lset707
Ldebug_frame_begin4:
Lset708 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset708
	.quad	Lfunc_begin4
Lset709 = Lfunc_end4-Lfunc_begin4
	.quad	Lset709
	.byte	4
Lset710 = Ltmp27-Lfunc_begin4
	.long	Lset710
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset711 = Ltmp28-Ltmp27
	.long	Lset711
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end4:
Lset712 = Ldebug_frame_end5-Ldebug_frame_begin5
	.long	Lset712
Ldebug_frame_begin5:
Lset713 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset713
	.quad	Lfunc_begin5
Lset714 = Lfunc_end5-Lfunc_begin5
	.quad	Lset714
	.byte	4
Lset715 = Ltmp37-Lfunc_begin5
	.long	Lset715
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset716 = Ltmp38-Ltmp37
	.long	Lset716
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end5:
Lset717 = Ldebug_frame_end6-Ldebug_frame_begin6
	.long	Lset717
Ldebug_frame_begin6:
Lset718 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset718
	.quad	Lfunc_begin6
Lset719 = Lfunc_end6-Lfunc_begin6
	.quad	Lset719
	.byte	4
Lset720 = Ltmp47-Lfunc_begin6
	.long	Lset720
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset721 = Ltmp48-Ltmp47
	.long	Lset721
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end6:
Lset722 = Ldebug_frame_end7-Ldebug_frame_begin7
	.long	Lset722
Ldebug_frame_begin7:
Lset723 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset723
	.quad	Lfunc_begin7
Lset724 = Lfunc_end7-Lfunc_begin7
	.quad	Lset724
	.byte	4
Lset725 = Ltmp57-Lfunc_begin7
	.long	Lset725
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset726 = Ltmp58-Ltmp57
	.long	Lset726
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end7:
Lset727 = Ldebug_frame_end8-Ldebug_frame_begin8
	.long	Lset727
Ldebug_frame_begin8:
Lset728 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset728
	.quad	Lfunc_begin8
Lset729 = Lfunc_end8-Lfunc_begin8
	.quad	Lset729
	.byte	4
Lset730 = Ltmp67-Lfunc_begin8
	.long	Lset730
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset731 = Ltmp68-Ltmp67
	.long	Lset731
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end8:
Lset732 = Ldebug_frame_end9-Ldebug_frame_begin9
	.long	Lset732
Ldebug_frame_begin9:
Lset733 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset733
	.quad	Lfunc_begin9
Lset734 = Lfunc_end9-Lfunc_begin9
	.quad	Lset734
	.byte	4
Lset735 = Ltmp77-Lfunc_begin9
	.long	Lset735
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset736 = Ltmp78-Ltmp77
	.long	Lset736
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end9:
Lset737 = Ldebug_frame_end10-Ldebug_frame_begin10
	.long	Lset737
Ldebug_frame_begin10:
Lset738 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset738
	.quad	Lfunc_begin10
Lset739 = Lfunc_end10-Lfunc_begin10
	.quad	Lset739
	.byte	4
Lset740 = Ltmp87-Lfunc_begin10
	.long	Lset740
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset741 = Ltmp88-Ltmp87
	.long	Lset741
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end10:
Lset742 = Ldebug_frame_end11-Ldebug_frame_begin11
	.long	Lset742
Ldebug_frame_begin11:
Lset743 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset743
	.quad	Lfunc_begin11
Lset744 = Lfunc_end11-Lfunc_begin11
	.quad	Lset744
	.byte	4
Lset745 = Ltmp97-Lfunc_begin11
	.long	Lset745
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset746 = Ltmp98-Ltmp97
	.long	Lset746
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end11:
Lset747 = Ldebug_frame_end12-Ldebug_frame_begin12
	.long	Lset747
Ldebug_frame_begin12:
Lset748 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset748
	.quad	Lfunc_begin12
Lset749 = Lfunc_end12-Lfunc_begin12
	.quad	Lset749
	.byte	4
Lset750 = Ltmp107-Lfunc_begin12
	.long	Lset750
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset751 = Ltmp108-Ltmp107
	.long	Lset751
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end12:
Lset752 = Ldebug_frame_end13-Ldebug_frame_begin13
	.long	Lset752
Ldebug_frame_begin13:
Lset753 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset753
	.quad	Lfunc_begin13
Lset754 = Lfunc_end13-Lfunc_begin13
	.quad	Lset754
	.byte	4
Lset755 = Ltmp117-Lfunc_begin13
	.long	Lset755
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset756 = Ltmp118-Ltmp117
	.long	Lset756
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end13:
Lset757 = Ldebug_frame_end14-Ldebug_frame_begin14
	.long	Lset757
Ldebug_frame_begin14:
Lset758 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset758
	.quad	Lfunc_begin14
Lset759 = Lfunc_end14-Lfunc_begin14
	.quad	Lset759
	.byte	4
Lset760 = Ltmp127-Lfunc_begin14
	.long	Lset760
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset761 = Ltmp128-Ltmp127
	.long	Lset761
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end14:
Lset762 = Ldebug_frame_end15-Ldebug_frame_begin15
	.long	Lset762
Ldebug_frame_begin15:
Lset763 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset763
	.quad	Lfunc_begin15
Lset764 = Lfunc_end15-Lfunc_begin15
	.quad	Lset764
	.byte	4
Lset765 = Ltmp137-Lfunc_begin15
	.long	Lset765
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset766 = Ltmp138-Ltmp137
	.long	Lset766
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end15:
Lset767 = Ldebug_frame_end16-Ldebug_frame_begin16
	.long	Lset767
Ldebug_frame_begin16:
Lset768 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset768
	.quad	Lfunc_begin16
Lset769 = Lfunc_end16-Lfunc_begin16
	.quad	Lset769
	.byte	4
Lset770 = Ltmp147-Lfunc_begin16
	.long	Lset770
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset771 = Ltmp148-Ltmp147
	.long	Lset771
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end16:
Lset772 = Ldebug_frame_end17-Ldebug_frame_begin17
	.long	Lset772
Ldebug_frame_begin17:
Lset773 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset773
	.quad	Lfunc_begin17
Lset774 = Lfunc_end17-Lfunc_begin17
	.quad	Lset774
	.byte	4
Lset775 = Ltmp157-Lfunc_begin17
	.long	Lset775
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset776 = Ltmp158-Ltmp157
	.long	Lset776
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end17:
Lset777 = Ldebug_frame_end18-Ldebug_frame_begin18
	.long	Lset777
Ldebug_frame_begin18:
Lset778 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset778
	.quad	Lfunc_begin18
Lset779 = Lfunc_end18-Lfunc_begin18
	.quad	Lset779
	.byte	4
Lset780 = Ltmp167-Lfunc_begin18
	.long	Lset780
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset781 = Ltmp168-Ltmp167
	.long	Lset781
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end18:
Lset782 = Ldebug_frame_end19-Ldebug_frame_begin19
	.long	Lset782
Ldebug_frame_begin19:
Lset783 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset783
	.quad	Lfunc_begin19
Lset784 = Lfunc_end19-Lfunc_begin19
	.quad	Lset784
	.byte	4
Lset785 = Ltmp177-Lfunc_begin19
	.long	Lset785
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset786 = Ltmp178-Ltmp177
	.long	Lset786
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end19:
Lset787 = Ldebug_frame_end20-Ldebug_frame_begin20
	.long	Lset787
Ldebug_frame_begin20:
Lset788 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset788
	.quad	Lfunc_begin20
Lset789 = Lfunc_end20-Lfunc_begin20
	.quad	Lset789
	.byte	4
Lset790 = Ltmp187-Lfunc_begin20
	.long	Lset790
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset791 = Ltmp188-Ltmp187
	.long	Lset791
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end20:
Lset792 = Ldebug_frame_end21-Ldebug_frame_begin21
	.long	Lset792
Ldebug_frame_begin21:
Lset793 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset793
	.quad	Lfunc_begin21
Lset794 = Lfunc_end21-Lfunc_begin21
	.quad	Lset794
	.byte	4
Lset795 = Ltmp197-Lfunc_begin21
	.long	Lset795
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset796 = Ltmp198-Ltmp197
	.long	Lset796
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end21:
Lset797 = Ldebug_frame_end22-Ldebug_frame_begin22
	.long	Lset797
Ldebug_frame_begin22:
Lset798 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset798
	.quad	Lfunc_begin22
Lset799 = Lfunc_end22-Lfunc_begin22
	.quad	Lset799
	.byte	4
Lset800 = Ltmp207-Lfunc_begin22
	.long	Lset800
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset801 = Ltmp208-Ltmp207
	.long	Lset801
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end22:
Lset802 = Ldebug_frame_end23-Ldebug_frame_begin23
	.long	Lset802
Ldebug_frame_begin23:
Lset803 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset803
	.quad	Lfunc_begin23
Lset804 = Lfunc_end23-Lfunc_begin23
	.quad	Lset804
	.byte	4
Lset805 = Ltmp217-Lfunc_begin23
	.long	Lset805
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset806 = Ltmp218-Ltmp217
	.long	Lset806
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end23:
Lset807 = Ldebug_frame_end24-Ldebug_frame_begin24
	.long	Lset807
Ldebug_frame_begin24:
Lset808 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset808
	.quad	Lfunc_begin24
Lset809 = Lfunc_end24-Lfunc_begin24
	.quad	Lset809
	.byte	4
Lset810 = Ltmp227-Lfunc_begin24
	.long	Lset810
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset811 = Ltmp228-Ltmp227
	.long	Lset811
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end24:
Lset812 = Ldebug_frame_end25-Ldebug_frame_begin25
	.long	Lset812
Ldebug_frame_begin25:
Lset813 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset813
	.quad	Lfunc_begin25
Lset814 = Lfunc_end25-Lfunc_begin25
	.quad	Lset814
	.byte	4
Lset815 = Ltmp237-Lfunc_begin25
	.long	Lset815
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset816 = Ltmp238-Ltmp237
	.long	Lset816
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end25:
Lset817 = Ldebug_frame_end26-Ldebug_frame_begin26
	.long	Lset817
Ldebug_frame_begin26:
Lset818 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset818
	.quad	Lfunc_begin26
Lset819 = Lfunc_end26-Lfunc_begin26
	.quad	Lset819
	.byte	4
Lset820 = Ltmp247-Lfunc_begin26
	.long	Lset820
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset821 = Ltmp248-Ltmp247
	.long	Lset821
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end26:
Lset822 = Ldebug_frame_end27-Ldebug_frame_begin27
	.long	Lset822
Ldebug_frame_begin27:
Lset823 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset823
	.quad	Lfunc_begin27
Lset824 = Lfunc_end27-Lfunc_begin27
	.quad	Lset824
	.byte	4
Lset825 = Ltmp257-Lfunc_begin27
	.long	Lset825
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset826 = Ltmp258-Ltmp257
	.long	Lset826
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end27:
Lset827 = Ldebug_frame_end28-Ldebug_frame_begin28
	.long	Lset827
Ldebug_frame_begin28:
Lset828 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset828
	.quad	Lfunc_begin28
Lset829 = Lfunc_end28-Lfunc_begin28
	.quad	Lset829
	.byte	4
Lset830 = Ltmp267-Lfunc_begin28
	.long	Lset830
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset831 = Ltmp268-Ltmp267
	.long	Lset831
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end28:
Lset832 = Ldebug_frame_end29-Ldebug_frame_begin29
	.long	Lset832
Ldebug_frame_begin29:
Lset833 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset833
	.quad	Lfunc_begin29
Lset834 = Lfunc_end29-Lfunc_begin29
	.quad	Lset834
	.byte	4
Lset835 = Ltmp279-Lfunc_begin29
	.long	Lset835
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset836 = Ltmp280-Ltmp279
	.long	Lset836
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end29:
Lset837 = Ldebug_frame_end30-Ldebug_frame_begin30
	.long	Lset837
Ldebug_frame_begin30:
Lset838 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset838
	.quad	Lfunc_begin30
Lset839 = Lfunc_end30-Lfunc_begin30
	.quad	Lset839
	.byte	4
Lset840 = Ltmp289-Lfunc_begin30
	.long	Lset840
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset841 = Ltmp290-Ltmp289
	.long	Lset841
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end30:
Lset842 = Ldebug_frame_end31-Ldebug_frame_begin31
	.long	Lset842
Ldebug_frame_begin31:
Lset843 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset843
	.quad	Lfunc_begin31
Lset844 = Lfunc_end31-Lfunc_begin31
	.quad	Lset844
	.byte	4
Lset845 = Ltmp299-Lfunc_begin31
	.long	Lset845
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset846 = Ltmp300-Ltmp299
	.long	Lset846
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end31:
Lset847 = Ldebug_frame_end32-Ldebug_frame_begin32
	.long	Lset847
Ldebug_frame_begin32:
Lset848 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset848
	.quad	Lfunc_begin32
Lset849 = Lfunc_end32-Lfunc_begin32
	.quad	Lset849
	.byte	4
Lset850 = Ltmp309-Lfunc_begin32
	.long	Lset850
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset851 = Ltmp310-Ltmp309
	.long	Lset851
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end32:
Lset852 = Ldebug_frame_end33-Ldebug_frame_begin33
	.long	Lset852
Ldebug_frame_begin33:
Lset853 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset853
	.quad	Lfunc_begin33
Lset854 = Lfunc_end33-Lfunc_begin33
	.quad	Lset854
	.byte	4
Lset855 = Ltmp319-Lfunc_begin33
	.long	Lset855
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset856 = Ltmp320-Ltmp319
	.long	Lset856
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end33:
Lset857 = Ldebug_frame_end34-Ldebug_frame_begin34
	.long	Lset857
Ldebug_frame_begin34:
Lset858 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset858
	.quad	Lfunc_begin34
Lset859 = Lfunc_end34-Lfunc_begin34
	.quad	Lset859
	.byte	4
Lset860 = Ltmp329-Lfunc_begin34
	.long	Lset860
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset861 = Ltmp330-Ltmp329
	.long	Lset861
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end34:
Lset862 = Ldebug_frame_end35-Ldebug_frame_begin35
	.long	Lset862
Ldebug_frame_begin35:
Lset863 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset863
	.quad	Lfunc_begin35
Lset864 = Lfunc_end35-Lfunc_begin35
	.quad	Lset864
	.byte	4
Lset865 = Ltmp339-Lfunc_begin35
	.long	Lset865
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset866 = Ltmp340-Ltmp339
	.long	Lset866
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end35:
Lset867 = Ldebug_frame_end36-Ldebug_frame_begin36
	.long	Lset867
Ldebug_frame_begin36:
Lset868 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset868
	.quad	Lfunc_begin36
Lset869 = Lfunc_end36-Lfunc_begin36
	.quad	Lset869
	.byte	4
Lset870 = Ltmp349-Lfunc_begin36
	.long	Lset870
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset871 = Ltmp350-Ltmp349
	.long	Lset871
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end36:
Lset872 = Ldebug_frame_end37-Ldebug_frame_begin37
	.long	Lset872
Ldebug_frame_begin37:
Lset873 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset873
	.quad	Lfunc_begin37
Lset874 = Lfunc_end37-Lfunc_begin37
	.quad	Lset874
	.byte	4
Lset875 = Ltmp359-Lfunc_begin37
	.long	Lset875
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset876 = Ltmp360-Ltmp359
	.long	Lset876
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end37:
Lset877 = Ldebug_frame_end38-Ldebug_frame_begin38
	.long	Lset877
Ldebug_frame_begin38:
Lset878 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset878
	.quad	Lfunc_begin38
Lset879 = Lfunc_end38-Lfunc_begin38
	.quad	Lset879
	.byte	4
Lset880 = Ltmp371-Lfunc_begin38
	.long	Lset880
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset881 = Ltmp372-Ltmp371
	.long	Lset881
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end38:
Lset882 = Ldebug_frame_end39-Ldebug_frame_begin39
	.long	Lset882
Ldebug_frame_begin39:
Lset883 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset883
	.quad	Lfunc_begin39
Lset884 = Lfunc_end39-Lfunc_begin39
	.quad	Lset884
	.byte	4
Lset885 = Ltmp381-Lfunc_begin39
	.long	Lset885
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset886 = Ltmp382-Ltmp381
	.long	Lset886
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end39:
Lset887 = Ldebug_frame_end40-Ldebug_frame_begin40
	.long	Lset887
Ldebug_frame_begin40:
Lset888 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset888
	.quad	Lfunc_begin40
Lset889 = Lfunc_end40-Lfunc_begin40
	.quad	Lset889
	.byte	4
Lset890 = Ltmp391-Lfunc_begin40
	.long	Lset890
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset891 = Ltmp392-Ltmp391
	.long	Lset891
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end40:
Lset892 = Ldebug_frame_end41-Ldebug_frame_begin41
	.long	Lset892
Ldebug_frame_begin41:
Lset893 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset893
	.quad	Lfunc_begin41
Lset894 = Lfunc_end41-Lfunc_begin41
	.quad	Lset894
	.byte	4
Lset895 = Ltmp401-Lfunc_begin41
	.long	Lset895
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset896 = Ltmp402-Ltmp401
	.long	Lset896
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end41:
Lset897 = Ldebug_frame_end42-Ldebug_frame_begin42
	.long	Lset897
Ldebug_frame_begin42:
Lset898 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset898
	.quad	Lfunc_begin42
Lset899 = Lfunc_end42-Lfunc_begin42
	.quad	Lset899
	.byte	4
Lset900 = Ltmp411-Lfunc_begin42
	.long	Lset900
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset901 = Ltmp412-Ltmp411
	.long	Lset901
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end42:
Lset902 = Ldebug_frame_end43-Ldebug_frame_begin43
	.long	Lset902
Ldebug_frame_begin43:
Lset903 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset903
	.quad	Lfunc_begin43
Lset904 = Lfunc_end43-Lfunc_begin43
	.quad	Lset904
	.byte	4
Lset905 = Ltmp421-Lfunc_begin43
	.long	Lset905
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset906 = Ltmp422-Ltmp421
	.long	Lset906
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end43:
Lset907 = Ldebug_frame_end44-Ldebug_frame_begin44
	.long	Lset907
Ldebug_frame_begin44:
Lset908 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset908
	.quad	Lfunc_begin44
Lset909 = Lfunc_end44-Lfunc_begin44
	.quad	Lset909
	.byte	4
Lset910 = Ltmp431-Lfunc_begin44
	.long	Lset910
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset911 = Ltmp432-Ltmp431
	.long	Lset911
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end44:
Lset912 = Ldebug_frame_end45-Ldebug_frame_begin45
	.long	Lset912
Ldebug_frame_begin45:
Lset913 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset913
	.quad	Lfunc_begin45
Lset914 = Lfunc_end45-Lfunc_begin45
	.quad	Lset914
	.byte	4
Lset915 = Ltmp441-Lfunc_begin45
	.long	Lset915
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset916 = Ltmp442-Ltmp441
	.long	Lset916
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end45:
Lset917 = Ldebug_frame_end46-Ldebug_frame_begin46
	.long	Lset917
Ldebug_frame_begin46:
Lset918 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset918
	.quad	Lfunc_begin46
Lset919 = Lfunc_end46-Lfunc_begin46
	.quad	Lset919
	.byte	4
Lset920 = Ltmp451-Lfunc_begin46
	.long	Lset920
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset921 = Ltmp452-Ltmp451
	.long	Lset921
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end46:
Lset922 = Ldebug_frame_end47-Ldebug_frame_begin47
	.long	Lset922
Ldebug_frame_begin47:
Lset923 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset923
	.quad	Lfunc_begin47
Lset924 = Lfunc_end47-Lfunc_begin47
	.quad	Lset924
	.byte	4
Lset925 = Ltmp461-Lfunc_begin47
	.long	Lset925
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset926 = Ltmp462-Ltmp461
	.long	Lset926
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end47:
Lset927 = Ldebug_frame_end48-Ldebug_frame_begin48
	.long	Lset927
Ldebug_frame_begin48:
Lset928 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset928
	.quad	Lfunc_begin48
Lset929 = Lfunc_end48-Lfunc_begin48
	.quad	Lset929
	.byte	4
Lset930 = Ltmp471-Lfunc_begin48
	.long	Lset930
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset931 = Ltmp472-Ltmp471
	.long	Lset931
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end48:
Lset932 = Ldebug_frame_end49-Ldebug_frame_begin49
	.long	Lset932
Ldebug_frame_begin49:
Lset933 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset933
	.quad	Lfunc_begin49
Lset934 = Lfunc_end49-Lfunc_begin49
	.quad	Lset934
	.byte	4
Lset935 = Ltmp481-Lfunc_begin49
	.long	Lset935
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset936 = Ltmp482-Ltmp481
	.long	Lset936
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end49:
Lset937 = Ldebug_frame_end50-Ldebug_frame_begin50
	.long	Lset937
Ldebug_frame_begin50:
Lset938 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset938
	.quad	Lfunc_begin50
Lset939 = Lfunc_end50-Lfunc_begin50
	.quad	Lset939
	.byte	4
Lset940 = Ltmp491-Lfunc_begin50
	.long	Lset940
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset941 = Ltmp492-Ltmp491
	.long	Lset941
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end50:
Lset942 = Ldebug_frame_end51-Ldebug_frame_begin51
	.long	Lset942
Ldebug_frame_begin51:
Lset943 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset943
	.quad	Lfunc_begin51
Lset944 = Lfunc_end51-Lfunc_begin51
	.quad	Lset944
	.byte	4
Lset945 = Ltmp501-Lfunc_begin51
	.long	Lset945
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset946 = Ltmp502-Ltmp501
	.long	Lset946
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end51:
Lset947 = Ldebug_frame_end52-Ldebug_frame_begin52
	.long	Lset947
Ldebug_frame_begin52:
Lset948 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset948
	.quad	Lfunc_begin52
Lset949 = Lfunc_end52-Lfunc_begin52
	.quad	Lset949
	.byte	4
Lset950 = Ltmp511-Lfunc_begin52
	.long	Lset950
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset951 = Ltmp512-Ltmp511
	.long	Lset951
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end52:
Lset952 = Ldebug_frame_end53-Ldebug_frame_begin53
	.long	Lset952
Ldebug_frame_begin53:
Lset953 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset953
	.quad	Lfunc_begin53
Lset954 = Lfunc_end53-Lfunc_begin53
	.quad	Lset954
	.byte	4
Lset955 = Ltmp521-Lfunc_begin53
	.long	Lset955
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset956 = Ltmp522-Ltmp521
	.long	Lset956
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end53:
Lset957 = Ldebug_frame_end54-Ldebug_frame_begin54
	.long	Lset957
Ldebug_frame_begin54:
Lset958 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset958
	.quad	Lfunc_begin54
Lset959 = Lfunc_end54-Lfunc_begin54
	.quad	Lset959
	.byte	4
Lset960 = Ltmp531-Lfunc_begin54
	.long	Lset960
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset961 = Ltmp532-Ltmp531
	.long	Lset961
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end54:
Lset962 = Ldebug_frame_end55-Ldebug_frame_begin55
	.long	Lset962
Ldebug_frame_begin55:
Lset963 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset963
	.quad	Lfunc_begin55
Lset964 = Lfunc_end55-Lfunc_begin55
	.quad	Lset964
	.byte	4
Lset965 = Ltmp543-Lfunc_begin55
	.long	Lset965
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset966 = Ltmp544-Ltmp543
	.long	Lset966
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end55:
Lset967 = Ldebug_frame_end56-Ldebug_frame_begin56
	.long	Lset967
Ldebug_frame_begin56:
Lset968 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset968
	.quad	Lfunc_begin56
Lset969 = Lfunc_end56-Lfunc_begin56
	.quad	Lset969
	.byte	4
Lset970 = Ltmp555-Lfunc_begin56
	.long	Lset970
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset971 = Ltmp556-Ltmp555
	.long	Lset971
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end56:
Lset972 = Ldebug_frame_end57-Ldebug_frame_begin57
	.long	Lset972
Ldebug_frame_begin57:
Lset973 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset973
	.quad	Lfunc_begin57
Lset974 = Lfunc_end57-Lfunc_begin57
	.quad	Lset974
	.byte	4
Lset975 = Ltmp567-Lfunc_begin57
	.long	Lset975
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset976 = Ltmp568-Ltmp567
	.long	Lset976
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end57:
Lset977 = Ldebug_frame_end58-Ldebug_frame_begin58
	.long	Lset977
Ldebug_frame_begin58:
Lset978 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset978
	.quad	Lfunc_begin58
Lset979 = Lfunc_end58-Lfunc_begin58
	.quad	Lset979
	.byte	4
Lset980 = Ltmp579-Lfunc_begin58
	.long	Lset980
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset981 = Ltmp580-Ltmp579
	.long	Lset981
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end58:
Lset982 = Ldebug_frame_end59-Ldebug_frame_begin59
	.long	Lset982
Ldebug_frame_begin59:
Lset983 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset983
	.quad	Lfunc_begin59
Lset984 = Lfunc_end59-Lfunc_begin59
	.quad	Lset984
	.byte	4
Lset985 = Ltmp591-Lfunc_begin59
	.long	Lset985
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset986 = Ltmp592-Ltmp591
	.long	Lset986
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end59:
Lset987 = Ldebug_frame_end60-Ldebug_frame_begin60
	.long	Lset987
Ldebug_frame_begin60:
Lset988 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset988
	.quad	Lfunc_begin60
Lset989 = Lfunc_end60-Lfunc_begin60
	.quad	Lset989
	.byte	4
Lset990 = Ltmp603-Lfunc_begin60
	.long	Lset990
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset991 = Ltmp604-Ltmp603
	.long	Lset991
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end60:
Lset992 = Ldebug_frame_end61-Ldebug_frame_begin61
	.long	Lset992
Ldebug_frame_begin61:
Lset993 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset993
	.quad	Lfunc_begin61
Lset994 = Lfunc_end61-Lfunc_begin61
	.quad	Lset994
	.byte	4
Lset995 = Ltmp615-Lfunc_begin61
	.long	Lset995
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset996 = Ltmp616-Ltmp615
	.long	Lset996
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end61:
Lset997 = Ldebug_frame_end62-Ldebug_frame_begin62
	.long	Lset997
Ldebug_frame_begin62:
Lset998 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset998
	.quad	Lfunc_begin62
Lset999 = Lfunc_end62-Lfunc_begin62
	.quad	Lset999
	.byte	4
Lset1000 = Ltmp627-Lfunc_begin62
	.long	Lset1000
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1001 = Ltmp628-Ltmp627
	.long	Lset1001
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end62:
Lset1002 = Ldebug_frame_end63-Ldebug_frame_begin63
	.long	Lset1002
Ldebug_frame_begin63:
Lset1003 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1003
	.quad	Lfunc_begin63
Lset1004 = Lfunc_end63-Lfunc_begin63
	.quad	Lset1004
	.byte	4
Lset1005 = Ltmp639-Lfunc_begin63
	.long	Lset1005
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1006 = Ltmp640-Ltmp639
	.long	Lset1006
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end63:
Lset1007 = Ldebug_frame_end64-Ldebug_frame_begin64
	.long	Lset1007
Ldebug_frame_begin64:
Lset1008 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1008
	.quad	Lfunc_begin64
Lset1009 = Lfunc_end64-Lfunc_begin64
	.quad	Lset1009
	.byte	4
Lset1010 = Ltmp651-Lfunc_begin64
	.long	Lset1010
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1011 = Ltmp652-Ltmp651
	.long	Lset1011
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end64:
Lset1012 = Ldebug_frame_end65-Ldebug_frame_begin65
	.long	Lset1012
Ldebug_frame_begin65:
Lset1013 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1013
	.quad	Lfunc_begin65
Lset1014 = Lfunc_end65-Lfunc_begin65
	.quad	Lset1014
	.byte	4
Lset1015 = Ltmp663-Lfunc_begin65
	.long	Lset1015
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1016 = Ltmp664-Ltmp663
	.long	Lset1016
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end65:
Lset1017 = Ldebug_frame_end66-Ldebug_frame_begin66
	.long	Lset1017
Ldebug_frame_begin66:
Lset1018 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1018
	.quad	Lfunc_begin66
Lset1019 = Lfunc_end66-Lfunc_begin66
	.quad	Lset1019
	.byte	4
Lset1020 = Ltmp675-Lfunc_begin66
	.long	Lset1020
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1021 = Ltmp676-Ltmp675
	.long	Lset1021
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end66:
Lset1022 = Ldebug_frame_end67-Ldebug_frame_begin67
	.long	Lset1022
Ldebug_frame_begin67:
Lset1023 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1023
	.quad	Lfunc_begin67
Lset1024 = Lfunc_end67-Lfunc_begin67
	.quad	Lset1024
	.byte	4
Lset1025 = Ltmp687-Lfunc_begin67
	.long	Lset1025
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1026 = Ltmp688-Ltmp687
	.long	Lset1026
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end67:
Lset1027 = Ldebug_frame_end68-Ldebug_frame_begin68
	.long	Lset1027
Ldebug_frame_begin68:
Lset1028 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1028
	.quad	Lfunc_begin68
Lset1029 = Lfunc_end68-Lfunc_begin68
	.quad	Lset1029
	.byte	4
Lset1030 = Ltmp699-Lfunc_begin68
	.long	Lset1030
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1031 = Ltmp700-Ltmp699
	.long	Lset1031
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end68:
Lset1032 = Ldebug_frame_end69-Ldebug_frame_begin69
	.long	Lset1032
Ldebug_frame_begin69:
Lset1033 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1033
	.quad	Lfunc_begin69
Lset1034 = Lfunc_end69-Lfunc_begin69
	.quad	Lset1034
	.byte	4
Lset1035 = Ltmp711-Lfunc_begin69
	.long	Lset1035
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1036 = Ltmp712-Ltmp711
	.long	Lset1036
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end69:
Lset1037 = Ldebug_frame_end70-Ldebug_frame_begin70
	.long	Lset1037
Ldebug_frame_begin70:
Lset1038 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1038
	.quad	Lfunc_begin70
Lset1039 = Lfunc_end70-Lfunc_begin70
	.quad	Lset1039
	.byte	4
Lset1040 = Ltmp723-Lfunc_begin70
	.long	Lset1040
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1041 = Ltmp724-Ltmp723
	.long	Lset1041
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end70:
Lset1042 = Ldebug_frame_end71-Ldebug_frame_begin71
	.long	Lset1042
Ldebug_frame_begin71:
Lset1043 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1043
	.quad	Lfunc_begin71
Lset1044 = Lfunc_end71-Lfunc_begin71
	.quad	Lset1044
	.byte	4
Lset1045 = Ltmp735-Lfunc_begin71
	.long	Lset1045
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1046 = Ltmp736-Ltmp735
	.long	Lset1046
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end71:
Lset1047 = Ldebug_frame_end72-Ldebug_frame_begin72
	.long	Lset1047
Ldebug_frame_begin72:
Lset1048 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1048
	.quad	Lfunc_begin72
Lset1049 = Lfunc_end72-Lfunc_begin72
	.quad	Lset1049
	.byte	4
Lset1050 = Ltmp747-Lfunc_begin72
	.long	Lset1050
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1051 = Ltmp748-Ltmp747
	.long	Lset1051
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end72:
Lset1052 = Ldebug_frame_end73-Ldebug_frame_begin73
	.long	Lset1052
Ldebug_frame_begin73:
Lset1053 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1053
	.quad	Lfunc_begin73
Lset1054 = Lfunc_end73-Lfunc_begin73
	.quad	Lset1054
	.byte	4
Lset1055 = Ltmp759-Lfunc_begin73
	.long	Lset1055
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1056 = Ltmp760-Ltmp759
	.long	Lset1056
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end73:
Lset1057 = Ldebug_frame_end74-Ldebug_frame_begin74
	.long	Lset1057
Ldebug_frame_begin74:
Lset1058 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1058
	.quad	Lfunc_begin74
Lset1059 = Lfunc_end74-Lfunc_begin74
	.quad	Lset1059
	.byte	4
Lset1060 = Ltmp771-Lfunc_begin74
	.long	Lset1060
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1061 = Ltmp772-Ltmp771
	.long	Lset1061
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end74:
Lset1062 = Ldebug_frame_end75-Ldebug_frame_begin75
	.long	Lset1062
Ldebug_frame_begin75:
Lset1063 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1063
	.quad	Lfunc_begin75
Lset1064 = Lfunc_end75-Lfunc_begin75
	.quad	Lset1064
	.byte	4
Lset1065 = Ltmp783-Lfunc_begin75
	.long	Lset1065
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1066 = Ltmp784-Ltmp783
	.long	Lset1066
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end75:
Lset1067 = Ldebug_frame_end76-Ldebug_frame_begin76
	.long	Lset1067
Ldebug_frame_begin76:
Lset1068 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1068
	.quad	Lfunc_begin76
Lset1069 = Lfunc_end76-Lfunc_begin76
	.quad	Lset1069
	.byte	4
Lset1070 = Ltmp795-Lfunc_begin76
	.long	Lset1070
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1071 = Ltmp796-Ltmp795
	.long	Lset1071
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end76:
Lset1072 = Ldebug_frame_end77-Ldebug_frame_begin77
	.long	Lset1072
Ldebug_frame_begin77:
Lset1073 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1073
	.quad	Lfunc_begin77
Lset1074 = Lfunc_end77-Lfunc_begin77
	.quad	Lset1074
	.byte	4
Lset1075 = Ltmp807-Lfunc_begin77
	.long	Lset1075
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1076 = Ltmp808-Ltmp807
	.long	Lset1076
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end77:
Lset1077 = Ldebug_frame_end78-Ldebug_frame_begin78
	.long	Lset1077
Ldebug_frame_begin78:
Lset1078 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1078
	.quad	Lfunc_begin78
Lset1079 = Lfunc_end78-Lfunc_begin78
	.quad	Lset1079
	.byte	4
Lset1080 = Ltmp819-Lfunc_begin78
	.long	Lset1080
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1081 = Ltmp820-Ltmp819
	.long	Lset1081
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end78:
Lset1082 = Ldebug_frame_end79-Ldebug_frame_begin79
	.long	Lset1082
Ldebug_frame_begin79:
Lset1083 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1083
	.quad	Lfunc_begin79
Lset1084 = Lfunc_end79-Lfunc_begin79
	.quad	Lset1084
	.byte	4
Lset1085 = Ltmp831-Lfunc_begin79
	.long	Lset1085
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1086 = Ltmp832-Ltmp831
	.long	Lset1086
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end79:
Lset1087 = Ldebug_frame_end80-Ldebug_frame_begin80
	.long	Lset1087
Ldebug_frame_begin80:
Lset1088 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1088
	.quad	Lfunc_begin80
Lset1089 = Lfunc_end80-Lfunc_begin80
	.quad	Lset1089
	.byte	4
Lset1090 = Ltmp843-Lfunc_begin80
	.long	Lset1090
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1091 = Ltmp844-Ltmp843
	.long	Lset1091
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end80:
Lset1092 = Ldebug_frame_end81-Ldebug_frame_begin81
	.long	Lset1092
Ldebug_frame_begin81:
Lset1093 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1093
	.quad	Lfunc_begin81
Lset1094 = Lfunc_end81-Lfunc_begin81
	.quad	Lset1094
	.byte	4
Lset1095 = Ltmp856-Lfunc_begin81
	.long	Lset1095
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1096 = Ltmp857-Ltmp856
	.long	Lset1096
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end81:
Lset1097 = Ldebug_frame_end82-Ldebug_frame_begin82
	.long	Lset1097
Ldebug_frame_begin82:
Lset1098 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1098
	.quad	Lfunc_begin82
Lset1099 = Lfunc_end82-Lfunc_begin82
	.quad	Lset1099
	.byte	4
Lset1100 = Ltmp868-Lfunc_begin82
	.long	Lset1100
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1101 = Ltmp869-Ltmp868
	.long	Lset1101
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end82:
Lset1102 = Ldebug_frame_end83-Ldebug_frame_begin83
	.long	Lset1102
Ldebug_frame_begin83:
Lset1103 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1103
	.quad	Lfunc_begin83
Lset1104 = Lfunc_end83-Lfunc_begin83
	.quad	Lset1104
	.byte	4
Lset1105 = Ltmp880-Lfunc_begin83
	.long	Lset1105
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1106 = Ltmp881-Ltmp880
	.long	Lset1106
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end83:
Lset1107 = Ldebug_frame_end84-Ldebug_frame_begin84
	.long	Lset1107
Ldebug_frame_begin84:
Lset1108 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1108
	.quad	Lfunc_begin84
Lset1109 = Lfunc_end84-Lfunc_begin84
	.quad	Lset1109
	.byte	4
Lset1110 = Ltmp892-Lfunc_begin84
	.long	Lset1110
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1111 = Ltmp893-Ltmp892
	.long	Lset1111
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end84:
Lset1112 = Ldebug_frame_end85-Ldebug_frame_begin85
	.long	Lset1112
Ldebug_frame_begin85:
Lset1113 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1113
	.quad	Lfunc_begin85
Lset1114 = Lfunc_end85-Lfunc_begin85
	.quad	Lset1114
	.byte	4
Lset1115 = Ltmp904-Lfunc_begin85
	.long	Lset1115
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1116 = Ltmp905-Ltmp904
	.long	Lset1116
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end85:
Lset1117 = Ldebug_frame_end86-Ldebug_frame_begin86
	.long	Lset1117
Ldebug_frame_begin86:
Lset1118 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1118
	.quad	Lfunc_begin86
Lset1119 = Lfunc_end86-Lfunc_begin86
	.quad	Lset1119
	.byte	4
Lset1120 = Ltmp916-Lfunc_begin86
	.long	Lset1120
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1121 = Ltmp917-Ltmp916
	.long	Lset1121
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end86:
Lset1122 = Ldebug_frame_end87-Ldebug_frame_begin87
	.long	Lset1122
Ldebug_frame_begin87:
Lset1123 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1123
	.quad	Lfunc_begin87
Lset1124 = Lfunc_end87-Lfunc_begin87
	.quad	Lset1124
	.byte	4
Lset1125 = Ltmp928-Lfunc_begin87
	.long	Lset1125
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1126 = Ltmp929-Ltmp928
	.long	Lset1126
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end87:
Lset1127 = Ldebug_frame_end88-Ldebug_frame_begin88
	.long	Lset1127
Ldebug_frame_begin88:
Lset1128 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1128
	.quad	Lfunc_begin88
Lset1129 = Lfunc_end88-Lfunc_begin88
	.quad	Lset1129
	.byte	4
Lset1130 = Ltmp940-Lfunc_begin88
	.long	Lset1130
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1131 = Ltmp941-Ltmp940
	.long	Lset1131
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end88:
Lset1132 = Ldebug_frame_end89-Ldebug_frame_begin89
	.long	Lset1132
Ldebug_frame_begin89:
Lset1133 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1133
	.quad	Lfunc_begin89
Lset1134 = Lfunc_end89-Lfunc_begin89
	.quad	Lset1134
	.byte	4
Lset1135 = Ltmp952-Lfunc_begin89
	.long	Lset1135
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1136 = Ltmp953-Ltmp952
	.long	Lset1136
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end89:
Lset1137 = Ldebug_frame_end90-Ldebug_frame_begin90
	.long	Lset1137
Ldebug_frame_begin90:
Lset1138 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1138
	.quad	Lfunc_begin90
Lset1139 = Lfunc_end90-Lfunc_begin90
	.quad	Lset1139
	.byte	4
Lset1140 = Ltmp965-Lfunc_begin90
	.long	Lset1140
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1141 = Ltmp966-Ltmp965
	.long	Lset1141
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end90:
Lset1142 = Ldebug_frame_end91-Ldebug_frame_begin91
	.long	Lset1142
Ldebug_frame_begin91:
Lset1143 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1143
	.quad	Lfunc_begin91
Lset1144 = Lfunc_end91-Lfunc_begin91
	.quad	Lset1144
	.byte	4
Lset1145 = Ltmp977-Lfunc_begin91
	.long	Lset1145
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1146 = Ltmp978-Ltmp977
	.long	Lset1146
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end91:
Lset1147 = Ldebug_frame_end92-Ldebug_frame_begin92
	.long	Lset1147
Ldebug_frame_begin92:
Lset1148 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1148
	.quad	Lfunc_begin92
Lset1149 = Lfunc_end92-Lfunc_begin92
	.quad	Lset1149
	.byte	4
Lset1150 = Ltmp989-Lfunc_begin92
	.long	Lset1150
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1151 = Ltmp990-Ltmp989
	.long	Lset1151
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end92:
Lset1152 = Ldebug_frame_end93-Ldebug_frame_begin93
	.long	Lset1152
Ldebug_frame_begin93:
Lset1153 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1153
	.quad	Lfunc_begin93
Lset1154 = Lfunc_end93-Lfunc_begin93
	.quad	Lset1154
	.byte	4
Lset1155 = Ltmp1001-Lfunc_begin93
	.long	Lset1155
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1156 = Ltmp1002-Ltmp1001
	.long	Lset1156
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end93:
Lset1157 = Ldebug_frame_end94-Ldebug_frame_begin94
	.long	Lset1157
Ldebug_frame_begin94:
Lset1158 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1158
	.quad	Lfunc_begin94
Lset1159 = Lfunc_end94-Lfunc_begin94
	.quad	Lset1159
	.byte	4
Lset1160 = Ltmp1013-Lfunc_begin94
	.long	Lset1160
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1161 = Ltmp1014-Ltmp1013
	.long	Lset1161
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end94:
Lset1162 = Ldebug_frame_end95-Ldebug_frame_begin95
	.long	Lset1162
Ldebug_frame_begin95:
Lset1163 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1163
	.quad	Lfunc_begin95
Lset1164 = Lfunc_end95-Lfunc_begin95
	.quad	Lset1164
	.byte	4
Lset1165 = Ltmp1025-Lfunc_begin95
	.long	Lset1165
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1166 = Ltmp1026-Ltmp1025
	.long	Lset1166
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end95:
Lset1167 = Ldebug_frame_end96-Ldebug_frame_begin96
	.long	Lset1167
Ldebug_frame_begin96:
Lset1168 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1168
	.quad	Lfunc_begin96
Lset1169 = Lfunc_end96-Lfunc_begin96
	.quad	Lset1169
	.byte	4
Lset1170 = Ltmp1037-Lfunc_begin96
	.long	Lset1170
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1171 = Ltmp1038-Ltmp1037
	.long	Lset1171
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end96:
Lset1172 = Ldebug_frame_end97-Ldebug_frame_begin97
	.long	Lset1172
Ldebug_frame_begin97:
Lset1173 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1173
	.quad	Lfunc_begin97
Lset1174 = Lfunc_end97-Lfunc_begin97
	.quad	Lset1174
	.byte	4
Lset1175 = Ltmp1049-Lfunc_begin97
	.long	Lset1175
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1176 = Ltmp1050-Ltmp1049
	.long	Lset1176
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end97:
Lset1177 = Ldebug_frame_end98-Ldebug_frame_begin98
	.long	Lset1177
Ldebug_frame_begin98:
Lset1178 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1178
	.quad	Lfunc_begin98
Lset1179 = Lfunc_end98-Lfunc_begin98
	.quad	Lset1179
	.byte	4
Lset1180 = Ltmp1061-Lfunc_begin98
	.long	Lset1180
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1181 = Ltmp1062-Ltmp1061
	.long	Lset1181
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end98:
Lset1182 = Ldebug_frame_end99-Ldebug_frame_begin99
	.long	Lset1182
Ldebug_frame_begin99:
Lset1183 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1183
	.quad	Lfunc_begin99
Lset1184 = Lfunc_end99-Lfunc_begin99
	.quad	Lset1184
	.byte	4
Lset1185 = Ltmp1073-Lfunc_begin99
	.long	Lset1185
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1186 = Ltmp1074-Ltmp1073
	.long	Lset1186
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end99:
Lset1187 = Ldebug_frame_end100-Ldebug_frame_begin100
	.long	Lset1187
Ldebug_frame_begin100:
Lset1188 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1188
	.quad	Lfunc_begin100
Lset1189 = Lfunc_end100-Lfunc_begin100
	.quad	Lset1189
	.byte	4
Lset1190 = Ltmp1085-Lfunc_begin100
	.long	Lset1190
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1191 = Ltmp1086-Ltmp1085
	.long	Lset1191
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end100:
Lset1192 = Ldebug_frame_end101-Ldebug_frame_begin101
	.long	Lset1192
Ldebug_frame_begin101:
Lset1193 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1193
	.quad	Lfunc_begin101
Lset1194 = Lfunc_end101-Lfunc_begin101
	.quad	Lset1194
	.byte	4
Lset1195 = Ltmp1097-Lfunc_begin101
	.long	Lset1195
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1196 = Ltmp1098-Ltmp1097
	.long	Lset1196
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end101:
Lset1197 = Ldebug_frame_end102-Ldebug_frame_begin102
	.long	Lset1197
Ldebug_frame_begin102:
Lset1198 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1198
	.quad	Lfunc_begin102
Lset1199 = Lfunc_end102-Lfunc_begin102
	.quad	Lset1199
	.byte	4
Lset1200 = Ltmp1109-Lfunc_begin102
	.long	Lset1200
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1201 = Ltmp1110-Ltmp1109
	.long	Lset1201
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end102:
Lset1202 = Ldebug_frame_end103-Ldebug_frame_begin103
	.long	Lset1202
Ldebug_frame_begin103:
Lset1203 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1203
	.quad	Lfunc_begin103
Lset1204 = Lfunc_end103-Lfunc_begin103
	.quad	Lset1204
	.byte	4
Lset1205 = Ltmp1121-Lfunc_begin103
	.long	Lset1205
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1206 = Ltmp1122-Ltmp1121
	.long	Lset1206
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end103:
Lset1207 = Ldebug_frame_end104-Ldebug_frame_begin104
	.long	Lset1207
Ldebug_frame_begin104:
Lset1208 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1208
	.quad	Lfunc_begin104
Lset1209 = Lfunc_end104-Lfunc_begin104
	.quad	Lset1209
	.byte	4
Lset1210 = Ltmp1133-Lfunc_begin104
	.long	Lset1210
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1211 = Ltmp1134-Ltmp1133
	.long	Lset1211
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end104:
Lset1212 = Ldebug_frame_end105-Ldebug_frame_begin105
	.long	Lset1212
Ldebug_frame_begin105:
Lset1213 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1213
	.quad	Lfunc_begin105
Lset1214 = Lfunc_end105-Lfunc_begin105
	.quad	Lset1214
	.byte	4
Lset1215 = Ltmp1145-Lfunc_begin105
	.long	Lset1215
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1216 = Ltmp1146-Ltmp1145
	.long	Lset1216
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end105:
Lset1217 = Ldebug_frame_end106-Ldebug_frame_begin106
	.long	Lset1217
Ldebug_frame_begin106:
Lset1218 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1218
	.quad	Lfunc_begin106
Lset1219 = Lfunc_end106-Lfunc_begin106
	.quad	Lset1219
	.byte	4
Lset1220 = Ltmp1157-Lfunc_begin106
	.long	Lset1220
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1221 = Ltmp1158-Ltmp1157
	.long	Lset1221
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end106:
Lset1222 = Ldebug_frame_end107-Ldebug_frame_begin107
	.long	Lset1222
Ldebug_frame_begin107:
Lset1223 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1223
	.quad	Lfunc_begin107
Lset1224 = Lfunc_end107-Lfunc_begin107
	.quad	Lset1224
	.byte	4
Lset1225 = Ltmp1169-Lfunc_begin107
	.long	Lset1225
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1226 = Ltmp1170-Ltmp1169
	.long	Lset1226
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end107:
Lset1227 = Ldebug_frame_end108-Ldebug_frame_begin108
	.long	Lset1227
Ldebug_frame_begin108:
Lset1228 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1228
	.quad	Lfunc_begin108
Lset1229 = Lfunc_end108-Lfunc_begin108
	.quad	Lset1229
	.byte	4
Lset1230 = Ltmp1181-Lfunc_begin108
	.long	Lset1230
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1231 = Ltmp1182-Ltmp1181
	.long	Lset1231
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end108:
Lset1232 = Ldebug_frame_end109-Ldebug_frame_begin109
	.long	Lset1232
Ldebug_frame_begin109:
Lset1233 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1233
	.quad	Lfunc_begin109
Lset1234 = Lfunc_end109-Lfunc_begin109
	.quad	Lset1234
	.byte	4
Lset1235 = Ltmp1194-Lfunc_begin109
	.long	Lset1235
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1236 = Ltmp1195-Ltmp1194
	.long	Lset1236
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end109:
Lset1237 = Ldebug_frame_end110-Ldebug_frame_begin110
	.long	Lset1237
Ldebug_frame_begin110:
Lset1238 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1238
	.quad	Lfunc_begin110
Lset1239 = Lfunc_end110-Lfunc_begin110
	.quad	Lset1239
	.byte	4
Lset1240 = Ltmp1207-Lfunc_begin110
	.long	Lset1240
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1241 = Ltmp1208-Ltmp1207
	.long	Lset1241
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end110:
Lset1242 = Ldebug_frame_end111-Ldebug_frame_begin111
	.long	Lset1242
Ldebug_frame_begin111:
Lset1243 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1243
	.quad	Lfunc_begin111
Lset1244 = Lfunc_end111-Lfunc_begin111
	.quad	Lset1244
	.byte	4
Lset1245 = Ltmp1220-Lfunc_begin111
	.long	Lset1245
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1246 = Ltmp1221-Ltmp1220
	.long	Lset1246
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end111:
Lset1247 = Ldebug_frame_end112-Ldebug_frame_begin112
	.long	Lset1247
Ldebug_frame_begin112:
Lset1248 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1248
	.quad	Lfunc_begin112
Lset1249 = Lfunc_end112-Lfunc_begin112
	.quad	Lset1249
	.byte	4
Lset1250 = Ltmp1233-Lfunc_begin112
	.long	Lset1250
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1251 = Ltmp1234-Ltmp1233
	.long	Lset1251
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end112:
Lset1252 = Ldebug_frame_end113-Ldebug_frame_begin113
	.long	Lset1252
Ldebug_frame_begin113:
Lset1253 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1253
	.quad	Lfunc_begin113
Lset1254 = Lfunc_end113-Lfunc_begin113
	.quad	Lset1254
	.byte	4
Lset1255 = Ltmp1246-Lfunc_begin113
	.long	Lset1255
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1256 = Ltmp1247-Ltmp1246
	.long	Lset1256
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end113:
Lset1257 = Ldebug_frame_end114-Ldebug_frame_begin114
	.long	Lset1257
Ldebug_frame_begin114:
Lset1258 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1258
	.quad	Lfunc_begin114
Lset1259 = Lfunc_end114-Lfunc_begin114
	.quad	Lset1259
	.byte	4
Lset1260 = Ltmp1259-Lfunc_begin114
	.long	Lset1260
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1261 = Ltmp1260-Ltmp1259
	.long	Lset1261
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end114:
Lset1262 = Ldebug_frame_end115-Ldebug_frame_begin115
	.long	Lset1262
Ldebug_frame_begin115:
Lset1263 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1263
	.quad	Lfunc_begin115
Lset1264 = Lfunc_end115-Lfunc_begin115
	.quad	Lset1264
	.byte	4
Lset1265 = Ltmp1272-Lfunc_begin115
	.long	Lset1265
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1266 = Ltmp1273-Ltmp1272
	.long	Lset1266
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end115:
Lset1267 = Ldebug_frame_end116-Ldebug_frame_begin116
	.long	Lset1267
Ldebug_frame_begin116:
Lset1268 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1268
	.quad	Lfunc_begin116
Lset1269 = Lfunc_end116-Lfunc_begin116
	.quad	Lset1269
	.byte	4
Lset1270 = Ltmp1285-Lfunc_begin116
	.long	Lset1270
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1271 = Ltmp1286-Ltmp1285
	.long	Lset1271
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end116:
Lset1272 = Ldebug_frame_end117-Ldebug_frame_begin117
	.long	Lset1272
Ldebug_frame_begin117:
Lset1273 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1273
	.quad	Lfunc_begin117
Lset1274 = Lfunc_end117-Lfunc_begin117
	.quad	Lset1274
	.byte	4
Lset1275 = Ltmp1300-Lfunc_begin117
	.long	Lset1275
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1276 = Ltmp1301-Ltmp1300
	.long	Lset1276
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end117:
Lset1277 = Ldebug_frame_end118-Ldebug_frame_begin118
	.long	Lset1277
Ldebug_frame_begin118:
Lset1278 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1278
	.quad	Lfunc_begin118
Lset1279 = Lfunc_end118-Lfunc_begin118
	.quad	Lset1279
	.byte	4
Lset1280 = Ltmp1312-Lfunc_begin118
	.long	Lset1280
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1281 = Ltmp1313-Ltmp1312
	.long	Lset1281
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end118:
Lset1282 = Ldebug_frame_end119-Ldebug_frame_begin119
	.long	Lset1282
Ldebug_frame_begin119:
Lset1283 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1283
	.quad	Lfunc_begin119
Lset1284 = Lfunc_end119-Lfunc_begin119
	.quad	Lset1284
	.byte	4
Lset1285 = Ltmp1324-Lfunc_begin119
	.long	Lset1285
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1286 = Ltmp1325-Ltmp1324
	.long	Lset1286
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end119:
Lset1287 = Ldebug_frame_end120-Ldebug_frame_begin120
	.long	Lset1287
Ldebug_frame_begin120:
Lset1288 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1288
	.quad	Lfunc_begin120
Lset1289 = Lfunc_end120-Lfunc_begin120
	.quad	Lset1289
	.byte	4
Lset1290 = Ltmp1336-Lfunc_begin120
	.long	Lset1290
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1291 = Ltmp1337-Ltmp1336
	.long	Lset1291
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end120:
Lset1292 = Ldebug_frame_end121-Ldebug_frame_begin121
	.long	Lset1292
Ldebug_frame_begin121:
Lset1293 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1293
	.quad	Lfunc_begin121
Lset1294 = Lfunc_end121-Lfunc_begin121
	.quad	Lset1294
	.byte	4
Lset1295 = Ltmp1348-Lfunc_begin121
	.long	Lset1295
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1296 = Ltmp1349-Ltmp1348
	.long	Lset1296
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end121:
Lset1297 = Ldebug_frame_end122-Ldebug_frame_begin122
	.long	Lset1297
Ldebug_frame_begin122:
Lset1298 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1298
	.quad	Lfunc_begin122
Lset1299 = Lfunc_end122-Lfunc_begin122
	.quad	Lset1299
	.byte	4
Lset1300 = Ltmp1360-Lfunc_begin122
	.long	Lset1300
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1301 = Ltmp1361-Ltmp1360
	.long	Lset1301
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end122:
Lset1302 = Ldebug_frame_end123-Ldebug_frame_begin123
	.long	Lset1302
Ldebug_frame_begin123:
Lset1303 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1303
	.quad	Lfunc_begin123
Lset1304 = Lfunc_end123-Lfunc_begin123
	.quad	Lset1304
	.byte	4
Lset1305 = Ltmp1372-Lfunc_begin123
	.long	Lset1305
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1306 = Ltmp1373-Ltmp1372
	.long	Lset1306
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end123:
Lset1307 = Ldebug_frame_end124-Ldebug_frame_begin124
	.long	Lset1307
Ldebug_frame_begin124:
Lset1308 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1308
	.quad	Lfunc_begin124
Lset1309 = Lfunc_end124-Lfunc_begin124
	.quad	Lset1309
	.byte	4
Lset1310 = Ltmp1384-Lfunc_begin124
	.long	Lset1310
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1311 = Ltmp1385-Ltmp1384
	.long	Lset1311
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end124:
Lset1312 = Ldebug_frame_end125-Ldebug_frame_begin125
	.long	Lset1312
Ldebug_frame_begin125:
Lset1313 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1313
	.quad	Lfunc_begin125
Lset1314 = Lfunc_end125-Lfunc_begin125
	.quad	Lset1314
	.byte	4
Lset1315 = Ltmp1396-Lfunc_begin125
	.long	Lset1315
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1316 = Ltmp1397-Ltmp1396
	.long	Lset1316
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end125:
Lset1317 = Ldebug_frame_end126-Ldebug_frame_begin126
	.long	Lset1317
Ldebug_frame_begin126:
Lset1318 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1318
	.quad	Lfunc_begin126
Lset1319 = Lfunc_end126-Lfunc_begin126
	.quad	Lset1319
	.byte	4
Lset1320 = Ltmp1410-Lfunc_begin126
	.long	Lset1320
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1321 = Ltmp1411-Ltmp1410
	.long	Lset1321
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end126:
Lset1322 = Ldebug_frame_end127-Ldebug_frame_begin127
	.long	Lset1322
Ldebug_frame_begin127:
Lset1323 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1323
	.quad	Lfunc_begin127
Lset1324 = Lfunc_end127-Lfunc_begin127
	.quad	Lset1324
	.byte	4
Lset1325 = Ltmp1430-Lfunc_begin127
	.long	Lset1325
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1326 = Ltmp1431-Ltmp1430
	.long	Lset1326
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end127:
Lset1327 = Ldebug_frame_end128-Ldebug_frame_begin128
	.long	Lset1327
Ldebug_frame_begin128:
Lset1328 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1328
	.quad	Lfunc_begin128
Lset1329 = Lfunc_end128-Lfunc_begin128
	.quad	Lset1329
	.byte	4
Lset1330 = Ltmp1450-Lfunc_begin128
	.long	Lset1330
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1331 = Ltmp1451-Ltmp1450
	.long	Lset1331
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end128:
Lset1332 = Ldebug_frame_end129-Ldebug_frame_begin129
	.long	Lset1332
Ldebug_frame_begin129:
Lset1333 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1333
	.quad	Lfunc_begin129
Lset1334 = Lfunc_end129-Lfunc_begin129
	.quad	Lset1334
	.byte	4
Lset1335 = Ltmp1455-Lfunc_begin129
	.long	Lset1335
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1336 = Ltmp1456-Ltmp1455
	.long	Lset1336
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end129:
Lset1337 = Ldebug_frame_end130-Ldebug_frame_begin130
	.long	Lset1337
Ldebug_frame_begin130:
Lset1338 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1338
	.quad	Lfunc_begin130
Lset1339 = Lfunc_end130-Lfunc_begin130
	.quad	Lset1339
	.byte	4
Lset1340 = Ltmp1460-Lfunc_begin130
	.long	Lset1340
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1341 = Ltmp1461-Ltmp1460
	.long	Lset1341
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end130:
Lset1342 = Ldebug_frame_end131-Ldebug_frame_begin131
	.long	Lset1342
Ldebug_frame_begin131:
Lset1343 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1343
	.quad	Lfunc_begin131
Lset1344 = Lfunc_end131-Lfunc_begin131
	.quad	Lset1344
	.byte	4
Lset1345 = Ltmp1465-Lfunc_begin131
	.long	Lset1345
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1346 = Ltmp1466-Ltmp1465
	.long	Lset1346
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end131:
Lset1347 = Ldebug_frame_end132-Ldebug_frame_begin132
	.long	Lset1347
Ldebug_frame_begin132:
Lset1348 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1348
	.quad	Lfunc_begin132
Lset1349 = Lfunc_end132-Lfunc_begin132
	.quad	Lset1349
	.byte	4
Lset1350 = Ltmp1470-Lfunc_begin132
	.long	Lset1350
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1351 = Ltmp1471-Ltmp1470
	.long	Lset1351
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end132:
Lset1352 = Ldebug_frame_end133-Ldebug_frame_begin133
	.long	Lset1352
Ldebug_frame_begin133:
Lset1353 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1353
	.quad	Lfunc_begin133
Lset1354 = Lfunc_end133-Lfunc_begin133
	.quad	Lset1354
	.byte	4
Lset1355 = Ltmp1476-Lfunc_begin133
	.long	Lset1355
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1356 = Ltmp1477-Ltmp1476
	.long	Lset1356
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end133:
Lset1357 = Ldebug_frame_end134-Ldebug_frame_begin134
	.long	Lset1357
Ldebug_frame_begin134:
Lset1358 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1358
	.quad	Lfunc_begin134
Lset1359 = Lfunc_end134-Lfunc_begin134
	.quad	Lset1359
	.byte	4
Lset1360 = Ltmp1482-Lfunc_begin134
	.long	Lset1360
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1361 = Ltmp1483-Ltmp1482
	.long	Lset1361
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end134:
Lset1362 = Ldebug_frame_end135-Ldebug_frame_begin135
	.long	Lset1362
Ldebug_frame_begin135:
Lset1363 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1363
	.quad	Lfunc_begin135
Lset1364 = Lfunc_end135-Lfunc_begin135
	.quad	Lset1364
	.byte	4
Lset1365 = Ltmp1488-Lfunc_begin135
	.long	Lset1365
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1366 = Ltmp1489-Ltmp1488
	.long	Lset1366
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end135:
Lset1367 = Ldebug_frame_end136-Ldebug_frame_begin136
	.long	Lset1367
Ldebug_frame_begin136:
Lset1368 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1368
	.quad	Lfunc_begin136
Lset1369 = Lfunc_end136-Lfunc_begin136
	.quad	Lset1369
	.byte	4
Lset1370 = Ltmp1494-Lfunc_begin136
	.long	Lset1370
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1371 = Ltmp1495-Ltmp1494
	.long	Lset1371
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end136:
Lset1372 = Ldebug_frame_end137-Ldebug_frame_begin137
	.long	Lset1372
Ldebug_frame_begin137:
Lset1373 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1373
	.quad	Lfunc_begin137
Lset1374 = Lfunc_end137-Lfunc_begin137
	.quad	Lset1374
	.byte	4
Lset1375 = Ltmp1500-Lfunc_begin137
	.long	Lset1375
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1376 = Ltmp1501-Ltmp1500
	.long	Lset1376
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end137:
Lset1377 = Ldebug_frame_end138-Ldebug_frame_begin138
	.long	Lset1377
Ldebug_frame_begin138:
Lset1378 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1378
	.quad	Lfunc_begin138
Lset1379 = Lfunc_end138-Lfunc_begin138
	.quad	Lset1379
	.byte	4
Lset1380 = Ltmp1506-Lfunc_begin138
	.long	Lset1380
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1381 = Ltmp1507-Ltmp1506
	.long	Lset1381
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end138:
	.section	__DWARF,__debug_info,regular,debug
Linfo_begin1:
	.long	40162
	.short	2
Lset1382 = Labbrev_begin-Lsection_abbrev
	.long	Lset1382
	.byte	8
	.byte	1
	.ascii	 "4.2.1 (Based on Apple Inc. build 5658) (LLVM build 2336.11.00)"
	.byte	0
	.byte	1
	.ascii	 "atomic.c"
	.byte	0
	.quad	0
	.long	0
	.ascii	 "/Users/will/repos/zfs/lib/libspl/asm-generic/"
	.byte	0
	.byte	2
	.long	416
	.ascii	 "atomic_inc_long"
	.byte	0
	.ascii	 "atomic_inc_long"
	.byte	0
	.byte	1
	.byte	51
	.byte	1
	.byte	1
	.quad	Lfunc_begin1
	.quad	Lfunc_end1
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	51
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp5
	.quad	Ltmp9
	.byte	5
	.long	327
	.quad	Ltmp5
	.quad	Ltmp6
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	51
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	51
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp5
	.quad	Ltmp6
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	51
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp8
	.quad	Ltmp9
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	51
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	51
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp8
	.quad	Ltmp9
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	51
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	7
	.long	533
	.ascii	 "__assert_c99"
	.byte	0
	.byte	2
	.byte	38
	.byte	1
	.quad	Lfunc_begin2
	.quad	Lfunc_end2
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "expr"
	.byte	0
	.byte	2
	.byte	37
	.long	40002
	.byte	2
	.byte	145
	.byte	120
	.byte	3
	.ascii	 "file"
	.byte	0
	.byte	2
	.byte	37
	.long	40002
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "line"
	.byte	0
	.byte	2
	.byte	37
	.long	37828
	.byte	2
	.byte	145
	.byte	108
	.byte	3
	.ascii	 "func"
	.byte	0
	.byte	2
	.byte	37
	.long	40002
	.byte	2
	.byte	145
	.byte	96
	.byte	8
	.quad	Ltmp14
	.quad	Ltmp16
	.byte	0
	.byte	2
	.long	800
	.ascii	 "atomic_inc_8"
	.byte	0
	.ascii	 "atomic_inc_8"
	.byte	0
	.byte	1
	.byte	52
	.byte	1
	.byte	1
	.quad	Lfunc_begin3
	.quad	Lfunc_end3
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	52
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp22
	.quad	Ltmp26
	.byte	5
	.long	711
	.quad	Ltmp22
	.quad	Ltmp23
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	52
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	52
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp22
	.quad	Ltmp23
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	52
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp25
	.quad	Ltmp26
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	52
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	52
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp25
	.quad	Ltmp26
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	52
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	1075
	.ascii	 "atomic_inc_uchar"
	.byte	0
	.ascii	 "atomic_inc_uchar"
	.byte	0
	.byte	1
	.byte	53
	.byte	1
	.byte	1
	.quad	Lfunc_begin4
	.quad	Lfunc_end4
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	53
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp32
	.quad	Ltmp36
	.byte	5
	.long	986
	.quad	Ltmp32
	.quad	Ltmp33
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	53
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	53
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp32
	.quad	Ltmp33
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	53
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp35
	.quad	Ltmp36
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	53
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	53
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp35
	.quad	Ltmp36
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	53
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	1344
	.ascii	 "atomic_inc_16"
	.byte	0
	.ascii	 "atomic_inc_16"
	.byte	0
	.byte	1
	.byte	54
	.byte	1
	.byte	1
	.quad	Lfunc_begin5
	.quad	Lfunc_end5
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	54
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp42
	.quad	Ltmp46
	.byte	5
	.long	1255
	.quad	Ltmp42
	.quad	Ltmp43
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	54
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	54
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp42
	.quad	Ltmp43
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	54
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp45
	.quad	Ltmp46
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	54
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	54
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp45
	.quad	Ltmp46
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	54
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	1621
	.ascii	 "atomic_inc_ushort"
	.byte	0
	.ascii	 "atomic_inc_ushort"
	.byte	0
	.byte	1
	.byte	55
	.byte	1
	.byte	1
	.quad	Lfunc_begin6
	.quad	Lfunc_end6
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	55
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp52
	.quad	Ltmp56
	.byte	5
	.long	1532
	.quad	Ltmp52
	.quad	Ltmp53
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	55
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	55
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp52
	.quad	Ltmp53
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	55
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp55
	.quad	Ltmp56
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	55
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	55
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp55
	.quad	Ltmp56
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	55
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	1890
	.ascii	 "atomic_inc_32"
	.byte	0
	.ascii	 "atomic_inc_32"
	.byte	0
	.byte	1
	.byte	56
	.byte	1
	.byte	1
	.quad	Lfunc_begin7
	.quad	Lfunc_end7
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	56
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp62
	.quad	Ltmp66
	.byte	5
	.long	1801
	.quad	Ltmp62
	.quad	Ltmp63
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	56
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	56
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp62
	.quad	Ltmp63
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	56
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp65
	.quad	Ltmp66
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	56
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	56
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp65
	.quad	Ltmp66
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	56
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	2163
	.ascii	 "atomic_inc_uint"
	.byte	0
	.ascii	 "atomic_inc_uint"
	.byte	0
	.byte	1
	.byte	57
	.byte	1
	.byte	1
	.quad	Lfunc_begin8
	.quad	Lfunc_end8
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	57
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp72
	.quad	Ltmp76
	.byte	5
	.long	2074
	.quad	Ltmp72
	.quad	Ltmp73
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	57
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	57
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp72
	.quad	Ltmp73
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	57
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp75
	.quad	Ltmp76
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	57
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	57
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp75
	.quad	Ltmp76
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	57
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	2438
	.ascii	 "atomic_inc_ulong"
	.byte	0
	.ascii	 "atomic_inc_ulong"
	.byte	0
	.byte	1
	.byte	58
	.byte	1
	.byte	1
	.quad	Lfunc_begin9
	.quad	Lfunc_end9
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	58
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp82
	.quad	Ltmp86
	.byte	5
	.long	2349
	.quad	Ltmp82
	.quad	Ltmp83
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	58
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	58
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp82
	.quad	Ltmp83
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	58
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp85
	.quad	Ltmp86
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	58
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	58
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp85
	.quad	Ltmp86
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	58
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	2707
	.ascii	 "atomic_inc_64"
	.byte	0
	.ascii	 "atomic_inc_64"
	.byte	0
	.byte	1
	.byte	59
	.byte	1
	.byte	1
	.quad	Lfunc_begin10
	.quad	Lfunc_end10
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	59
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp92
	.quad	Ltmp96
	.byte	5
	.long	2618
	.quad	Ltmp92
	.quad	Ltmp93
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	59
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	59
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp92
	.quad	Ltmp93
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	59
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp95
	.quad	Ltmp96
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	59
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	59
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp95
	.quad	Ltmp96
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	59
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	2980
	.ascii	 "atomic_dec_long"
	.byte	0
	.ascii	 "atomic_dec_long"
	.byte	0
	.byte	1
	.byte	70
	.byte	1
	.byte	1
	.quad	Lfunc_begin11
	.quad	Lfunc_end11
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	70
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp102
	.quad	Ltmp106
	.byte	5
	.long	2891
	.quad	Ltmp102
	.quad	Ltmp103
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	70
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	70
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp102
	.quad	Ltmp103
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	70
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp105
	.quad	Ltmp106
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	70
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	70
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp105
	.quad	Ltmp106
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	70
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	3247
	.ascii	 "atomic_dec_8"
	.byte	0
	.ascii	 "atomic_dec_8"
	.byte	0
	.byte	1
	.byte	71
	.byte	1
	.byte	1
	.quad	Lfunc_begin12
	.quad	Lfunc_end12
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	71
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp112
	.quad	Ltmp116
	.byte	5
	.long	3158
	.quad	Ltmp112
	.quad	Ltmp113
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	71
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	71
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp112
	.quad	Ltmp113
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	71
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp115
	.quad	Ltmp116
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	71
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	71
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp115
	.quad	Ltmp116
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	71
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	3522
	.ascii	 "atomic_dec_uchar"
	.byte	0
	.ascii	 "atomic_dec_uchar"
	.byte	0
	.byte	1
	.byte	72
	.byte	1
	.byte	1
	.quad	Lfunc_begin13
	.quad	Lfunc_end13
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	72
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp122
	.quad	Ltmp126
	.byte	5
	.long	3433
	.quad	Ltmp122
	.quad	Ltmp123
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	72
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	72
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp122
	.quad	Ltmp123
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	72
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp125
	.quad	Ltmp126
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	72
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	72
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp125
	.quad	Ltmp126
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	72
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	3791
	.ascii	 "atomic_dec_16"
	.byte	0
	.ascii	 "atomic_dec_16"
	.byte	0
	.byte	1
	.byte	73
	.byte	1
	.byte	1
	.quad	Lfunc_begin14
	.quad	Lfunc_end14
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	73
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp132
	.quad	Ltmp136
	.byte	5
	.long	3702
	.quad	Ltmp132
	.quad	Ltmp133
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	73
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	73
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp132
	.quad	Ltmp133
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	73
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp135
	.quad	Ltmp136
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	73
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	73
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp135
	.quad	Ltmp136
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	73
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	4068
	.ascii	 "atomic_dec_ushort"
	.byte	0
	.ascii	 "atomic_dec_ushort"
	.byte	0
	.byte	1
	.byte	74
	.byte	1
	.byte	1
	.quad	Lfunc_begin15
	.quad	Lfunc_end15
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	74
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp142
	.quad	Ltmp146
	.byte	5
	.long	3979
	.quad	Ltmp142
	.quad	Ltmp143
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	74
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	74
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp142
	.quad	Ltmp143
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	74
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp145
	.quad	Ltmp146
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	74
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	74
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp145
	.quad	Ltmp146
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	74
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	4337
	.ascii	 "atomic_dec_32"
	.byte	0
	.ascii	 "atomic_dec_32"
	.byte	0
	.byte	1
	.byte	75
	.byte	1
	.byte	1
	.quad	Lfunc_begin16
	.quad	Lfunc_end16
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	75
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp152
	.quad	Ltmp156
	.byte	5
	.long	4248
	.quad	Ltmp152
	.quad	Ltmp153
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	75
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	75
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp152
	.quad	Ltmp153
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	75
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp155
	.quad	Ltmp156
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	75
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	75
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp155
	.quad	Ltmp156
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	75
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	4610
	.ascii	 "atomic_dec_uint"
	.byte	0
	.ascii	 "atomic_dec_uint"
	.byte	0
	.byte	1
	.byte	76
	.byte	1
	.byte	1
	.quad	Lfunc_begin17
	.quad	Lfunc_end17
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	76
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp162
	.quad	Ltmp166
	.byte	5
	.long	4521
	.quad	Ltmp162
	.quad	Ltmp163
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	76
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	76
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp162
	.quad	Ltmp163
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	76
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp165
	.quad	Ltmp166
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	76
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	76
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp165
	.quad	Ltmp166
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	76
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	4885
	.ascii	 "atomic_dec_ulong"
	.byte	0
	.ascii	 "atomic_dec_ulong"
	.byte	0
	.byte	1
	.byte	77
	.byte	1
	.byte	1
	.quad	Lfunc_begin18
	.quad	Lfunc_end18
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	77
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp172
	.quad	Ltmp176
	.byte	5
	.long	4796
	.quad	Ltmp172
	.quad	Ltmp173
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	77
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	77
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp172
	.quad	Ltmp173
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	77
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp175
	.quad	Ltmp176
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	77
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	77
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp175
	.quad	Ltmp176
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	77
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	5154
	.ascii	 "atomic_dec_64"
	.byte	0
	.ascii	 "atomic_dec_64"
	.byte	0
	.byte	1
	.byte	78
	.byte	1
	.byte	1
	.quad	Lfunc_begin19
	.quad	Lfunc_end19
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	78
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp182
	.quad	Ltmp186
	.byte	5
	.long	5065
	.quad	Ltmp182
	.quad	Ltmp183
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	78
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	78
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp182
	.quad	Ltmp183
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	78
	.long	39986
	.byte	2
	.byte	145
	.byte	88
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp185
	.quad	Ltmp186
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	78
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	78
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp185
	.quad	Ltmp186
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	78
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	5437
	.ascii	 "atomic_add_8"
	.byte	0
	.ascii	 "atomic_add_8"
	.byte	0
	.byte	1
	.byte	89
	.byte	1
	.byte	1
	.quad	Lfunc_begin20
	.quad	Lfunc_end20
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	89
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	89
	.long	40089
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp192
	.quad	Ltmp196
	.byte	5
	.long	5347
	.quad	Ltmp192
	.quad	Ltmp193
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	89
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	89
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp192
	.quad	Ltmp193
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	89
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp195
	.quad	Ltmp196
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	89
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	89
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp195
	.quad	Ltmp196
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	89
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	5726
	.ascii	 "atomic_add_char"
	.byte	0
	.ascii	 "atomic_add_char"
	.byte	0
	.byte	1
	.byte	90
	.byte	1
	.byte	1
	.quad	Lfunc_begin21
	.quad	Lfunc_end21
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	90
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	90
	.long	40074
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp202
	.quad	Ltmp206
	.byte	5
	.long	5636
	.quad	Ltmp202
	.quad	Ltmp203
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	90
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	90
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp202
	.quad	Ltmp203
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	90
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp205
	.quad	Ltmp206
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	90
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	90
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp205
	.quad	Ltmp206
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	90
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	6011
	.ascii	 "atomic_add_16"
	.byte	0
	.ascii	 "atomic_add_16"
	.byte	0
	.byte	1
	.byte	91
	.byte	1
	.byte	1
	.quad	Lfunc_begin22
	.quad	Lfunc_end22
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	91
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	91
	.long	40116
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp212
	.quad	Ltmp216
	.byte	5
	.long	5921
	.quad	Ltmp212
	.quad	Ltmp213
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	91
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	91
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp212
	.quad	Ltmp213
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	91
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp215
	.quad	Ltmp216
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	91
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	91
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp215
	.quad	Ltmp216
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	91
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	6302
	.ascii	 "atomic_add_short"
	.byte	0
	.ascii	 "atomic_add_short"
	.byte	0
	.byte	1
	.byte	92
	.byte	1
	.byte	1
	.quad	Lfunc_begin23
	.quad	Lfunc_end23
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	92
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	92
	.long	40103
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp222
	.quad	Ltmp226
	.byte	5
	.long	6212
	.quad	Ltmp222
	.quad	Ltmp223
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	92
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	92
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp222
	.quad	Ltmp223
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	92
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp225
	.quad	Ltmp226
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	92
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	92
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp225
	.quad	Ltmp226
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	92
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	6587
	.ascii	 "atomic_add_32"
	.byte	0
	.ascii	 "atomic_add_32"
	.byte	0
	.byte	1
	.byte	93
	.byte	1
	.byte	1
	.quad	Lfunc_begin24
	.quad	Lfunc_end24
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	93
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	93
	.long	40131
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp232
	.quad	Ltmp236
	.byte	5
	.long	6497
	.quad	Ltmp232
	.quad	Ltmp233
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	93
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	93
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp232
	.quad	Ltmp233
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	93
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp235
	.quad	Ltmp236
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	93
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	93
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp235
	.quad	Ltmp236
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	93
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	6874
	.ascii	 "atomic_add_int"
	.byte	0
	.ascii	 "atomic_add_int"
	.byte	0
	.byte	1
	.byte	94
	.byte	1
	.byte	1
	.quad	Lfunc_begin25
	.quad	Lfunc_end25
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	94
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	94
	.long	37828
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp242
	.quad	Ltmp246
	.byte	5
	.long	6784
	.quad	Ltmp242
	.quad	Ltmp243
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	94
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	94
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp242
	.quad	Ltmp243
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	94
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp245
	.quad	Ltmp246
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	94
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	94
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp245
	.quad	Ltmp246
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	94
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	7163
	.ascii	 "atomic_add_long"
	.byte	0
	.ascii	 "atomic_add_long"
	.byte	0
	.byte	1
	.byte	95
	.byte	1
	.byte	1
	.quad	Lfunc_begin26
	.quad	Lfunc_end26
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	95
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	95
	.long	39777
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp252
	.quad	Ltmp256
	.byte	5
	.long	7073
	.quad	Ltmp252
	.quad	Ltmp253
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	95
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	95
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp252
	.quad	Ltmp253
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	95
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp255
	.quad	Ltmp256
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	95
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	95
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp255
	.quad	Ltmp256
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	95
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	7448
	.ascii	 "atomic_add_64"
	.byte	0
	.ascii	 "atomic_add_64"
	.byte	0
	.byte	1
	.byte	96
	.byte	1
	.byte	1
	.quad	Lfunc_begin27
	.quad	Lfunc_end27
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	96
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	96
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp262
	.quad	Ltmp266
	.byte	5
	.long	7358
	.quad	Ltmp262
	.quad	Ltmp263
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	96
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	96
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp262
	.quad	Ltmp263
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	96
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp265
	.quad	Ltmp266
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	96
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	96
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp265
	.quad	Ltmp266
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	96
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	7735
	.ascii	 "atomic_add_ptr"
	.byte	0
	.ascii	 "atomic_add_ptr"
	.byte	0
	.byte	1
	.byte	99
	.byte	1
	.byte	1
	.quad	Lfunc_begin28
	.quad	Lfunc_end28
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	98
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	98
	.long	40146
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp271
	.quad	Ltmp278
	.byte	5
	.long	7645
	.quad	Ltmp271
	.quad	Ltmp273
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	100
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	100
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp272
	.quad	Ltmp273
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	100
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp275
	.quad	Ltmp278
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	102
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	102
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp276
	.quad	Ltmp278
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	102
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	8018
	.ascii	 "atomic_sub_8"
	.byte	0
	.ascii	 "atomic_sub_8"
	.byte	0
	.byte	1
	.byte	114
	.byte	1
	.byte	1
	.quad	Lfunc_begin29
	.quad	Lfunc_end29
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	114
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	114
	.long	40089
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp284
	.quad	Ltmp288
	.byte	5
	.long	7928
	.quad	Ltmp284
	.quad	Ltmp285
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	114
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	114
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp284
	.quad	Ltmp285
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	114
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp287
	.quad	Ltmp288
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	114
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	114
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp287
	.quad	Ltmp288
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	114
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	8307
	.ascii	 "atomic_sub_char"
	.byte	0
	.ascii	 "atomic_sub_char"
	.byte	0
	.byte	1
	.byte	115
	.byte	1
	.byte	1
	.quad	Lfunc_begin30
	.quad	Lfunc_end30
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	115
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	115
	.long	40074
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp294
	.quad	Ltmp298
	.byte	5
	.long	8217
	.quad	Ltmp294
	.quad	Ltmp295
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	115
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	115
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp294
	.quad	Ltmp295
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	115
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp297
	.quad	Ltmp298
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	115
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	115
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp297
	.quad	Ltmp298
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	115
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	8592
	.ascii	 "atomic_sub_16"
	.byte	0
	.ascii	 "atomic_sub_16"
	.byte	0
	.byte	1
	.byte	116
	.byte	1
	.byte	1
	.quad	Lfunc_begin31
	.quad	Lfunc_end31
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	116
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	116
	.long	40116
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp304
	.quad	Ltmp308
	.byte	5
	.long	8502
	.quad	Ltmp304
	.quad	Ltmp305
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	116
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	116
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp304
	.quad	Ltmp305
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	116
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp307
	.quad	Ltmp308
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	116
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	116
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp307
	.quad	Ltmp308
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	116
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	8883
	.ascii	 "atomic_sub_short"
	.byte	0
	.ascii	 "atomic_sub_short"
	.byte	0
	.byte	1
	.byte	117
	.byte	1
	.byte	1
	.quad	Lfunc_begin32
	.quad	Lfunc_end32
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	117
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	117
	.long	40103
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp314
	.quad	Ltmp318
	.byte	5
	.long	8793
	.quad	Ltmp314
	.quad	Ltmp315
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	117
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	117
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp314
	.quad	Ltmp315
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	117
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp317
	.quad	Ltmp318
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	117
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	117
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp317
	.quad	Ltmp318
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	117
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	9168
	.ascii	 "atomic_sub_32"
	.byte	0
	.ascii	 "atomic_sub_32"
	.byte	0
	.byte	1
	.byte	118
	.byte	1
	.byte	1
	.quad	Lfunc_begin33
	.quad	Lfunc_end33
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	118
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	118
	.long	40131
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp324
	.quad	Ltmp328
	.byte	5
	.long	9078
	.quad	Ltmp324
	.quad	Ltmp325
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	118
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	118
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp324
	.quad	Ltmp325
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	118
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp327
	.quad	Ltmp328
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	118
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	118
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp327
	.quad	Ltmp328
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	118
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	9455
	.ascii	 "atomic_sub_int"
	.byte	0
	.ascii	 "atomic_sub_int"
	.byte	0
	.byte	1
	.byte	119
	.byte	1
	.byte	1
	.quad	Lfunc_begin34
	.quad	Lfunc_end34
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	119
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	119
	.long	37828
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp334
	.quad	Ltmp338
	.byte	5
	.long	9365
	.quad	Ltmp334
	.quad	Ltmp335
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	119
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	119
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp334
	.quad	Ltmp335
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	119
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp337
	.quad	Ltmp338
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	119
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	119
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp337
	.quad	Ltmp338
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	119
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	9744
	.ascii	 "atomic_sub_long"
	.byte	0
	.ascii	 "atomic_sub_long"
	.byte	0
	.byte	1
	.byte	120
	.byte	1
	.byte	1
	.quad	Lfunc_begin35
	.quad	Lfunc_end35
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	120
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	120
	.long	39777
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp344
	.quad	Ltmp348
	.byte	5
	.long	9654
	.quad	Ltmp344
	.quad	Ltmp345
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	120
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	120
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp344
	.quad	Ltmp345
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	120
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp347
	.quad	Ltmp348
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	120
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	120
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp347
	.quad	Ltmp348
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	120
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	10029
	.ascii	 "atomic_sub_64"
	.byte	0
	.ascii	 "atomic_sub_64"
	.byte	0
	.byte	1
	.byte	121
	.byte	1
	.byte	1
	.quad	Lfunc_begin36
	.quad	Lfunc_end36
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	121
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	121
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp354
	.quad	Ltmp358
	.byte	5
	.long	9939
	.quad	Ltmp354
	.quad	Ltmp355
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	121
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	121
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp354
	.quad	Ltmp355
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	121
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp357
	.quad	Ltmp358
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	121
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	121
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp357
	.quad	Ltmp358
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	121
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	10316
	.ascii	 "atomic_sub_ptr"
	.byte	0
	.ascii	 "atomic_sub_ptr"
	.byte	0
	.byte	1
	.byte	124
	.byte	1
	.byte	1
	.quad	Lfunc_begin37
	.quad	Lfunc_end37
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	123
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	123
	.long	40146
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp363
	.quad	Ltmp370
	.byte	5
	.long	10226
	.quad	Ltmp363
	.quad	Ltmp365
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	125
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	125
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp364
	.quad	Ltmp365
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	125
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp367
	.quad	Ltmp370
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	127
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	127
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp368
	.quad	Ltmp370
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	127
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	10597
	.ascii	 "atomic_or_8"
	.byte	0
	.ascii	 "atomic_or_8"
	.byte	0
	.byte	1
	.byte	139
	.byte	1
	.byte	1
	.quad	Lfunc_begin38
	.quad	Lfunc_end38
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	139
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	139
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp376
	.quad	Ltmp380
	.byte	5
	.long	10507
	.quad	Ltmp376
	.quad	Ltmp377
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	139
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	139
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp376
	.quad	Ltmp377
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	139
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp379
	.quad	Ltmp380
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	139
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	139
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp379
	.quad	Ltmp380
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	139
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	10886
	.ascii	 "atomic_or_uchar"
	.byte	0
	.ascii	 "atomic_or_uchar"
	.byte	0
	.byte	1
	.byte	140
	.byte	1
	.byte	1
	.quad	Lfunc_begin39
	.quad	Lfunc_end39
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	140
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	140
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp386
	.quad	Ltmp390
	.byte	5
	.long	10796
	.quad	Ltmp386
	.quad	Ltmp387
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	140
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	140
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp386
	.quad	Ltmp387
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	140
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp389
	.quad	Ltmp390
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	140
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	140
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp389
	.quad	Ltmp390
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	140
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	11169
	.ascii	 "atomic_or_16"
	.byte	0
	.ascii	 "atomic_or_16"
	.byte	0
	.byte	1
	.byte	141
	.byte	1
	.byte	1
	.quad	Lfunc_begin40
	.quad	Lfunc_end40
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	141
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	141
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp396
	.quad	Ltmp400
	.byte	5
	.long	11079
	.quad	Ltmp396
	.quad	Ltmp397
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	141
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	141
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp396
	.quad	Ltmp397
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	141
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp399
	.quad	Ltmp400
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	141
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	141
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp399
	.quad	Ltmp400
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	141
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	11460
	.ascii	 "atomic_or_ushort"
	.byte	0
	.ascii	 "atomic_or_ushort"
	.byte	0
	.byte	1
	.byte	142
	.byte	1
	.byte	1
	.quad	Lfunc_begin41
	.quad	Lfunc_end41
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	142
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	142
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp406
	.quad	Ltmp410
	.byte	5
	.long	11370
	.quad	Ltmp406
	.quad	Ltmp407
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	142
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	142
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp406
	.quad	Ltmp407
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	142
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp409
	.quad	Ltmp410
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	142
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	142
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp409
	.quad	Ltmp410
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	142
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	11743
	.ascii	 "atomic_or_32"
	.byte	0
	.ascii	 "atomic_or_32"
	.byte	0
	.byte	1
	.byte	143
	.byte	1
	.byte	1
	.quad	Lfunc_begin42
	.quad	Lfunc_end42
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	143
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	143
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp416
	.quad	Ltmp420
	.byte	5
	.long	11653
	.quad	Ltmp416
	.quad	Ltmp417
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	143
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	143
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp416
	.quad	Ltmp417
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	143
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp419
	.quad	Ltmp420
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	143
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	143
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp419
	.quad	Ltmp420
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	143
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	12030
	.ascii	 "atomic_or_uint"
	.byte	0
	.ascii	 "atomic_or_uint"
	.byte	0
	.byte	1
	.byte	144
	.byte	1
	.byte	1
	.quad	Lfunc_begin43
	.quad	Lfunc_end43
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	144
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	144
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp426
	.quad	Ltmp430
	.byte	5
	.long	11940
	.quad	Ltmp426
	.quad	Ltmp427
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	144
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	144
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp426
	.quad	Ltmp427
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	144
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp429
	.quad	Ltmp430
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	144
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	144
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp429
	.quad	Ltmp430
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	144
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	12319
	.ascii	 "atomic_or_ulong"
	.byte	0
	.ascii	 "atomic_or_ulong"
	.byte	0
	.byte	1
	.byte	145
	.byte	1
	.byte	1
	.quad	Lfunc_begin44
	.quad	Lfunc_end44
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	145
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	145
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp436
	.quad	Ltmp440
	.byte	5
	.long	12229
	.quad	Ltmp436
	.quad	Ltmp437
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	145
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	145
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp436
	.quad	Ltmp437
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	145
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp439
	.quad	Ltmp440
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	145
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	145
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp439
	.quad	Ltmp440
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	145
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	12602
	.ascii	 "atomic_or_64"
	.byte	0
	.ascii	 "atomic_or_64"
	.byte	0
	.byte	1
	.byte	146
	.byte	1
	.byte	1
	.quad	Lfunc_begin45
	.quad	Lfunc_end45
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	146
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	146
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp446
	.quad	Ltmp450
	.byte	5
	.long	12512
	.quad	Ltmp446
	.quad	Ltmp447
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	146
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	146
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp446
	.quad	Ltmp447
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	146
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp449
	.quad	Ltmp450
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	146
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	146
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp449
	.quad	Ltmp450
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	146
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	12885
	.ascii	 "atomic_and_8"
	.byte	0
	.ascii	 "atomic_and_8"
	.byte	0
	.byte	1
	.byte	157
	.byte	1
	.byte	1
	.quad	Lfunc_begin46
	.quad	Lfunc_end46
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	157
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	157
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp456
	.quad	Ltmp460
	.byte	5
	.long	12795
	.quad	Ltmp456
	.quad	Ltmp457
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	157
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	157
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp456
	.quad	Ltmp457
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	157
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp459
	.quad	Ltmp460
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	157
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	157
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp459
	.quad	Ltmp460
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	157
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	13176
	.ascii	 "atomic_and_uchar"
	.byte	0
	.ascii	 "atomic_and_uchar"
	.byte	0
	.byte	1
	.byte	158
	.byte	1
	.byte	1
	.quad	Lfunc_begin47
	.quad	Lfunc_end47
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	158
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	158
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp466
	.quad	Ltmp470
	.byte	5
	.long	13086
	.quad	Ltmp466
	.quad	Ltmp467
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	158
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	158
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp466
	.quad	Ltmp467
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	158
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp469
	.quad	Ltmp470
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	158
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	158
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp469
	.quad	Ltmp470
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	158
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	13461
	.ascii	 "atomic_and_16"
	.byte	0
	.ascii	 "atomic_and_16"
	.byte	0
	.byte	1
	.byte	159
	.byte	1
	.byte	1
	.quad	Lfunc_begin48
	.quad	Lfunc_end48
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	159
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	159
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp476
	.quad	Ltmp480
	.byte	5
	.long	13371
	.quad	Ltmp476
	.quad	Ltmp477
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	159
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	159
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp476
	.quad	Ltmp477
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	159
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp479
	.quad	Ltmp480
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	159
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	159
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp479
	.quad	Ltmp480
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	159
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	13754
	.ascii	 "atomic_and_ushort"
	.byte	0
	.ascii	 "atomic_and_ushort"
	.byte	0
	.byte	1
	.byte	160
	.byte	1
	.byte	1
	.quad	Lfunc_begin49
	.quad	Lfunc_end49
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	160
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	160
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp486
	.quad	Ltmp490
	.byte	5
	.long	13664
	.quad	Ltmp486
	.quad	Ltmp487
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	160
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	160
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp486
	.quad	Ltmp487
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	160
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp489
	.quad	Ltmp490
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	160
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	160
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp489
	.quad	Ltmp490
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	160
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	14039
	.ascii	 "atomic_and_32"
	.byte	0
	.ascii	 "atomic_and_32"
	.byte	0
	.byte	1
	.byte	161
	.byte	1
	.byte	1
	.quad	Lfunc_begin50
	.quad	Lfunc_end50
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	161
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	161
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp496
	.quad	Ltmp500
	.byte	5
	.long	13949
	.quad	Ltmp496
	.quad	Ltmp497
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	161
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	161
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp496
	.quad	Ltmp497
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	161
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp499
	.quad	Ltmp500
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	161
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	161
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp499
	.quad	Ltmp500
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	161
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	14328
	.ascii	 "atomic_and_uint"
	.byte	0
	.ascii	 "atomic_and_uint"
	.byte	0
	.byte	1
	.byte	162
	.byte	1
	.byte	1
	.quad	Lfunc_begin51
	.quad	Lfunc_end51
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	162
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	162
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp506
	.quad	Ltmp510
	.byte	5
	.long	14238
	.quad	Ltmp506
	.quad	Ltmp507
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	162
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	162
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp506
	.quad	Ltmp507
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	162
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp509
	.quad	Ltmp510
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	162
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	162
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp509
	.quad	Ltmp510
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	162
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	14619
	.ascii	 "atomic_and_ulong"
	.byte	0
	.ascii	 "atomic_and_ulong"
	.byte	0
	.byte	1
	.byte	163
	.byte	1
	.byte	1
	.quad	Lfunc_begin52
	.quad	Lfunc_end52
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	163
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	163
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp516
	.quad	Ltmp520
	.byte	5
	.long	14529
	.quad	Ltmp516
	.quad	Ltmp517
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	163
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	163
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp516
	.quad	Ltmp517
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	163
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp519
	.quad	Ltmp520
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	163
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	163
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp519
	.quad	Ltmp520
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	163
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	14904
	.ascii	 "atomic_and_64"
	.byte	0
	.ascii	 "atomic_and_64"
	.byte	0
	.byte	1
	.byte	164
	.byte	1
	.byte	1
	.quad	Lfunc_begin53
	.quad	Lfunc_end53
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	164
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	164
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp526
	.quad	Ltmp530
	.byte	5
	.long	14814
	.quad	Ltmp526
	.quad	Ltmp527
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	164
	.long	39971
	.byte	2
	.byte	145
	.byte	96
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	164
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	4
	.quad	Ltmp526
	.quad	Ltmp527
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	164
	.long	39986
	.byte	2
	.byte	145
	.byte	80
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp529
	.quad	Ltmp530
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	164
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	164
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp529
	.quad	Ltmp530
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	164
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	7
	.ascii	 "long unsigned int"
	.byte	0
	.byte	8
	.byte	10
	.long	15224
	.ascii	 "atomic_inc_long_nv"
	.byte	0
	.ascii	 "atomic_inc_long_nv"
	.byte	0
	.byte	1
	.byte	181
	.byte	1
	.long	14904
	.byte	1
	.quad	Lfunc_begin54
	.quad	Lfunc_end54
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	181
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp536
	.quad	Ltmp542
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	181
	.long	14904
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	15132
	.quad	Ltmp536
	.quad	Ltmp537
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	181
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	181
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp536
	.quad	Ltmp537
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	181
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp539
	.quad	Ltmp540
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	181
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	181
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp539
	.quad	Ltmp540
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	181
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	8
	.ascii	 "unsigned char"
	.byte	0
	.byte	1
	.byte	11
	.long	15224
	.ascii	 "uint8_t"
	.byte	0
	.byte	1
	.byte	40
	.byte	10
	.long	15548
	.ascii	 "atomic_inc_8_nv"
	.byte	0
	.ascii	 "atomic_inc_8_nv"
	.byte	0
	.byte	1
	.byte	182
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin55
	.quad	Lfunc_end55
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	182
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp548
	.quad	Ltmp554
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	182
	.long	15241
	.byte	2
	.byte	145
	.byte	103
	.byte	5
	.long	15457
	.quad	Ltmp548
	.quad	Ltmp549
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	182
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	182
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp548
	.quad	Ltmp549
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	182
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp551
	.quad	Ltmp552
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	182
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	182
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp551
	.quad	Ltmp552
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	182
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	11
	.long	15224
	.ascii	 "uchar_t"
	.byte	0
	.byte	1
	.byte	42
	.byte	10
	.long	15863
	.ascii	 "atomic_inc_uchar_nv"
	.byte	0
	.ascii	 "atomic_inc_uchar_nv"
	.byte	0
	.byte	1
	.byte	183
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin56
	.quad	Lfunc_end56
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	183
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp560
	.quad	Ltmp566
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	183
	.long	15548
	.byte	2
	.byte	145
	.byte	103
	.byte	5
	.long	15772
	.quad	Ltmp560
	.quad	Ltmp561
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	183
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	183
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp560
	.quad	Ltmp561
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	183
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp563
	.quad	Ltmp564
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	183
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	183
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp563
	.quad	Ltmp564
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	183
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	7
	.ascii	 "short unsigned int"
	.byte	0
	.byte	2
	.byte	11
	.long	15863
	.ascii	 "uint16_t"
	.byte	0
	.byte	1
	.byte	45
	.byte	10
	.long	16195
	.ascii	 "atomic_inc_16_nv"
	.byte	0
	.ascii	 "atomic_inc_16_nv"
	.byte	0
	.byte	1
	.byte	184
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin57
	.quad	Lfunc_end57
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	184
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp572
	.quad	Ltmp578
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	184
	.long	15885
	.byte	2
	.byte	145
	.byte	102
	.byte	5
	.long	16104
	.quad	Ltmp572
	.quad	Ltmp573
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	184
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	184
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp572
	.quad	Ltmp573
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	184
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp575
	.quad	Ltmp576
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	184
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	184
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp575
	.quad	Ltmp576
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	184
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	11
	.long	15863
	.ascii	 "ushort_t"
	.byte	0
	.byte	1
	.byte	43
	.byte	10
	.long	16513
	.ascii	 "atomic_inc_ushort_nv"
	.byte	0
	.ascii	 "atomic_inc_ushort_nv"
	.byte	0
	.byte	1
	.byte	185
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin58
	.quad	Lfunc_end58
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	185
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp584
	.quad	Ltmp590
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	185
	.long	16195
	.byte	2
	.byte	145
	.byte	102
	.byte	5
	.long	16422
	.quad	Ltmp584
	.quad	Ltmp585
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	185
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	185
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp584
	.quad	Ltmp585
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	185
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp587
	.quad	Ltmp588
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	185
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	185
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp587
	.quad	Ltmp588
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	185
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	7
	.ascii	 "unsigned int"
	.byte	0
	.byte	4
	.byte	11
	.long	16513
	.ascii	 "uint32_t"
	.byte	0
	.byte	1
	.byte	50
	.byte	10
	.long	16839
	.ascii	 "atomic_inc_32_nv"
	.byte	0
	.ascii	 "atomic_inc_32_nv"
	.byte	0
	.byte	1
	.byte	186
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin59
	.quad	Lfunc_end59
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	186
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp596
	.quad	Ltmp602
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	186
	.long	16529
	.byte	2
	.byte	145
	.byte	100
	.byte	5
	.long	16748
	.quad	Ltmp596
	.quad	Ltmp597
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	186
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	186
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp596
	.quad	Ltmp597
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	186
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp599
	.quad	Ltmp600
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	186
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	186
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp599
	.quad	Ltmp600
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	186
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	11
	.long	16513
	.ascii	 "uint_t"
	.byte	0
	.byte	1
	.byte	44
	.byte	10
	.long	17151
	.ascii	 "atomic_inc_uint_nv"
	.byte	0
	.ascii	 "atomic_inc_uint_nv"
	.byte	0
	.byte	1
	.byte	187
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin60
	.quad	Lfunc_end60
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	187
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp608
	.quad	Ltmp614
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	187
	.long	16839
	.byte	2
	.byte	145
	.byte	100
	.byte	5
	.long	17060
	.quad	Ltmp608
	.quad	Ltmp609
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	187
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	187
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp608
	.quad	Ltmp609
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	187
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp611
	.quad	Ltmp612
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	187
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	187
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp611
	.quad	Ltmp612
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	187
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	11
	.long	14904
	.ascii	 "ulong_t"
	.byte	0
	.byte	1
	.byte	45
	.byte	10
	.long	17467
	.ascii	 "atomic_inc_ulong_nv"
	.byte	0
	.ascii	 "atomic_inc_ulong_nv"
	.byte	0
	.byte	1
	.byte	188
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin61
	.quad	Lfunc_end61
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	188
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp620
	.quad	Ltmp626
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	188
	.long	17151
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	17375
	.quad	Ltmp620
	.quad	Ltmp621
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	188
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	188
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp620
	.quad	Ltmp621
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	188
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp623
	.quad	Ltmp624
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	188
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	188
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp623
	.quad	Ltmp624
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	188
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	7
	.ascii	 "long long unsigned int"
	.byte	0
	.byte	8
	.byte	11
	.long	17467
	.ascii	 "uint64_t"
	.byte	0
	.byte	1
	.byte	55
	.byte	10
	.long	17804
	.ascii	 "atomic_inc_64_nv"
	.byte	0
	.ascii	 "atomic_inc_64_nv"
	.byte	0
	.byte	1
	.byte	189
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin62
	.quad	Lfunc_end62
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	189
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp632
	.quad	Ltmp638
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	189
	.long	17493
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	17712
	.quad	Ltmp632
	.quad	Ltmp633
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	189
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	189
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp632
	.quad	Ltmp633
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	189
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp635
	.quad	Ltmp636
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	189
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	189
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp635
	.quad	Ltmp636
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	189
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	18103
	.ascii	 "atomic_dec_long_nv"
	.byte	0
	.ascii	 "atomic_dec_long_nv"
	.byte	0
	.byte	1
	.byte	202
	.byte	1
	.long	14904
	.byte	1
	.quad	Lfunc_begin63
	.quad	Lfunc_end63
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	202
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp644
	.quad	Ltmp650
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	202
	.long	14904
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	18011
	.quad	Ltmp644
	.quad	Ltmp645
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	202
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	202
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp644
	.quad	Ltmp645
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	202
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp647
	.quad	Ltmp648
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	202
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	202
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp647
	.quad	Ltmp648
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	202
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	18395
	.ascii	 "atomic_dec_8_nv"
	.byte	0
	.ascii	 "atomic_dec_8_nv"
	.byte	0
	.byte	1
	.byte	203
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin64
	.quad	Lfunc_end64
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	203
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp656
	.quad	Ltmp662
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	203
	.long	15241
	.byte	2
	.byte	145
	.byte	103
	.byte	5
	.long	18304
	.quad	Ltmp656
	.quad	Ltmp657
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	203
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	203
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp656
	.quad	Ltmp657
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	203
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp659
	.quad	Ltmp660
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	203
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	203
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp659
	.quad	Ltmp660
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	203
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	18695
	.ascii	 "atomic_dec_uchar_nv"
	.byte	0
	.ascii	 "atomic_dec_uchar_nv"
	.byte	0
	.byte	1
	.byte	204
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin65
	.quad	Lfunc_end65
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	204
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp668
	.quad	Ltmp674
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	204
	.long	15548
	.byte	2
	.byte	145
	.byte	103
	.byte	5
	.long	18604
	.quad	Ltmp668
	.quad	Ltmp669
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	204
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	204
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp668
	.quad	Ltmp669
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	204
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp671
	.quad	Ltmp672
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	204
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	204
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp671
	.quad	Ltmp672
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	204
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	18989
	.ascii	 "atomic_dec_16_nv"
	.byte	0
	.ascii	 "atomic_dec_16_nv"
	.byte	0
	.byte	1
	.byte	205
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin66
	.quad	Lfunc_end66
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	205
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp680
	.quad	Ltmp686
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	205
	.long	15885
	.byte	2
	.byte	145
	.byte	102
	.byte	5
	.long	18898
	.quad	Ltmp680
	.quad	Ltmp681
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	205
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	205
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp680
	.quad	Ltmp681
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	205
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp683
	.quad	Ltmp684
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	205
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	205
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp683
	.quad	Ltmp684
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	205
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	19291
	.ascii	 "atomic_dec_ushort_nv"
	.byte	0
	.ascii	 "atomic_dec_ushort_nv"
	.byte	0
	.byte	1
	.byte	206
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin67
	.quad	Lfunc_end67
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	206
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp692
	.quad	Ltmp698
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	206
	.long	16195
	.byte	2
	.byte	145
	.byte	102
	.byte	5
	.long	19200
	.quad	Ltmp692
	.quad	Ltmp693
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	206
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	206
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp692
	.quad	Ltmp693
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	206
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp695
	.quad	Ltmp696
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	206
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	206
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp695
	.quad	Ltmp696
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	206
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	19585
	.ascii	 "atomic_dec_32_nv"
	.byte	0
	.ascii	 "atomic_dec_32_nv"
	.byte	0
	.byte	1
	.byte	207
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin68
	.quad	Lfunc_end68
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	207
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp704
	.quad	Ltmp710
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	207
	.long	16529
	.byte	2
	.byte	145
	.byte	100
	.byte	5
	.long	19494
	.quad	Ltmp704
	.quad	Ltmp705
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	207
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	207
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp704
	.quad	Ltmp705
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	207
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp707
	.quad	Ltmp708
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	207
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	207
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp707
	.quad	Ltmp708
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	207
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	19883
	.ascii	 "atomic_dec_uint_nv"
	.byte	0
	.ascii	 "atomic_dec_uint_nv"
	.byte	0
	.byte	1
	.byte	208
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin69
	.quad	Lfunc_end69
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	208
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp716
	.quad	Ltmp722
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	208
	.long	16839
	.byte	2
	.byte	145
	.byte	100
	.byte	5
	.long	19792
	.quad	Ltmp716
	.quad	Ltmp717
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	208
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	208
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp716
	.quad	Ltmp717
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	208
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp719
	.quad	Ltmp720
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	208
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	208
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp719
	.quad	Ltmp720
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	208
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	20184
	.ascii	 "atomic_dec_ulong_nv"
	.byte	0
	.ascii	 "atomic_dec_ulong_nv"
	.byte	0
	.byte	1
	.byte	209
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin70
	.quad	Lfunc_end70
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	209
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp728
	.quad	Ltmp734
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	209
	.long	17151
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	20092
	.quad	Ltmp728
	.quad	Ltmp729
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	209
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	209
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp728
	.quad	Ltmp729
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	209
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp731
	.quad	Ltmp732
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	209
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	209
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp731
	.quad	Ltmp732
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	209
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	20479
	.ascii	 "atomic_dec_64_nv"
	.byte	0
	.ascii	 "atomic_dec_64_nv"
	.byte	0
	.byte	1
	.byte	210
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin71
	.quad	Lfunc_end71
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	210
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	4
	.quad	Ltmp740
	.quad	Ltmp746
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	210
	.long	17493
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	20387
	.quad	Ltmp740
	.quad	Ltmp741
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	210
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	210
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp740
	.quad	Ltmp741
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	210
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp743
	.quad	Ltmp744
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	210
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	210
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp743
	.quad	Ltmp744
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	210
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	20786
	.ascii	 "atomic_add_8_nv"
	.byte	0
	.ascii	 "atomic_add_8_nv"
	.byte	0
	.byte	1
	.byte	223
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin72
	.quad	Lfunc_end72
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	223
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	223
	.long	40089
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp752
	.quad	Ltmp758
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	223
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	20695
	.quad	Ltmp752
	.quad	Ltmp753
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	223
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	223
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp752
	.quad	Ltmp753
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	223
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp755
	.quad	Ltmp756
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	223
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	223
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp755
	.quad	Ltmp756
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	223
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	21099
	.ascii	 "atomic_add_char_nv"
	.byte	0
	.ascii	 "atomic_add_char_nv"
	.byte	0
	.byte	1
	.byte	224
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin73
	.quad	Lfunc_end73
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	224
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	224
	.long	40074
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp764
	.quad	Ltmp770
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	224
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	21008
	.quad	Ltmp764
	.quad	Ltmp765
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	224
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	224
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp764
	.quad	Ltmp765
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	224
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp767
	.quad	Ltmp768
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	224
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	224
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp767
	.quad	Ltmp768
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	224
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	21408
	.ascii	 "atomic_add_16_nv"
	.byte	0
	.ascii	 "atomic_add_16_nv"
	.byte	0
	.byte	1
	.byte	225
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin74
	.quad	Lfunc_end74
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	225
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	225
	.long	40116
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp776
	.quad	Ltmp782
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	225
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	21317
	.quad	Ltmp776
	.quad	Ltmp777
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	225
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	225
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp776
	.quad	Ltmp777
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	225
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp779
	.quad	Ltmp780
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	225
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	225
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp779
	.quad	Ltmp780
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	225
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	21723
	.ascii	 "atomic_add_short_nv"
	.byte	0
	.ascii	 "atomic_add_short_nv"
	.byte	0
	.byte	1
	.byte	226
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin75
	.quad	Lfunc_end75
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	226
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	226
	.long	40103
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp788
	.quad	Ltmp794
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	226
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	21632
	.quad	Ltmp788
	.quad	Ltmp789
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	226
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	226
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp788
	.quad	Ltmp789
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	226
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp791
	.quad	Ltmp792
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	226
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	226
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp791
	.quad	Ltmp792
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	226
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	22032
	.ascii	 "atomic_add_32_nv"
	.byte	0
	.ascii	 "atomic_add_32_nv"
	.byte	0
	.byte	1
	.byte	227
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin76
	.quad	Lfunc_end76
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	227
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	227
	.long	40131
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp800
	.quad	Ltmp806
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	227
	.long	16529
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	21941
	.quad	Ltmp800
	.quad	Ltmp801
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	227
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	227
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp800
	.quad	Ltmp801
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	227
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp803
	.quad	Ltmp804
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	227
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	227
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp803
	.quad	Ltmp804
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	227
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	22343
	.ascii	 "atomic_add_int_nv"
	.byte	0
	.ascii	 "atomic_add_int_nv"
	.byte	0
	.byte	1
	.byte	228
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin77
	.quad	Lfunc_end77
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	228
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	228
	.long	37828
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp812
	.quad	Ltmp818
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	228
	.long	16839
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	22252
	.quad	Ltmp812
	.quad	Ltmp813
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	228
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	228
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp812
	.quad	Ltmp813
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	228
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp815
	.quad	Ltmp816
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	228
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	228
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp815
	.quad	Ltmp816
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	228
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	22658
	.ascii	 "atomic_add_long_nv"
	.byte	0
	.ascii	 "atomic_add_long_nv"
	.byte	0
	.byte	1
	.byte	229
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin78
	.quad	Lfunc_end78
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	229
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	229
	.long	39777
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp824
	.quad	Ltmp830
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	229
	.long	17151
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	22566
	.quad	Ltmp824
	.quad	Ltmp825
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	229
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	229
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp824
	.quad	Ltmp825
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	229
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp827
	.quad	Ltmp828
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	229
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	229
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp827
	.quad	Ltmp828
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	229
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	22969
	.ascii	 "atomic_add_64_nv"
	.byte	0
	.ascii	 "atomic_add_64_nv"
	.byte	0
	.byte	1
	.byte	230
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin79
	.quad	Lfunc_end79
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	230
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	230
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp836
	.quad	Ltmp842
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	230
	.long	17493
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	22877
	.quad	Ltmp836
	.quad	Ltmp837
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	230
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	230
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp836
	.quad	Ltmp837
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	230
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp839
	.quad	Ltmp840
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	230
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	230
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp839
	.quad	Ltmp840
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	230
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	12
	.byte	8
	.byte	1
	.byte	0
	.byte	10
	.long	23287
	.ascii	 "atomic_add_ptr_nv"
	.byte	0
	.ascii	 "atomic_add_ptr_nv"
	.byte	0
	.byte	1
	.byte	233
	.byte	1
	.long	22969
	.byte	1
	.quad	Lfunc_begin80
	.quad	Lfunc_end80
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	232
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	232
	.long	40146
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp847
	.quad	Ltmp855
	.byte	6
	.ascii	 "ptr"
	.byte	0
	.byte	1
	.byte	234
	.long	22969
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	23195
	.quad	Ltmp847
	.quad	Ltmp849
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	236
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	236
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp848
	.quad	Ltmp849
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	236
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp851
	.quad	Ltmp853
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	238
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	238
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp852
	.quad	Ltmp853
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	238
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	23594
	.ascii	 "atomic_sub_8_nv"
	.byte	0
	.ascii	 "atomic_sub_8_nv"
	.byte	0
	.byte	1
	.byte	254
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin81
	.quad	Lfunc_end81
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	254
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	254
	.long	40089
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp861
	.quad	Ltmp867
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	254
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	23503
	.quad	Ltmp861
	.quad	Ltmp862
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	254
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	254
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp861
	.quad	Ltmp862
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	254
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp864
	.quad	Ltmp865
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	254
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	254
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp864
	.quad	Ltmp865
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	254
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	10
	.long	23907
	.ascii	 "atomic_sub_char_nv"
	.byte	0
	.ascii	 "atomic_sub_char_nv"
	.byte	0
	.byte	1
	.byte	255
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin82
	.quad	Lfunc_end82
	.byte	1
	.byte	86
	.byte	3
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	255
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	3
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	255
	.long	40074
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp873
	.quad	Ltmp879
	.byte	6
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	255
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	23816
	.quad	Ltmp873
	.quad	Ltmp874
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	255
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	255
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp873
	.quad	Ltmp874
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	255
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp876
	.quad	Ltmp877
	.byte	6
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	255
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	6
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	255
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp876
	.quad	Ltmp877
	.byte	6
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	255
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	24226
	.ascii	 "atomic_sub_16_nv"
	.byte	0
	.ascii	 "atomic_sub_16_nv"
	.byte	0
	.byte	1
	.short	256
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin83
	.quad	Lfunc_end83
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	256
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	256
	.long	40116
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp885
	.quad	Ltmp891
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	256
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	24132
	.quad	Ltmp885
	.quad	Ltmp886
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	256
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	256
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp885
	.quad	Ltmp886
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	256
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp888
	.quad	Ltmp889
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	256
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	256
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp888
	.quad	Ltmp889
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	256
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	24551
	.ascii	 "atomic_sub_short_nv"
	.byte	0
	.ascii	 "atomic_sub_short_nv"
	.byte	0
	.byte	1
	.short	257
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin84
	.quad	Lfunc_end84
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	257
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	257
	.long	40103
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp897
	.quad	Ltmp903
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	257
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	24457
	.quad	Ltmp897
	.quad	Ltmp898
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	257
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	257
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp897
	.quad	Ltmp898
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	257
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp900
	.quad	Ltmp901
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	257
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	257
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp900
	.quad	Ltmp901
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	257
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	24870
	.ascii	 "atomic_sub_32_nv"
	.byte	0
	.ascii	 "atomic_sub_32_nv"
	.byte	0
	.byte	1
	.short	258
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin85
	.quad	Lfunc_end85
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	258
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	258
	.long	40131
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp909
	.quad	Ltmp915
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	258
	.long	16529
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	24776
	.quad	Ltmp909
	.quad	Ltmp910
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	258
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	258
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp909
	.quad	Ltmp910
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	258
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp912
	.quad	Ltmp913
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	258
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	258
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp912
	.quad	Ltmp913
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	258
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	25191
	.ascii	 "atomic_sub_int_nv"
	.byte	0
	.ascii	 "atomic_sub_int_nv"
	.byte	0
	.byte	1
	.short	259
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin86
	.quad	Lfunc_end86
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	259
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	259
	.long	37828
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp921
	.quad	Ltmp927
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	259
	.long	16839
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	25097
	.quad	Ltmp921
	.quad	Ltmp922
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	259
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	259
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp921
	.quad	Ltmp922
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	259
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp924
	.quad	Ltmp925
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	259
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	259
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp924
	.quad	Ltmp925
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	259
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	25516
	.ascii	 "atomic_sub_long_nv"
	.byte	0
	.ascii	 "atomic_sub_long_nv"
	.byte	0
	.byte	1
	.short	260
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin87
	.quad	Lfunc_end87
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	260
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	260
	.long	39777
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp933
	.quad	Ltmp939
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	260
	.long	17151
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	25421
	.quad	Ltmp933
	.quad	Ltmp934
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	260
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	260
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp933
	.quad	Ltmp934
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	260
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp936
	.quad	Ltmp937
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	260
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	260
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp936
	.quad	Ltmp937
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	260
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	25837
	.ascii	 "atomic_sub_64_nv"
	.byte	0
	.ascii	 "atomic_sub_64_nv"
	.byte	0
	.byte	1
	.short	261
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin88
	.quad	Lfunc_end88
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	261
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	261
	.long	39971
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp945
	.quad	Ltmp951
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	261
	.long	17493
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	25742
	.quad	Ltmp945
	.quad	Ltmp946
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	261
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	261
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp945
	.quad	Ltmp946
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	261
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp948
	.quad	Ltmp949
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	261
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	261
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp948
	.quad	Ltmp949
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	261
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	26161
	.ascii	 "atomic_sub_ptr_nv"
	.byte	0
	.ascii	 "atomic_sub_ptr_nv"
	.byte	0
	.byte	1
	.short	264
	.byte	1
	.long	22969
	.byte	1
	.quad	Lfunc_begin89
	.quad	Lfunc_end89
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	263
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	263
	.long	40146
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp956
	.quad	Ltmp964
	.byte	15
	.ascii	 "ptr"
	.byte	0
	.byte	1
	.short	265
	.long	22969
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	26066
	.quad	Ltmp956
	.quad	Ltmp958
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	267
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	267
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp957
	.quad	Ltmp958
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	267
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp960
	.quad	Ltmp962
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	269
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	269
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp961
	.quad	Ltmp962
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	269
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	26484
	.ascii	 "atomic_or_long_nv"
	.byte	0
	.ascii	 "atomic_or_long_nv"
	.byte	0
	.byte	1
	.short	285
	.byte	1
	.long	14904
	.byte	1
	.quad	Lfunc_begin90
	.quad	Lfunc_end90
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	285
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	285
	.long	14904
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp970
	.quad	Ltmp976
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	285
	.long	14904
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	26389
	.quad	Ltmp970
	.quad	Ltmp971
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	285
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	285
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp970
	.quad	Ltmp971
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	285
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp973
	.quad	Ltmp974
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	285
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	285
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp973
	.quad	Ltmp974
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	285
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	26799
	.ascii	 "atomic_or_8_nv"
	.byte	0
	.ascii	 "atomic_or_8_nv"
	.byte	0
	.byte	1
	.short	286
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin91
	.quad	Lfunc_end91
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	286
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	286
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp982
	.quad	Ltmp988
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	286
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	26705
	.quad	Ltmp982
	.quad	Ltmp983
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	286
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	286
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp982
	.quad	Ltmp983
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	286
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp985
	.quad	Ltmp986
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	286
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	286
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp985
	.quad	Ltmp986
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	286
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	27122
	.ascii	 "atomic_or_uchar_nv"
	.byte	0
	.ascii	 "atomic_or_uchar_nv"
	.byte	0
	.byte	1
	.short	287
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin92
	.quad	Lfunc_end92
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	287
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	287
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp994
	.quad	Ltmp1000
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	287
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	27028
	.quad	Ltmp994
	.quad	Ltmp995
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	287
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	287
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp994
	.quad	Ltmp995
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	287
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp997
	.quad	Ltmp998
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	287
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	287
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp997
	.quad	Ltmp998
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	287
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	27439
	.ascii	 "atomic_or_16_nv"
	.byte	0
	.ascii	 "atomic_or_16_nv"
	.byte	0
	.byte	1
	.short	288
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin93
	.quad	Lfunc_end93
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	288
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	288
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1006
	.quad	Ltmp1012
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	288
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	27345
	.quad	Ltmp1006
	.quad	Ltmp1007
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	288
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	288
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1006
	.quad	Ltmp1007
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	288
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1009
	.quad	Ltmp1010
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	288
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	288
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1009
	.quad	Ltmp1010
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	288
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	27764
	.ascii	 "atomic_or_ushort_nv"
	.byte	0
	.ascii	 "atomic_or_ushort_nv"
	.byte	0
	.byte	1
	.short	289
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin94
	.quad	Lfunc_end94
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	289
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	289
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1018
	.quad	Ltmp1024
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	289
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	27670
	.quad	Ltmp1018
	.quad	Ltmp1019
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	289
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	289
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1018
	.quad	Ltmp1019
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	289
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1021
	.quad	Ltmp1022
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	289
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	289
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1021
	.quad	Ltmp1022
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	289
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	28081
	.ascii	 "atomic_or_32_nv"
	.byte	0
	.ascii	 "atomic_or_32_nv"
	.byte	0
	.byte	1
	.short	290
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin95
	.quad	Lfunc_end95
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	290
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	290
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1030
	.quad	Ltmp1036
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	290
	.long	16529
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	27987
	.quad	Ltmp1030
	.quad	Ltmp1031
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	290
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	290
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1030
	.quad	Ltmp1031
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	290
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1033
	.quad	Ltmp1034
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	290
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	290
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1033
	.quad	Ltmp1034
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	290
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	28402
	.ascii	 "atomic_or_uint_nv"
	.byte	0
	.ascii	 "atomic_or_uint_nv"
	.byte	0
	.byte	1
	.short	291
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin96
	.quad	Lfunc_end96
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	291
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	291
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1042
	.quad	Ltmp1048
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	291
	.long	16839
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	28308
	.quad	Ltmp1042
	.quad	Ltmp1043
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	291
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	291
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1042
	.quad	Ltmp1043
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	291
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1045
	.quad	Ltmp1046
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	291
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	291
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1045
	.quad	Ltmp1046
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	291
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	28727
	.ascii	 "atomic_or_ulong_nv"
	.byte	0
	.ascii	 "atomic_or_ulong_nv"
	.byte	0
	.byte	1
	.short	292
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin97
	.quad	Lfunc_end97
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	292
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	292
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1054
	.quad	Ltmp1060
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	292
	.long	17151
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	28632
	.quad	Ltmp1054
	.quad	Ltmp1055
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	292
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	292
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1054
	.quad	Ltmp1055
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	292
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1057
	.quad	Ltmp1058
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	292
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	292
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1057
	.quad	Ltmp1058
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	292
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	29046
	.ascii	 "atomic_or_64_nv"
	.byte	0
	.ascii	 "atomic_or_64_nv"
	.byte	0
	.byte	1
	.short	293
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin98
	.quad	Lfunc_end98
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	293
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	293
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1066
	.quad	Ltmp1072
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	293
	.long	17493
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	28951
	.quad	Ltmp1066
	.quad	Ltmp1067
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	293
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	293
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1066
	.quad	Ltmp1067
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	293
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1069
	.quad	Ltmp1070
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	293
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	293
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1069
	.quad	Ltmp1070
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	293
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	29371
	.ascii	 "atomic_and_long_nv"
	.byte	0
	.ascii	 "atomic_and_long_nv"
	.byte	0
	.byte	1
	.short	306
	.byte	1
	.long	14904
	.byte	1
	.quad	Lfunc_begin99
	.quad	Lfunc_end99
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	306
	.long	39946
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	306
	.long	14904
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1078
	.quad	Ltmp1084
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	306
	.long	14904
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	29276
	.quad	Ltmp1078
	.quad	Ltmp1079
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	306
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	306
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1078
	.quad	Ltmp1079
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	306
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1081
	.quad	Ltmp1082
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	306
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	306
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1081
	.quad	Ltmp1082
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	306
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	29688
	.ascii	 "atomic_and_8_nv"
	.byte	0
	.ascii	 "atomic_and_8_nv"
	.byte	0
	.byte	1
	.short	307
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin100
	.quad	Lfunc_end100
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	307
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	307
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp1090
	.quad	Ltmp1096
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	307
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	29594
	.quad	Ltmp1090
	.quad	Ltmp1091
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	307
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	307
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1090
	.quad	Ltmp1091
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	307
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1093
	.quad	Ltmp1094
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	307
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	307
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1093
	.quad	Ltmp1094
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	307
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	30013
	.ascii	 "atomic_and_uchar_nv"
	.byte	0
	.ascii	 "atomic_and_uchar_nv"
	.byte	0
	.byte	1
	.short	308
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin101
	.quad	Lfunc_end101
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	308
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	308
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp1102
	.quad	Ltmp1108
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	308
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	29919
	.quad	Ltmp1102
	.quad	Ltmp1103
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	308
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	308
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1102
	.quad	Ltmp1103
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	308
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1105
	.quad	Ltmp1106
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	308
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	308
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1105
	.quad	Ltmp1106
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	308
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	30332
	.ascii	 "atomic_and_16_nv"
	.byte	0
	.ascii	 "atomic_and_16_nv"
	.byte	0
	.byte	1
	.short	309
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin102
	.quad	Lfunc_end102
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	309
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	309
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1114
	.quad	Ltmp1120
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	309
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	30238
	.quad	Ltmp1114
	.quad	Ltmp1115
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	309
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	309
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1114
	.quad	Ltmp1115
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	309
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1117
	.quad	Ltmp1118
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	309
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	309
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1117
	.quad	Ltmp1118
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	309
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	30659
	.ascii	 "atomic_and_ushort_nv"
	.byte	0
	.ascii	 "atomic_and_ushort_nv"
	.byte	0
	.byte	1
	.short	310
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin103
	.quad	Lfunc_end103
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	310
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	310
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1126
	.quad	Ltmp1132
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	310
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	30565
	.quad	Ltmp1126
	.quad	Ltmp1127
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	310
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	310
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1126
	.quad	Ltmp1127
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	310
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1129
	.quad	Ltmp1130
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	310
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	310
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1129
	.quad	Ltmp1130
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	310
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	30978
	.ascii	 "atomic_and_32_nv"
	.byte	0
	.ascii	 "atomic_and_32_nv"
	.byte	0
	.byte	1
	.short	311
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin104
	.quad	Lfunc_end104
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	311
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	311
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1138
	.quad	Ltmp1144
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	311
	.long	16529
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	30884
	.quad	Ltmp1138
	.quad	Ltmp1139
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	311
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	311
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1138
	.quad	Ltmp1139
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	311
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1141
	.quad	Ltmp1142
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	311
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	311
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1141
	.quad	Ltmp1142
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	311
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	31301
	.ascii	 "atomic_and_uint_nv"
	.byte	0
	.ascii	 "atomic_and_uint_nv"
	.byte	0
	.byte	1
	.short	312
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin105
	.quad	Lfunc_end105
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	312
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	312
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1150
	.quad	Ltmp1156
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	312
	.long	16839
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	31207
	.quad	Ltmp1150
	.quad	Ltmp1151
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	312
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	312
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1150
	.quad	Ltmp1151
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	312
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1153
	.quad	Ltmp1154
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	312
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	312
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1153
	.quad	Ltmp1154
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	312
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	31628
	.ascii	 "atomic_and_ulong_nv"
	.byte	0
	.ascii	 "atomic_and_ulong_nv"
	.byte	0
	.byte	1
	.short	313
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin106
	.quad	Lfunc_end106
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	313
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	313
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1162
	.quad	Ltmp1168
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	313
	.long	17151
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	31533
	.quad	Ltmp1162
	.quad	Ltmp1163
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	313
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	313
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1162
	.quad	Ltmp1163
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	313
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1165
	.quad	Ltmp1166
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	313
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	313
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1165
	.quad	Ltmp1166
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	313
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	31949
	.ascii	 "atomic_and_64_nv"
	.byte	0
	.ascii	 "atomic_and_64_nv"
	.byte	0
	.byte	1
	.short	314
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin107
	.quad	Lfunc_end107
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	314
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	314
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1174
	.quad	Ltmp1180
	.byte	15
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	314
	.long	17493
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	31854
	.quad	Ltmp1174
	.quad	Ltmp1175
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	314
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	314
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1174
	.quad	Ltmp1175
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	314
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1177
	.quad	Ltmp1178
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	314
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	314
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1177
	.quad	Ltmp1178
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	314
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	32277
	.ascii	 "atomic_cas_8"
	.byte	0
	.ascii	 "atomic_cas_8"
	.byte	0
	.byte	1
	.short	333
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin108
	.quad	Lfunc_end108
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	333
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	333
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	333
	.long	15241
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1186
	.quad	Ltmp1193
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	333
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	32183
	.quad	Ltmp1186
	.quad	Ltmp1187
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	333
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	333
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1186
	.quad	Ltmp1187
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	333
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1189
	.quad	Ltmp1191
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	333
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	333
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1190
	.quad	Ltmp1191
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	333
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	32613
	.ascii	 "atomic_cas_uchar"
	.byte	0
	.ascii	 "atomic_cas_uchar"
	.byte	0
	.byte	1
	.short	334
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin109
	.quad	Lfunc_end109
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	334
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	334
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	334
	.long	15548
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1199
	.quad	Ltmp1206
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	334
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	32519
	.quad	Ltmp1199
	.quad	Ltmp1200
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	334
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	334
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1199
	.quad	Ltmp1200
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	334
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1202
	.quad	Ltmp1204
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	334
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	334
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1203
	.quad	Ltmp1204
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	334
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	32943
	.ascii	 "atomic_cas_16"
	.byte	0
	.ascii	 "atomic_cas_16"
	.byte	0
	.byte	1
	.short	335
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin110
	.quad	Lfunc_end110
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	335
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	335
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	335
	.long	15885
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1212
	.quad	Ltmp1219
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	335
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	32849
	.quad	Ltmp1212
	.quad	Ltmp1213
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	335
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	335
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1212
	.quad	Ltmp1213
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	335
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1215
	.quad	Ltmp1217
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	335
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	335
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1216
	.quad	Ltmp1217
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	335
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	33281
	.ascii	 "atomic_cas_ushort"
	.byte	0
	.ascii	 "atomic_cas_ushort"
	.byte	0
	.byte	1
	.short	336
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin111
	.quad	Lfunc_end111
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	336
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	336
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	336
	.long	16195
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1225
	.quad	Ltmp1232
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	336
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	33187
	.quad	Ltmp1225
	.quad	Ltmp1226
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	336
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	336
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1225
	.quad	Ltmp1226
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	336
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1228
	.quad	Ltmp1230
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	336
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	336
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1229
	.quad	Ltmp1230
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	336
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	33612
	.ascii	 "atomic_cas_32"
	.byte	0
	.ascii	 "atomic_cas_32"
	.byte	0
	.byte	1
	.short	337
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin112
	.quad	Lfunc_end112
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	337
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	337
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	337
	.long	16529
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1238
	.quad	Ltmp1245
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	337
	.long	16529
	.byte	2
	.byte	145
	.byte	92
	.byte	5
	.long	33517
	.quad	Ltmp1238
	.quad	Ltmp1239
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	337
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	337
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp1238
	.quad	Ltmp1239
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	337
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1241
	.quad	Ltmp1243
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	337
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	337
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp1242
	.quad	Ltmp1243
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	337
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	33947
	.ascii	 "atomic_cas_uint"
	.byte	0
	.ascii	 "atomic_cas_uint"
	.byte	0
	.byte	1
	.short	338
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin113
	.quad	Lfunc_end113
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	338
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	338
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	338
	.long	16839
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1251
	.quad	Ltmp1258
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	338
	.long	16839
	.byte	2
	.byte	145
	.byte	92
	.byte	5
	.long	33852
	.quad	Ltmp1251
	.quad	Ltmp1252
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	338
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	338
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp1251
	.quad	Ltmp1252
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	338
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1254
	.quad	Ltmp1256
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	338
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	338
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp1255
	.quad	Ltmp1256
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	338
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	34286
	.ascii	 "atomic_cas_ulong"
	.byte	0
	.ascii	 "atomic_cas_ulong"
	.byte	0
	.byte	1
	.short	339
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin114
	.quad	Lfunc_end114
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	339
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	339
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	339
	.long	17151
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp1264
	.quad	Ltmp1271
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	339
	.long	17151
	.byte	2
	.byte	145
	.byte	72
	.byte	5
	.long	34191
	.quad	Ltmp1264
	.quad	Ltmp1265
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	339
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	339
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1264
	.quad	Ltmp1265
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	339
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1267
	.quad	Ltmp1269
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	339
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	339
	.long	39971
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	4
	.quad	Ltmp1268
	.quad	Ltmp1269
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	339
	.long	39986
	.byte	3
	.byte	145
	.byte	152
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	34619
	.ascii	 "atomic_cas_64"
	.byte	0
	.ascii	 "atomic_cas_64"
	.byte	0
	.byte	1
	.short	340
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin115
	.quad	Lfunc_end115
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	340
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	340
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	340
	.long	17493
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp1277
	.quad	Ltmp1284
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	340
	.long	17493
	.byte	2
	.byte	145
	.byte	72
	.byte	5
	.long	34524
	.quad	Ltmp1277
	.quad	Ltmp1278
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	340
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	340
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1277
	.quad	Ltmp1278
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	340
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1280
	.quad	Ltmp1282
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	340
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	340
	.long	39971
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	4
	.quad	Ltmp1281
	.quad	Ltmp1282
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	340
	.long	39986
	.byte	3
	.byte	145
	.byte	152
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	34954
	.ascii	 "atomic_cas_ptr"
	.byte	0
	.ascii	 "atomic_cas_ptr"
	.byte	0
	.byte	1
	.short	343
	.byte	1
	.long	22969
	.byte	1
	.quad	Lfunc_begin116
	.quad	Lfunc_end116
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	342
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	342
	.long	22969
	.byte	2
	.byte	145
	.byte	104
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	342
	.long	22969
	.byte	2
	.byte	145
	.byte	96
	.byte	4
	.quad	Ltmp1289
	.quad	Ltmp1299
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	344
	.long	22969
	.byte	2
	.byte	145
	.byte	72
	.byte	5
	.long	34859
	.quad	Ltmp1289
	.quad	Ltmp1291
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	346
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	346
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1290
	.quad	Ltmp1291
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	346
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1295
	.quad	Ltmp1297
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	350
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	350
	.long	39971
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	4
	.quad	Ltmp1296
	.quad	Ltmp1297
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	350
	.long	39986
	.byte	3
	.byte	145
	.byte	152
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	35268
	.ascii	 "atomic_swap_8"
	.byte	0
	.ascii	 "atomic_swap_8"
	.byte	0
	.byte	1
	.short	371
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin117
	.quad	Lfunc_end117
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	371
	.long	40010
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	371
	.long	15241
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp1305
	.quad	Ltmp1311
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	371
	.long	15241
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	35174
	.quad	Ltmp1305
	.quad	Ltmp1306
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	371
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	371
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1305
	.quad	Ltmp1306
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	371
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1308
	.quad	Ltmp1309
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	371
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	371
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1308
	.quad	Ltmp1309
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	371
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	35590
	.ascii	 "atomic_swap_uchar"
	.byte	0
	.ascii	 "atomic_swap_uchar"
	.byte	0
	.byte	1
	.short	372
	.byte	1
	.long	15548
	.byte	1
	.quad	Lfunc_begin118
	.quad	Lfunc_end118
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	372
	.long	40018
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	372
	.long	15548
	.byte	2
	.byte	145
	.byte	111
	.byte	4
	.quad	Ltmp1317
	.quad	Ltmp1323
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	372
	.long	15548
	.byte	2
	.byte	145
	.byte	99
	.byte	5
	.long	35496
	.quad	Ltmp1317
	.quad	Ltmp1318
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	372
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	372
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1317
	.quad	Ltmp1318
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	372
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1320
	.quad	Ltmp1321
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	372
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	372
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1320
	.quad	Ltmp1321
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	372
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	35906
	.ascii	 "atomic_swap_16"
	.byte	0
	.ascii	 "atomic_swap_16"
	.byte	0
	.byte	1
	.short	373
	.byte	1
	.long	15885
	.byte	1
	.quad	Lfunc_begin119
	.quad	Lfunc_end119
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	373
	.long	40026
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	373
	.long	15885
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1329
	.quad	Ltmp1335
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	373
	.long	15885
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	35812
	.quad	Ltmp1329
	.quad	Ltmp1330
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	373
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	373
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1329
	.quad	Ltmp1330
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	373
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1332
	.quad	Ltmp1333
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	373
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	373
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1332
	.quad	Ltmp1333
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	373
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	36230
	.ascii	 "atomic_swap_ushort"
	.byte	0
	.ascii	 "atomic_swap_ushort"
	.byte	0
	.byte	1
	.short	374
	.byte	1
	.long	16195
	.byte	1
	.quad	Lfunc_begin120
	.quad	Lfunc_end120
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	374
	.long	40034
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	374
	.long	16195
	.byte	2
	.byte	145
	.byte	110
	.byte	4
	.quad	Ltmp1341
	.quad	Ltmp1347
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	374
	.long	16195
	.byte	2
	.byte	145
	.byte	98
	.byte	5
	.long	36136
	.quad	Ltmp1341
	.quad	Ltmp1342
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	374
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	374
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1341
	.quad	Ltmp1342
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	374
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1344
	.quad	Ltmp1345
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	374
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	374
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1344
	.quad	Ltmp1345
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	374
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	36546
	.ascii	 "atomic_swap_32"
	.byte	0
	.ascii	 "atomic_swap_32"
	.byte	0
	.byte	1
	.short	375
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin121
	.quad	Lfunc_end121
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	375
	.long	40042
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	375
	.long	16529
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1353
	.quad	Ltmp1359
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	375
	.long	16529
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	36452
	.quad	Ltmp1353
	.quad	Ltmp1354
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	375
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	375
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1353
	.quad	Ltmp1354
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	375
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1356
	.quad	Ltmp1357
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	375
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	375
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1356
	.quad	Ltmp1357
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	375
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	36866
	.ascii	 "atomic_swap_uint"
	.byte	0
	.ascii	 "atomic_swap_uint"
	.byte	0
	.byte	1
	.short	376
	.byte	1
	.long	16839
	.byte	1
	.quad	Lfunc_begin122
	.quad	Lfunc_end122
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	376
	.long	40050
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	376
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1365
	.quad	Ltmp1371
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	376
	.long	16839
	.byte	2
	.byte	145
	.byte	96
	.byte	5
	.long	36772
	.quad	Ltmp1365
	.quad	Ltmp1366
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	376
	.long	39971
	.byte	2
	.byte	145
	.byte	88
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	376
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	4
	.quad	Ltmp1365
	.quad	Ltmp1366
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	376
	.long	39986
	.byte	2
	.byte	145
	.byte	72
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1368
	.quad	Ltmp1369
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	376
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	376
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	4
	.quad	Ltmp1368
	.quad	Ltmp1369
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	376
	.long	39986
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	37190
	.ascii	 "atomic_swap_ulong"
	.byte	0
	.ascii	 "atomic_swap_ulong"
	.byte	0
	.byte	1
	.short	377
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin123
	.quad	Lfunc_end123
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	377
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	377
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1377
	.quad	Ltmp1383
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	377
	.long	17151
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	37095
	.quad	Ltmp1377
	.quad	Ltmp1378
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	377
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	377
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1377
	.quad	Ltmp1378
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	377
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1380
	.quad	Ltmp1381
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	377
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	377
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1380
	.quad	Ltmp1381
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	377
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	37508
	.ascii	 "atomic_swap_64"
	.byte	0
	.ascii	 "atomic_swap_64"
	.byte	0
	.byte	1
	.short	378
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin124
	.quad	Lfunc_end124
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	378
	.long	40066
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	378
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1389
	.quad	Ltmp1395
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	378
	.long	17493
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	37413
	.quad	Ltmp1389
	.quad	Ltmp1390
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	378
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	378
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1389
	.quad	Ltmp1390
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	378
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1392
	.quad	Ltmp1393
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	378
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	378
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1392
	.quad	Ltmp1393
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	378
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	37828
	.ascii	 "atomic_swap_ptr"
	.byte	0
	.ascii	 "atomic_swap_ptr"
	.byte	0
	.byte	1
	.short	381
	.byte	1
	.long	22969
	.byte	1
	.quad	Lfunc_begin125
	.quad	Lfunc_end125
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	380
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	380
	.long	22969
	.byte	2
	.byte	145
	.byte	104
	.byte	4
	.quad	Ltmp1400
	.quad	Ltmp1409
	.byte	15
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	382
	.long	22969
	.byte	2
	.byte	145
	.byte	80
	.byte	5
	.long	37733
	.quad	Ltmp1400
	.quad	Ltmp1402
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	384
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	384
	.long	39971
	.byte	2
	.byte	145
	.byte	64
	.byte	4
	.quad	Ltmp1401
	.quad	Ltmp1402
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	384
	.long	39986
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1405
	.quad	Ltmp1407
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	387
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	387
	.long	39971
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	4
	.quad	Ltmp1406
	.quad	Ltmp1407
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	387
	.long	39986
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	9
	.byte	5
	.ascii	 "int"
	.byte	0
	.byte	4
	.byte	13
	.long	38262
	.ascii	 "atomic_set_long_excl"
	.byte	0
	.ascii	 "atomic_set_long_excl"
	.byte	0
	.byte	1
	.short	394
	.byte	1
	.long	37828
	.byte	1
	.quad	Lfunc_begin126
	.quad	Lfunc_end126
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	393
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "value"
	.byte	0
	.byte	1
	.short	393
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1414
	.quad	Ltmp1429
	.byte	15
	.ascii	 "bit"
	.byte	0
	.byte	1
	.short	395
	.long	17151
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	38070
	.quad	Ltmp1414
	.quad	Ltmp1416
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	397
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	397
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp1415
	.quad	Ltmp1416
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	397
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	5
	.long	38167
	.quad	Ltmp1419
	.quad	Ltmp1421
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	400
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	400
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp1420
	.quad	Ltmp1421
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	400
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1424
	.quad	Ltmp1426
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	404
	.long	39971
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	404
	.long	39971
	.byte	3
	.byte	145
	.byte	152
	.byte	127
	.byte	4
	.quad	Ltmp1425
	.quad	Ltmp1426
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	404
	.long	39986
	.byte	3
	.byte	145
	.byte	144
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.long	38693
	.ascii	 "atomic_clear_long_excl"
	.byte	0
	.ascii	 "atomic_clear_long_excl"
	.byte	0
	.byte	1
	.short	410
	.byte	1
	.long	37828
	.byte	1
	.quad	Lfunc_begin127
	.quad	Lfunc_end127
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	409
	.long	40058
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "value"
	.byte	0
	.byte	1
	.short	409
	.long	16839
	.byte	2
	.byte	145
	.byte	108
	.byte	4
	.quad	Ltmp1434
	.quad	Ltmp1449
	.byte	15
	.ascii	 "bit"
	.byte	0
	.byte	1
	.short	411
	.long	17151
	.byte	2
	.byte	145
	.byte	88
	.byte	5
	.long	38501
	.quad	Ltmp1434
	.quad	Ltmp1436
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	413
	.long	39971
	.byte	2
	.byte	145
	.byte	80
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	413
	.long	39971
	.byte	2
	.byte	145
	.byte	72
	.byte	4
	.quad	Ltmp1435
	.quad	Ltmp1436
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	413
	.long	39986
	.byte	2
	.byte	145
	.byte	64
	.byte	0
	.byte	0
	.byte	5
	.long	38598
	.quad	Ltmp1439
	.quad	Ltmp1441
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	416
	.long	39971
	.byte	3
	.byte	145
	.byte	184
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	416
	.long	39971
	.byte	3
	.byte	145
	.byte	176
	.byte	127
	.byte	4
	.quad	Ltmp1440
	.quad	Ltmp1441
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	416
	.long	39986
	.byte	3
	.byte	145
	.byte	168
	.byte	127
	.byte	0
	.byte	0
	.byte	4
	.quad	Ltmp1444
	.quad	Ltmp1446
	.byte	15
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	420
	.long	39971
	.byte	3
	.byte	145
	.byte	160
	.byte	127
	.byte	15
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	420
	.long	39971
	.byte	3
	.byte	145
	.byte	152
	.byte	127
	.byte	4
	.quad	Ltmp1445
	.quad	Ltmp1446
	.byte	15
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	420
	.long	39986
	.byte	3
	.byte	145
	.byte	144
	.byte	127
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	16
	.long	38765
	.ascii	 "membar_enter"
	.byte	0
	.ascii	 "membar_enter"
	.byte	0
	.byte	1
	.short	426
	.byte	1
	.byte	1
	.quad	Lfunc_begin128
	.quad	Lfunc_end128
	.byte	1
	.byte	86
	.byte	8
	.quad	Ltmp1453
	.quad	Ltmp1454
	.byte	0
	.byte	16
	.long	38835
	.ascii	 "membar_exit"
	.byte	0
	.ascii	 "membar_exit"
	.byte	0
	.byte	1
	.short	431
	.byte	1
	.byte	1
	.quad	Lfunc_begin129
	.quad	Lfunc_end129
	.byte	1
	.byte	86
	.byte	8
	.quad	Ltmp1458
	.quad	Ltmp1459
	.byte	0
	.byte	16
	.long	38913
	.ascii	 "membar_producer"
	.byte	0
	.ascii	 "membar_producer"
	.byte	0
	.byte	1
	.short	436
	.byte	1
	.byte	1
	.quad	Lfunc_begin130
	.quad	Lfunc_end130
	.byte	1
	.byte	86
	.byte	8
	.quad	Ltmp1463
	.quad	Ltmp1464
	.byte	0
	.byte	16
	.long	38991
	.ascii	 "membar_consumer"
	.byte	0
	.ascii	 "membar_consumer"
	.byte	0
	.byte	1
	.short	441
	.byte	1
	.byte	1
	.quad	Lfunc_begin131
	.quad	Lfunc_end131
	.byte	1
	.byte	86
	.byte	8
	.quad	Ltmp1468
	.quad	Ltmp1469
	.byte	0
	.byte	13
	.long	39101
	.ascii	 "cas8"
	.byte	0
	.ascii	 "cas8"
	.byte	0
	.byte	1
	.short	448
	.byte	1
	.long	15241
	.byte	1
	.quad	Lfunc_begin132
	.quad	Lfunc_end132
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	447
	.long	40010
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	447
	.long	15241
	.byte	2
	.byte	145
	.byte	119
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	447
	.long	15241
	.byte	2
	.byte	145
	.byte	118
	.byte	8
	.quad	Ltmp1474
	.quad	Ltmp1475
	.byte	0
	.byte	13
	.long	39213
	.ascii	 "cas32"
	.byte	0
	.ascii	 "cas32"
	.byte	0
	.byte	1
	.short	453
	.byte	1
	.long	16529
	.byte	1
	.quad	Lfunc_begin133
	.quad	Lfunc_end133
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	452
	.long	40042
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	452
	.long	16529
	.byte	2
	.byte	145
	.byte	116
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	452
	.long	16529
	.byte	2
	.byte	145
	.byte	112
	.byte	8
	.quad	Ltmp1480
	.quad	Ltmp1481
	.byte	0
	.byte	13
	.long	39325
	.ascii	 "cas64"
	.byte	0
	.ascii	 "cas64"
	.byte	0
	.byte	1
	.short	458
	.byte	1
	.long	17493
	.byte	1
	.quad	Lfunc_begin134
	.quad	Lfunc_end134
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	457
	.long	40066
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	457
	.long	17493
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	457
	.long	17493
	.byte	2
	.byte	145
	.byte	104
	.byte	8
	.quad	Ltmp1486
	.quad	Ltmp1487
	.byte	0
	.byte	13
	.long	39441
	.ascii	 "caslong"
	.byte	0
	.ascii	 "caslong"
	.byte	0
	.byte	1
	.short	463
	.byte	1
	.long	17151
	.byte	1
	.quad	Lfunc_begin135
	.quad	Lfunc_end135
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	462
	.long	40058
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	462
	.long	17151
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	462
	.long	17151
	.byte	2
	.byte	145
	.byte	104
	.byte	8
	.quad	Ltmp1492
	.quad	Ltmp1493
	.byte	0
	.byte	13
	.long	39555
	.ascii	 "casptr"
	.byte	0
	.ascii	 "casptr"
	.byte	0
	.byte	1
	.short	468
	.byte	1
	.long	22969
	.byte	1
	.quad	Lfunc_begin136
	.quad	Lfunc_end136
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	467
	.long	22969
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	467
	.long	22969
	.byte	2
	.byte	145
	.byte	112
	.byte	14
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	467
	.long	22969
	.byte	2
	.byte	145
	.byte	104
	.byte	8
	.quad	Ltmp1498
	.quad	Ltmp1499
	.byte	0
	.byte	16
	.long	39667
	.ascii	 "atomic_and_long"
	.byte	0
	.ascii	 "atomic_and_long"
	.byte	0
	.byte	1
	.short	473
	.byte	1
	.byte	1
	.quad	Lfunc_begin137
	.quad	Lfunc_end137
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	472
	.long	40058
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	472
	.long	17151
	.byte	2
	.byte	145
	.byte	112
	.byte	8
	.quad	Ltmp1504
	.quad	Ltmp1505
	.byte	0
	.byte	16
	.long	39777
	.ascii	 "atomic_or_long"
	.byte	0
	.ascii	 "atomic_or_long"
	.byte	0
	.byte	1
	.short	478
	.byte	1
	.byte	1
	.quad	Lfunc_begin138
	.quad	Lfunc_end138
	.byte	1
	.byte	86
	.byte	14
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	477
	.long	40058
	.byte	2
	.byte	145
	.byte	120
	.byte	14
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	477
	.long	17151
	.byte	2
	.byte	145
	.byte	112
	.byte	8
	.quad	Ltmp1510
	.quad	Ltmp1511
	.byte	0
	.byte	9
	.byte	5
	.ascii	 "long int"
	.byte	0
	.byte	8
	.byte	9
	.byte	6
	.ascii	 "char"
	.byte	0
	.byte	1
	.byte	17
	.byte	4
	.byte	5
	.byte	18
	.long	39816
	.long	39789
	.byte	19
	.long	39797
	.byte	55
	.byte	0
	.byte	20
	.long	39884
	.ascii	 "_opaque_pthread_mutex_t"
	.byte	0
	.byte	64
	.byte	1
	.byte	67
	.byte	21
	.ascii	 "__sig"
	.byte	0
	.long	39777
	.byte	1
	.byte	67
	.byte	2
	.byte	35
	.byte	0
	.byte	21
	.ascii	 "__opaque"
	.byte	0
	.long	39800
	.byte	1
	.byte	67
	.byte	2
	.byte	35
	.byte	8
	.byte	0
	.byte	22
	.long	39816
	.ascii	 "pthread_mutex_t"
	.byte	0
	.byte	1
	.short	315
	.byte	23
	.ascii	 "atomic_lock"
	.byte	0
	.long	39884
	.byte	1
	.byte	1
	.byte	37
	.byte	9
	.byte	3
	.quad	_atomic_lock
	.byte	24
	.long	14904
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	39938
	.byte	8
	.byte	1
	.byte	0
	.byte	9
	.byte	5
	.ascii	 "long long int"
	.byte	0
	.byte	8
	.byte	11
	.long	39954
	.ascii	 "int64_t"
	.byte	0
	.byte	1
	.byte	93
	.byte	25
	.long	39789
	.byte	8
	.byte	1
	.byte	0
	.byte	26
	.long	39789
	.byte	1
	.byte	1
	.byte	0
	.byte	25
	.long	39994
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	15241
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	15548
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	15885
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	16195
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	16529
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	16839
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	17151
	.byte	8
	.byte	1
	.byte	0
	.byte	25
	.long	17493
	.byte	8
	.byte	1
	.byte	0
	.byte	9
	.byte	6
	.ascii	 "signed char"
	.byte	0
	.byte	1
	.byte	11
	.long	40074
	.ascii	 "int8_t"
	.byte	0
	.byte	1
	.byte	78
	.byte	9
	.byte	5
	.ascii	 "short int"
	.byte	0
	.byte	2
	.byte	11
	.long	40103
	.ascii	 "int16_t"
	.byte	0
	.byte	1
	.byte	83
	.byte	11
	.long	37828
	.ascii	 "int32_t"
	.byte	0
	.byte	1
	.byte	88
	.byte	11
	.long	39777
	.ascii	 "ssize_t"
	.byte	0
	.byte	1
	.byte	235
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
Linfo_end1:
	.section	__DWARF,__debug_abbrev,regular,debug
Labbrev_begin:
	.byte	1
	.byte	17
	.byte	1
	.byte	37
	.byte	8
	.byte	19
	.byte	11
	.byte	3
	.byte	8
	.byte	82
	.byte	1
	.byte	16
	.byte	6
	.byte	27
	.byte	8
	.byte	0
	.byte	0
	.byte	2
	.byte	46
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	135
	.byte	64
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	39
	.byte	12
	.byte	63
	.byte	12
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	64
	.byte	10
	.byte	0
	.byte	0
	.byte	3
	.byte	5
	.byte	0
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	73
	.byte	19
	.byte	2
	.byte	10
	.byte	0
	.byte	0
	.byte	4
	.byte	11
	.byte	1
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	0
	.byte	0
	.byte	5
	.byte	11
	.byte	1
	.byte	1
	.byte	19
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	0
	.byte	0
	.byte	6
	.byte	52
	.byte	0
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	73
	.byte	19
	.byte	2
	.byte	10
	.byte	0
	.byte	0
	.byte	7
	.byte	46
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	39
	.byte	12
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	64
	.byte	10
	.byte	0
	.byte	0
	.byte	8
	.byte	11
	.byte	0
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	0
	.byte	0
	.byte	9
	.byte	36
	.byte	0
	.byte	62
	.byte	11
	.byte	3
	.byte	8
	.byte	11
	.byte	11
	.byte	0
	.byte	0
	.byte	10
	.byte	46
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	135
	.byte	64
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	39
	.byte	12
	.byte	73
	.byte	19
	.byte	63
	.byte	12
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	64
	.byte	10
	.byte	0
	.byte	0
	.byte	11
	.byte	22
	.byte	0
	.byte	73
	.byte	19
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	12
	.byte	15
	.byte	0
	.byte	11
	.byte	11
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	13
	.byte	46
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	135
	.byte	64
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	5
	.byte	39
	.byte	12
	.byte	73
	.byte	19
	.byte	63
	.byte	12
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	64
	.byte	10
	.byte	0
	.byte	0
	.byte	14
	.byte	5
	.byte	0
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	5
	.byte	73
	.byte	19
	.byte	2
	.byte	10
	.byte	0
	.byte	0
	.byte	15
	.byte	52
	.byte	0
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	5
	.byte	73
	.byte	19
	.byte	2
	.byte	10
	.byte	0
	.byte	0
	.byte	16
	.byte	46
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	135
	.byte	64
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	5
	.byte	39
	.byte	12
	.byte	63
	.byte	12
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	64
	.byte	10
	.byte	0
	.byte	0
	.byte	17
	.byte	36
	.byte	0
	.byte	11
	.byte	11
	.byte	62
	.byte	11
	.byte	0
	.byte	0
	.byte	18
	.byte	1
	.byte	1
	.byte	1
	.byte	19
	.byte	73
	.byte	19
	.byte	0
	.byte	0
	.byte	19
	.byte	33
	.byte	0
	.byte	73
	.byte	19
	.byte	47
	.byte	11
	.byte	0
	.byte	0
	.byte	20
	.byte	19
	.byte	1
	.byte	1
	.byte	19
	.byte	3
	.byte	8
	.byte	11
	.byte	11
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	21
	.byte	13
	.byte	0
	.byte	3
	.byte	8
	.byte	73
	.byte	19
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	56
	.byte	10
	.byte	0
	.byte	0
	.byte	22
	.byte	22
	.byte	0
	.byte	73
	.byte	19
	.byte	3
	.byte	8
	.byte	58
	.byte	11
	.byte	59
	.byte	5
	.byte	0
	.byte	0
	.byte	23
	.byte	52
	.byte	0
	.byte	3
	.byte	8
	.byte	73
	.byte	19
	.byte	63
	.byte	12
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	2
	.byte	10
	.byte	0
	.byte	0
	.byte	24
	.byte	53
	.byte	0
	.byte	73
	.byte	19
	.byte	11
	.byte	11
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	25
	.byte	15
	.byte	0
	.byte	73
	.byte	19
	.byte	11
	.byte	11
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	26
	.byte	38
	.byte	0
	.byte	73
	.byte	19
	.byte	11
	.byte	11
	.byte	58
	.byte	11
	.byte	59
	.byte	11
	.byte	0
	.byte	0
	.byte	0
Labbrev_end:
	.section	__DWARF,__debug_line,regular,debug
Lset1383 = Lline_end-Lline_begin
	.long	Lset1383
Lline_begin:
	.short	2
Lset1384 = Lline_prolog_end-Lline_prolog_begin
	.long	Lset1384
Lline_prolog_begin:
	.byte	1
	.byte	1
	.byte	246
	.byte	245
	.byte	10
	.byte	0
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	0
	.byte	0
	.byte	0
	.byte	1
	.asciz	 "/Users/will/repos/zfs/lib/libspl/asm-generic/"
	.asciz	 "/Users/will/repos/zfs/lib/libspl/asm-generic/../../../lib/libspl/include"
	.byte	0
	.asciz	 "atomic.c"
	.byte	1
	.byte	0
	.byte	0
	.asciz	 "assert.h"
	.byte	2
	.byte	0
	.byte	0
	.byte	0
Lline_prolog_end:
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp3
	.byte	70
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp4
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp5
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp7
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp8
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp13
	.byte	4
	.byte	2
	.byte	3
	.byte	115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp14
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp15
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp20
	.byte	4
	.byte	1
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp21
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp22
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp24
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp25
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp30
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp31
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp32
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp34
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp35
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp40
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp41
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp42
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp44
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp45
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp50
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp51
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp52
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp54
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp55
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp60
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp61
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp62
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp64
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp65
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp70
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp71
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp72
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp74
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp75
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp80
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp81
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp82
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp84
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp85
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp90
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp91
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp92
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp94
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp95
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp100
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp101
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp102
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp104
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp105
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp110
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp111
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp112
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp114
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp120
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp121
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp122
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp124
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp130
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp131
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp132
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp134
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp135
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp140
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp141
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp142
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp144
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp145
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp150
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp151
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp152
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp154
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp155
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp160
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp161
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp162
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp164
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp165
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp170
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp171
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp172
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp174
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp175
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp180
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp181
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp182
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp184
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp185
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp190
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp191
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp192
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp194
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp195
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp200
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp201
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp202
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp204
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp205
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp210
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp211
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp212
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp214
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp215
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp220
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp221
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp222
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp224
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp225
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp230
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp231
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp232
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp234
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp235
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp240
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp241
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp242
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp244
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp245
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp250
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp251
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp252
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp254
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp255
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp260
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp261
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp262
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp264
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp265
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp270
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp271
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp272
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp274
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp275
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp276
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp277
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp282
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp283
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp284
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp286
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp287
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp292
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp293
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp294
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp296
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp297
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp302
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp303
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp304
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp306
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp307
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp312
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp313
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp314
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp316
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp317
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp322
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp323
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp324
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp326
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp327
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp332
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp333
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp334
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp336
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp337
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp342
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp343
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp344
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp346
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp347
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp352
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp353
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp354
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp356
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp357
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp362
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp363
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp364
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp366
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp367
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp368
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp369
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp374
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp375
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp376
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp378
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp379
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp384
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp385
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp386
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp388
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp389
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp394
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp395
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp396
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp398
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp399
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp404
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp405
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp406
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp408
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp409
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp414
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp415
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp416
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp418
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp419
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp424
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp425
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp426
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp428
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp429
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp434
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp435
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp436
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp438
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp439
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp444
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp445
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp446
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp448
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp449
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp454
	.byte	31
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp455
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp456
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp458
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp459
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp464
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp465
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp466
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp468
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp469
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp474
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp475
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp476
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp478
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp479
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp484
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp485
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp486
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp488
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp489
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp494
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp495
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp496
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp498
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp499
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp504
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp505
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp506
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp508
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp509
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp514
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp515
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp516
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp518
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp519
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp524
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp525
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp526
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp528
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp529
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp534
	.byte	37
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp535
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp536
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp538
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp539
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp541
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp546
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp547
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp548
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp550
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp551
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp553
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp558
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp559
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp560
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp562
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp563
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp565
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp570
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp571
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp572
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp574
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp575
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp577
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp582
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp583
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp584
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp586
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp587
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp589
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp594
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp595
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp596
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp598
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp599
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp601
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp606
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp607
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp608
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp610
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp611
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp613
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp618
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp619
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp620
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp622
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp623
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp625
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp630
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp631
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp632
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp634
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp635
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp637
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp642
	.byte	33
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp643
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp644
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp646
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp647
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp649
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp654
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp655
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp656
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp658
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp659
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp661
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp666
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp667
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp668
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp670
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp671
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp673
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp678
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp679
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp680
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp682
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp683
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp685
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp690
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp691
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp692
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp694
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp695
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp697
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp702
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp703
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp704
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp706
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp707
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp709
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp714
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp715
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp716
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp718
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp719
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp721
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp726
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp727
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp728
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp730
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp731
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp733
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp738
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp739
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp740
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp742
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp743
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp745
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp750
	.byte	33
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp751
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp752
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp754
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp755
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp757
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp762
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp763
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp764
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp766
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp767
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp769
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp774
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp775
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp776
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp778
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp779
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp781
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp786
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp787
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp788
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp790
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp791
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp793
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp798
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp799
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp800
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp802
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp803
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp805
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp810
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp811
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp812
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp814
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp815
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp817
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp822
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp823
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp824
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp826
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp827
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp829
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp834
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp835
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp836
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp838
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp839
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp841
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp846
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp847
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp848
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp850
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp851
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp852
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp854
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp859
	.byte	34
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp860
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp861
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp863
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp864
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp866
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp871
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp872
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp873
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp875
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp876
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp878
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp883
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp884
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp885
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp887
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp888
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp890
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp895
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp896
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp897
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp899
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp900
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp902
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp907
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp908
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp909
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp911
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp912
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp914
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp919
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp920
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp921
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp923
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp924
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp926
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp931
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp932
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp933
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp935
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp936
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp938
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp943
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp944
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp945
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp947
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp948
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp950
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp955
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp956
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp957
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp959
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp960
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp961
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp963
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp968
	.byte	34
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp969
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp970
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp972
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp973
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp975
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp980
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp981
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp982
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp984
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp985
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp987
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp992
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp993
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp994
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp996
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp997
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp999
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1004
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1005
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1006
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1008
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1009
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1011
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1016
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1017
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1018
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1020
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1021
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1023
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1028
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1029
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1030
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1032
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1033
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1035
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1040
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1041
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1042
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1044
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1045
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1047
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1052
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1053
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1054
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1056
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1057
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1059
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1064
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1065
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1066
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1068
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1069
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1071
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1076
	.byte	33
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1077
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1078
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1080
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1081
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1083
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1088
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1089
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1090
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1092
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1093
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1095
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1100
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1101
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1102
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1104
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1105
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1107
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1112
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1113
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1114
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1116
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1119
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1124
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1126
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1128
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1129
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1131
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1136
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1137
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1138
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1140
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1141
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1143
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1148
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1149
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1150
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1152
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1153
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1155
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1160
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1161
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1162
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1164
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1165
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1167
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1172
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1173
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1174
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1176
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1177
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1179
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1184
	.byte	39
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1185
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1186
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1188
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1189
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1190
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1192
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1197
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1198
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1199
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1201
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1202
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1203
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1205
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1210
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1211
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1212
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1214
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1215
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1216
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1218
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1223
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1224
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1225
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1227
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1228
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1229
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1231
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1236
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1237
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1238
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1240
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1241
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1242
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1244
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1249
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1250
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1251
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1253
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1254
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1255
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1257
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1262
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1263
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1264
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1266
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1267
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1268
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1270
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1275
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1276
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1277
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1279
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1280
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1281
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1283
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1288
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1289
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1290
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1292
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1293
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1294
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1295
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1296
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1298
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1303
	.byte	39
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1304
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1305
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1307
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1308
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1310
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1315
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1316
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1317
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1319
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1320
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1322
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1327
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1328
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1329
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1331
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1332
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1334
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1339
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1340
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1341
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1343
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1344
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1346
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1351
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1352
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1353
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1355
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1356
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1358
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1363
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1364
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1365
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1367
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1368
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1370
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1375
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1376
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1377
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1379
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1380
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1382
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1387
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1388
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1389
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1391
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1392
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1394
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1399
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1400
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1401
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1403
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1404
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1405
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1406
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1408
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1413
	.byte	25
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1414
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1415
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1417
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1418
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1419
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1420
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1422
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1423
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1424
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1425
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1427
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1428
	.byte	15
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1433
	.byte	29
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1434
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1435
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1437
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1438
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1439
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1440
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1442
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1443
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1444
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1445
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1447
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1448
	.byte	15
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1452
	.byte	29
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1453
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1457
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1458
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1462
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1463
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1467
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1468
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1473
	.byte	25
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1474
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1479
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1480
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1485
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1486
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1491
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1492
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1497
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1498
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1503
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1504
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1509
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1510
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Lsection_end1
	.byte	0
	.byte	1
	.byte	1
Lline_end:
	.section	__DWARF,__debug_pubnames,regular,debug
Lset1385 = Lpubnames_end1-Lpubnames_begin1
	.long	Lset1385
Lpubnames_begin1:
	.short	2
Lset1386 = Linfo_begin1-Lsection_info
	.long	Lset1386
Lset1387 = Linfo_end1-Linfo_begin1
	.long	Lset1387
	.long	12030
	.asciz	 "atomic_or_ulong"
	.long	37835
	.asciz	 "atomic_set_long_excl"
	.long	39213
	.asciz	 "cas64"
	.long	12319
	.asciz	 "atomic_or_64"
	.long	12602
	.asciz	 "atomic_and_8"
	.long	34619
	.asciz	 "atomic_cas_ptr"
	.long	28727
	.asciz	 "atomic_or_64_nv"
	.long	29371
	.asciz	 "atomic_and_8_nv"
	.long	5726
	.asciz	 "atomic_add_16"
	.long	38835
	.asciz	 "membar_producer"
	.long	3522
	.asciz	 "atomic_dec_16"
	.long	19883
	.asciz	 "atomic_dec_ulong_nv"
	.long	18695
	.asciz	 "atomic_dec_16_nv"
	.long	33612
	.asciz	 "atomic_cas_uint"
	.long	34954
	.asciz	 "atomic_swap_8"
	.long	1890
	.asciz	 "atomic_inc_uint"
	.long	13176
	.asciz	 "atomic_and_16"
	.long	10029
	.asciz	 "atomic_sub_ptr"
	.long	34286
	.asciz	 "atomic_cas_64"
	.long	35590
	.asciz	 "atomic_swap_16"
	.long	11169
	.asciz	 "atomic_or_ushort"
	.long	416
	.asciz	 "__assert_c99"
	.long	143
	.asciz	 "atomic_inc_long"
	.long	28402
	.asciz	 "atomic_or_ulong_nv"
	.long	8307
	.asciz	 "atomic_sub_16"
	.long	37508
	.asciz	 "atomic_swap_ptr"
	.long	10597
	.asciz	 "atomic_or_uchar"
	.long	38991
	.asciz	 "cas8"
	.long	25516
	.asciz	 "atomic_sub_64_nv"
	.long	6874
	.asciz	 "atomic_add_long"
	.long	8592
	.asciz	 "atomic_sub_short"
	.long	30659
	.asciz	 "atomic_and_32_nv"
	.long	32943
	.asciz	 "atomic_cas_ushort"
	.long	25191
	.asciz	 "atomic_sub_long_nv"
	.long	5154
	.asciz	 "atomic_add_8"
	.long	7735
	.asciz	 "atomic_sub_8"
	.long	17166
	.asciz	 "atomic_inc_ulong_nv"
	.long	18103
	.asciz	 "atomic_dec_8_nv"
	.long	27439
	.asciz	 "atomic_or_ushort_nv"
	.long	27122
	.asciz	 "atomic_or_16_nv"
	.long	39325
	.asciz	 "caslong"
	.long	6302
	.asciz	 "atomic_add_32"
	.long	19585
	.asciz	 "atomic_dec_uint_nv"
	.long	3791
	.asciz	 "atomic_dec_ushort"
	.long	4068
	.asciz	 "atomic_dec_32"
	.long	6587
	.asciz	 "atomic_add_int"
	.long	13754
	.asciz	 "atomic_and_32"
	.long	24870
	.asciz	 "atomic_sub_int_nv"
	.long	31301
	.asciz	 "atomic_and_ulong_nv"
	.long	33947
	.asciz	 "atomic_cas_ulong"
	.long	17804
	.asciz	 "atomic_dec_long_nv"
	.long	36230
	.asciz	 "atomic_swap_32"
	.long	22973
	.asciz	 "atomic_add_ptr_nv"
	.long	2438
	.asciz	 "atomic_inc_64"
	.long	5437
	.asciz	 "atomic_add_char"
	.long	10886
	.asciz	 "atomic_or_16"
	.long	39908
	.asciz	 "atomic_lock"
	.long	8883
	.asciz	 "atomic_sub_32"
	.long	21723
	.asciz	 "atomic_add_32_nv"
	.long	23907
	.asciz	 "atomic_sub_16_nv"
	.long	15256
	.asciz	 "atomic_inc_8_nv"
	.long	14328
	.asciz	 "atomic_and_ulong"
	.long	22343
	.asciz	 "atomic_add_long_nv"
	.long	32613
	.asciz	 "atomic_cas_16"
	.long	31628
	.asciz	 "atomic_and_64_nv"
	.long	11743
	.asciz	 "atomic_or_uint"
	.long	16545
	.asciz	 "atomic_inc_32_nv"
	.long	18395
	.asciz	 "atomic_dec_uchar_nv"
	.long	20479
	.asciz	 "atomic_add_8_nv"
	.long	16211
	.asciz	 "atomic_inc_ushort_nv"
	.long	36866
	.asciz	 "atomic_swap_ulong"
	.long	38262
	.asciz	 "atomic_clear_long_excl"
	.long	32277
	.asciz	 "atomic_cas_uchar"
	.long	39667
	.asciz	 "atomic_or_long"
	.long	39441
	.asciz	 "casptr"
	.long	18989
	.asciz	 "atomic_dec_ushort_nv"
	.long	9168
	.asciz	 "atomic_sub_int"
	.long	19291
	.asciz	 "atomic_dec_32_nv"
	.long	26799
	.asciz	 "atomic_or_uchar_nv"
	.long	10316
	.asciz	 "atomic_or_8"
	.long	9455
	.asciz	 "atomic_sub_long"
	.long	39101
	.asciz	 "cas32"
	.long	11460
	.asciz	 "atomic_or_32"
	.long	12885
	.asciz	 "atomic_and_uchar"
	.long	23594
	.asciz	 "atomic_sub_char_nv"
	.long	35268
	.asciz	 "atomic_swap_uchar"
	.long	15563
	.asciz	 "atomic_inc_uchar_nv"
	.long	38765
	.asciz	 "membar_exit"
	.long	7163
	.asciz	 "atomic_add_64"
	.long	14039
	.asciz	 "atomic_and_uint"
	.long	4885
	.asciz	 "atomic_dec_64"
	.long	22032
	.asciz	 "atomic_add_int_nv"
	.long	6011
	.asciz	 "atomic_add_short"
	.long	30332
	.asciz	 "atomic_and_ushort_nv"
	.long	22658
	.asciz	 "atomic_add_64_nv"
	.long	14619
	.asciz	 "atomic_and_64"
	.long	16853
	.asciz	 "atomic_inc_uint_nv"
	.long	2163
	.asciz	 "atomic_inc_ulong"
	.long	30013
	.asciz	 "atomic_and_16_nv"
	.long	1075
	.asciz	 "atomic_inc_16"
	.long	33281
	.asciz	 "atomic_cas_32"
	.long	39555
	.asciz	 "atomic_and_long"
	.long	28081
	.asciz	 "atomic_or_uint_nv"
	.long	30978
	.asciz	 "atomic_and_uint_nv"
	.long	29046
	.asciz	 "atomic_and_long_nv"
	.long	17509
	.asciz	 "atomic_inc_64_nv"
	.long	8018
	.asciz	 "atomic_sub_char"
	.long	27764
	.asciz	 "atomic_or_32_nv"
	.long	29688
	.asciz	 "atomic_and_uchar_nv"
	.long	37190
	.asciz	 "atomic_swap_64"
	.long	14925
	.asciz	 "atomic_inc_long_nv"
	.long	38913
	.asciz	 "membar_consumer"
	.long	36546
	.asciz	 "atomic_swap_uint"
	.long	4610
	.asciz	 "atomic_dec_ulong"
	.long	533
	.asciz	 "atomic_inc_8"
	.long	9744
	.asciz	 "atomic_sub_64"
	.long	26161
	.asciz	 "atomic_or_long_nv"
	.long	38693
	.asciz	 "membar_enter"
	.long	13461
	.asciz	 "atomic_and_ushort"
	.long	20184
	.asciz	 "atomic_dec_64_nv"
	.long	26484
	.asciz	 "atomic_or_8_nv"
	.long	24226
	.asciz	 "atomic_sub_short_nv"
	.long	7448
	.asciz	 "atomic_add_ptr"
	.long	35906
	.asciz	 "atomic_swap_ushort"
	.long	2980
	.asciz	 "atomic_dec_8"
	.long	23287
	.asciz	 "atomic_sub_8_nv"
	.long	20786
	.asciz	 "atomic_add_char_nv"
	.long	4337
	.asciz	 "atomic_dec_uint"
	.long	800
	.asciz	 "atomic_inc_uchar"
	.long	31949
	.asciz	 "atomic_cas_8"
	.long	24551
	.asciz	 "atomic_sub_32_nv"
	.long	21099
	.asciz	 "atomic_add_16_nv"
	.long	2707
	.asciz	 "atomic_dec_long"
	.long	21408
	.asciz	 "atomic_add_short_nv"
	.long	1344
	.asciz	 "atomic_inc_ushort"
	.long	1621
	.asciz	 "atomic_inc_32"
	.long	3247
	.asciz	 "atomic_dec_uchar"
	.long	25837
	.asciz	 "atomic_sub_ptr_nv"
	.long	15901
	.asciz	 "atomic_inc_16_nv"
	.long	0
Lpubnames_end1:
	.section	__DWARF,__debug_pubtypes,regular,debug
Lset1388 = Lpubtypes_end1-Lpubtypes_begin1
	.long	Lset1388
Lpubtypes_begin1:
	.short	2
Lset1389 = Linfo_begin1-Lsection_info
	.long	Lset1389
Lset1390 = Linfo_end1-Linfo_begin1
	.long	Lset1390
	.long	0
Lpubtypes_end1:
	.section	__DWARF,__debug_aranges,regular,debug
	.section	__DWARF,__debug_ranges,regular,debug
	.section	__DWARF,__debug_macinfo,regular,debug
	.section	__DWARF,__debug_inlined,regular,debug
Lset1391 = Ldebug_inlined_end1-Ldebug_inlined_begin1
	.long	Lset1391
Ldebug_inlined_begin1:
	.short	2
	.byte	8
Ldebug_inlined_end1:

.subsections_via_symbols
