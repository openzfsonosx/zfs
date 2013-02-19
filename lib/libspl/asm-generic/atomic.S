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
	.globl	_membar_enter
	.align	4, 0x90
_membar_enter:
Leh_func_begin1:
Lfunc_begin1:
Ltmp2:
	pushq	%rbp
Ltmp0:
	movq	%rsp, %rbp
Ltmp1:
Ltmp3:
	popq	%rbp
	ret
Ltmp4:
Lfunc_end1:
Leh_func_end1:

	.globl	_membar_exit
	.align	4, 0x90
_membar_exit:
Leh_func_begin2:
Lfunc_begin2:
Ltmp7:
	pushq	%rbp
Ltmp5:
	movq	%rsp, %rbp
Ltmp6:
Ltmp8:
	popq	%rbp
	ret
Ltmp9:
Lfunc_end2:
Leh_func_end2:

	.globl	_membar_producer
	.align	4, 0x90
_membar_producer:
Leh_func_begin3:
Lfunc_begin3:
Ltmp12:
	pushq	%rbp
Ltmp10:
	movq	%rsp, %rbp
Ltmp11:
Ltmp13:
	popq	%rbp
	ret
Ltmp14:
Lfunc_end3:
Leh_func_end3:

	.globl	_membar_consumer
	.align	4, 0x90
_membar_consumer:
Leh_func_begin4:
Lfunc_begin4:
Ltmp17:
	pushq	%rbp
Ltmp15:
	movq	%rsp, %rbp
Ltmp16:
Ltmp18:
	popq	%rbp
	ret
Ltmp19:
Lfunc_end4:
Leh_func_end4:

	.globl	_atomic_clear_long_excl
	.align	4, 0x90
_atomic_clear_long_excl:
Leh_func_begin5:
Lfunc_begin5:
Ltmp23:
	pushq	%rbp
Ltmp20:
	movq	%rsp, %rbp
Ltmp21:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp22:
	movl	%esi, %ebx
Ltmp24:
	movq	%rdi, %r14
Ltmp25:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp26:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp27:
Ltmp28:
Ltmp29:
	je	LBB5_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp30:
Ltmp31:
	movslq	%eax, %rax
Ltmp32:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$413, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp33:
LBB5_2:
Ltmp34:
	movb	%bl, %cl
	movl	$1, %eax
	shlq	%cl, %rax
Ltmp35:
Ltmp36:
	movq	(%r14), %rcx
	btq	%rbx, %rcx
	jae	LBB5_9
	leaq	_atomic_lock(%rip), %rdi
Ltmp37:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp38:
	jne	LBB5_7
	movl	$-1, %eax
LBB5_5:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	cmpq	-32(%rbp), %rcx
	je	LBB5_13
LBB5_6:
	callq	___stack_chk_fail
LBB5_7:
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp39:
Ltmp40:
	movslq	%eax, %rax
Ltmp41:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$416, %edx
	movq	%r14, %rdi
	callq	___assert
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB5_6
	movl	$-1, %eax
	jmp	LBB5_13
Ltmp42:
LBB5_9:
Ltmp43:
	notq	%rax
	andq	%rax, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp44:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp45:
	jne	LBB5_11
	xorl	%eax, %eax
	jmp	LBB5_5
LBB5_11:
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp46:
Ltmp47:
	movslq	%eax, %rax
Ltmp48:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$420, %edx
	movq	%rbx, %rdi
	callq	___assert
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB5_6
	xorl	%eax, %eax
Ltmp49:
LBB5_13:
Ltmp50:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
Ltmp51:
Lfunc_end5:
Leh_func_end5:

	.globl	_atomic_set_long_excl
	.align	4, 0x90
_atomic_set_long_excl:
Leh_func_begin6:
Lfunc_begin6:
Ltmp55:
	pushq	%rbp
Ltmp52:
	movq	%rsp, %rbp
Ltmp53:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp54:
	movl	%esi, %ebx
Ltmp56:
	movq	%rdi, %r14
Ltmp57:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp58:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp59:
Ltmp60:
Ltmp61:
	je	LBB6_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp62:
Ltmp63:
	movslq	%eax, %rax
Ltmp64:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$397, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp65:
LBB6_2:
Ltmp66:
	movb	%bl, %cl
	movl	$1, %eax
	shlq	%cl, %rax
Ltmp67:
Ltmp68:
	movq	(%r14), %rcx
	btq	%rbx, %rcx
	jae	LBB6_9
	leaq	_atomic_lock(%rip), %rdi
Ltmp69:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp70:
	jne	LBB6_7
	movl	$-1, %eax
LBB6_5:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rcx
	movq	(%rcx), %rcx
	cmpq	-32(%rbp), %rcx
	je	LBB6_13
LBB6_6:
	callq	___stack_chk_fail
LBB6_7:
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp71:
Ltmp72:
	movslq	%eax, %rax
Ltmp73:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$400, %edx
	movq	%r14, %rdi
	callq	___assert
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB6_6
	movl	$-1, %eax
	jmp	LBB6_13
Ltmp74:
LBB6_9:
Ltmp75:
	orq	%rax, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp76:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp77:
	jne	LBB6_11
	xorl	%eax, %eax
	jmp	LBB6_5
LBB6_11:
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp78:
Ltmp79:
	movslq	%eax, %rax
Ltmp80:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$404, %edx
	movq	%rbx, %rdi
	callq	___assert
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB6_6
	xorl	%eax, %eax
Ltmp81:
LBB6_13:
Ltmp82:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
Ltmp83:
Lfunc_end6:
Leh_func_end6:

	.globl	_atomic_swap_ptr
	.align	4, 0x90
_atomic_swap_ptr:
Leh_func_begin7:
Lfunc_begin7:
Ltmp87:
	pushq	%rbp
Ltmp84:
	movq	%rsp, %rbp
Ltmp85:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp86:
	movq	%rsi, %rbx
Ltmp88:
	movq	%rdi, %r14
Ltmp89:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp90:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp91:
Ltmp92:
Ltmp93:
	je	LBB7_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp94:
Ltmp95:
	movslq	%eax, %rax
Ltmp96:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$384, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp97:
LBB7_2:
Ltmp98:
	movq	(%r14), %r15
Ltmp99:
Ltmp100:
	movq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp101:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp102:
	je	LBB7_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp103:
Ltmp104:
	movslq	%eax, %rax
Ltmp105:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$387, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB7_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB7_6
	movq	%r15, %rax
Ltmp106:
Ltmp107:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB7_6:
	callq	___stack_chk_fail
Ltmp108:
Lfunc_end7:
Leh_func_end7:

	.globl	_atomic_swap_64
	.align	4, 0x90
_atomic_swap_64:
Leh_func_begin8:
Lfunc_begin8:
Ltmp112:
	pushq	%rbp
Ltmp109:
	movq	%rsp, %rbp
Ltmp110:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp111:
	movq	%rsi, %rbx
Ltmp113:
	movq	%rdi, %r14
Ltmp114:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp115:
Ltmp116:
Ltmp117:
	je	LBB8_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp118:
Ltmp119:
	movslq	%eax, %rax
Ltmp120:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$378, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp121:
LBB8_2:
Ltmp122:
	movq	(%r14), %r15
	movq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp123:
	je	LBB8_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp124:
Ltmp125:
	movslq	%eax, %rax
Ltmp126:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$378, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB8_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB8_6
	movq	%r15, %rax
Ltmp127:
Ltmp128:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB8_6:
	callq	___stack_chk_fail
Ltmp129:
Lfunc_end8:
Leh_func_end8:

	.globl	_atomic_swap_ulong
	.align	4, 0x90
_atomic_swap_ulong:
Leh_func_begin9:
Lfunc_begin9:
Ltmp133:
	pushq	%rbp
Ltmp130:
	movq	%rsp, %rbp
Ltmp131:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp132:
	movq	%rsi, %rbx
Ltmp134:
	movq	%rdi, %r14
Ltmp135:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp136:
Ltmp137:
Ltmp138:
	je	LBB9_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp139:
Ltmp140:
	movslq	%eax, %rax
Ltmp141:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$377, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp142:
LBB9_2:
Ltmp143:
	movq	(%r14), %r15
	movq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp144:
	je	LBB9_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp145:
Ltmp146:
	movslq	%eax, %rax
Ltmp147:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$377, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB9_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB9_6
	movq	%r15, %rax
Ltmp148:
Ltmp149:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB9_6:
	callq	___stack_chk_fail
Ltmp150:
Lfunc_end9:
Leh_func_end9:

	.globl	_atomic_swap_uint
	.align	4, 0x90
_atomic_swap_uint:
Leh_func_begin10:
Lfunc_begin10:
Ltmp154:
	pushq	%rbp
Ltmp151:
	movq	%rsp, %rbp
Ltmp152:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp153:
	movl	%esi, %ebx
Ltmp155:
	movq	%rdi, %r14
Ltmp156:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp157:
Ltmp158:
Ltmp159:
	je	LBB10_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp160:
Ltmp161:
	movslq	%eax, %rax
Ltmp162:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$376, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp163:
LBB10_2:
Ltmp164:
	movl	(%r14), %r15d
	movl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp165:
	je	LBB10_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp166:
Ltmp167:
	movslq	%eax, %rax
Ltmp168:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$376, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB10_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB10_6
	movl	%r15d, %eax
Ltmp169:
Ltmp170:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB10_6:
	callq	___stack_chk_fail
Ltmp171:
Lfunc_end10:
Leh_func_end10:

	.globl	_atomic_swap_32
	.align	4, 0x90
_atomic_swap_32:
Leh_func_begin11:
Lfunc_begin11:
Ltmp175:
	pushq	%rbp
Ltmp172:
	movq	%rsp, %rbp
Ltmp173:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp174:
	movl	%esi, %ebx
Ltmp176:
	movq	%rdi, %r14
Ltmp177:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp178:
Ltmp179:
Ltmp180:
	je	LBB11_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp181:
Ltmp182:
	movslq	%eax, %rax
Ltmp183:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$375, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp184:
LBB11_2:
Ltmp185:
	movl	(%r14), %r15d
	movl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp186:
	je	LBB11_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp187:
Ltmp188:
	movslq	%eax, %rax
Ltmp189:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$375, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB11_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB11_6
	movl	%r15d, %eax
Ltmp190:
Ltmp191:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB11_6:
	callq	___stack_chk_fail
Ltmp192:
Lfunc_end11:
Leh_func_end11:

	.globl	_atomic_swap_ushort
	.align	4, 0x90
_atomic_swap_ushort:
Leh_func_begin12:
Lfunc_begin12:
Ltmp196:
	pushq	%rbp
Ltmp193:
	movq	%rsp, %rbp
Ltmp194:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp195:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp197:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp198:
Ltmp199:
	je	LBB12_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp200:
Ltmp201:
	movslq	%eax, %rax
Ltmp202:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$374, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp203:
LBB12_2:
Ltmp204:
	movw	(%r14), %r15w
	movw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp205:
	je	LBB12_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp206:
Ltmp207:
	movslq	%eax, %rax
Ltmp208:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$374, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB12_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB12_6
Ltmp209:
Ltmp210:
	movzwl	%r15w, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB12_6:
	callq	___stack_chk_fail
Ltmp211:
Lfunc_end12:
Leh_func_end12:

	.globl	_atomic_swap_16
	.align	4, 0x90
_atomic_swap_16:
Leh_func_begin13:
Lfunc_begin13:
Ltmp215:
	pushq	%rbp
Ltmp212:
	movq	%rsp, %rbp
Ltmp213:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp214:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp216:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp217:
Ltmp218:
	je	LBB13_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp219:
Ltmp220:
	movslq	%eax, %rax
Ltmp221:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$373, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp222:
LBB13_2:
Ltmp223:
	movw	(%r14), %r15w
	movw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp224:
	je	LBB13_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp225:
Ltmp226:
	movslq	%eax, %rax
Ltmp227:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$373, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB13_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB13_6
Ltmp228:
Ltmp229:
	movzwl	%r15w, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB13_6:
	callq	___stack_chk_fail
Ltmp230:
Lfunc_end13:
Leh_func_end13:

	.globl	_atomic_swap_uchar
	.align	4, 0x90
_atomic_swap_uchar:
Leh_func_begin14:
Lfunc_begin14:
Ltmp234:
	pushq	%rbp
Ltmp231:
	movq	%rsp, %rbp
Ltmp232:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp233:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp235:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp236:
Ltmp237:
	je	LBB14_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp238:
Ltmp239:
	movslq	%eax, %rax
Ltmp240:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$372, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp241:
LBB14_2:
Ltmp242:
	movb	(%r14), %r15b
	movb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp243:
	je	LBB14_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp244:
Ltmp245:
	movslq	%eax, %rax
Ltmp246:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$372, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB14_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB14_6
Ltmp247:
Ltmp248:
	movzbl	%r15b, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB14_6:
	callq	___stack_chk_fail
Ltmp249:
Lfunc_end14:
Leh_func_end14:

	.globl	_atomic_swap_8
	.align	4, 0x90
_atomic_swap_8:
Leh_func_begin15:
Lfunc_begin15:
Ltmp253:
	pushq	%rbp
Ltmp250:
	movq	%rsp, %rbp
Ltmp251:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp252:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp254:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp255:
Ltmp256:
	je	LBB15_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp257:
Ltmp258:
	movslq	%eax, %rax
Ltmp259:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$371, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp260:
LBB15_2:
Ltmp261:
	movb	(%r14), %r15b
	movb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp262:
	je	LBB15_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp263:
Ltmp264:
	movslq	%eax, %rax
Ltmp265:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$371, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB15_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB15_6
Ltmp266:
Ltmp267:
	movzbl	%r15b, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB15_6:
	callq	___stack_chk_fail
Ltmp268:
Lfunc_end15:
Leh_func_end15:

	.globl	_atomic_cas_ptr
	.align	4, 0x90
_atomic_cas_ptr:
Leh_func_begin16:
Lfunc_begin16:
Ltmp272:
	pushq	%rbp
Ltmp269:
	movq	%rsp, %rbp
Ltmp270:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp271:
	movq	%rdx, %rbx
Ltmp273:
	movq	%rsi, %r14
Ltmp274:
	movq	%rdi, %r15
Ltmp275:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp276:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp277:
Ltmp278:
Ltmp279:
Ltmp280:
	je	LBB16_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp281:
Ltmp282:
	movslq	%eax, %rax
Ltmp283:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$346, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp284:
LBB16_2:
Ltmp285:
	movq	(%r15), %r12
Ltmp286:
	cmpq	%r14, %r12
	jne	LBB16_4
Ltmp287:
	movq	%rbx, (%r15)
LBB16_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp288:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp289:
	je	LBB16_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp290:
Ltmp291:
	movslq	%eax, %rax
Ltmp292:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$350, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB16_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB16_8
	movq	%r12, %rax
Ltmp293:
Ltmp294:
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB16_8:
	callq	___stack_chk_fail
Ltmp295:
Lfunc_end16:
Leh_func_end16:

	.globl	_casptr
	.align	4, 0x90
_casptr:
Leh_func_begin17:
Lfunc_begin17:
Ltmp298:
	pushq	%rbp
Ltmp296:
	movq	%rsp, %rbp
Ltmp297:
Ltmp299:
Ltmp300:
Ltmp301:
Ltmp302:
Ltmp303:
Ltmp304:
Ltmp305:
	popq	%rbp
	jmp	_atomic_cas_ptr  # TAILCALL
Ltmp306:
Lfunc_end17:
Leh_func_end17:

	.globl	_atomic_cas_64
	.align	4, 0x90
_atomic_cas_64:
Leh_func_begin18:
Lfunc_begin18:
Ltmp310:
	pushq	%rbp
Ltmp307:
	movq	%rsp, %rbp
Ltmp308:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp309:
	movq	%rdx, %rbx
Ltmp311:
	movq	%rsi, %r14
Ltmp312:
	movq	%rdi, %r15
Ltmp313:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp314:
Ltmp315:
Ltmp316:
Ltmp317:
	je	LBB18_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp318:
Ltmp319:
	movslq	%eax, %rax
Ltmp320:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$340, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp321:
LBB18_2:
Ltmp322:
	movq	(%r15), %r12
	cmpq	%r14, %r12
	jne	LBB18_4
	movq	%rbx, (%r15)
LBB18_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp323:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp324:
	je	LBB18_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp325:
Ltmp326:
	movslq	%eax, %rax
Ltmp327:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$340, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB18_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB18_8
	movq	%r12, %rax
Ltmp328:
Ltmp329:
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB18_8:
	callq	___stack_chk_fail
Ltmp330:
Lfunc_end18:
Leh_func_end18:

	.globl	_cas64
	.align	4, 0x90
_cas64:
Leh_func_begin19:
Lfunc_begin19:
Ltmp333:
	pushq	%rbp
Ltmp331:
	movq	%rsp, %rbp
Ltmp332:
Ltmp334:
Ltmp335:
Ltmp336:
Ltmp337:
Ltmp338:
Ltmp339:
Ltmp340:
	popq	%rbp
	jmp	_atomic_cas_64  # TAILCALL
Ltmp341:
Lfunc_end19:
Leh_func_end19:

	.globl	_atomic_cas_ulong
	.align	4, 0x90
_atomic_cas_ulong:
Leh_func_begin20:
Lfunc_begin20:
Ltmp345:
	pushq	%rbp
Ltmp342:
	movq	%rsp, %rbp
Ltmp343:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp344:
	movq	%rdx, %rbx
Ltmp346:
	movq	%rsi, %r14
Ltmp347:
	movq	%rdi, %r15
Ltmp348:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp349:
Ltmp350:
Ltmp351:
Ltmp352:
	je	LBB20_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp353:
Ltmp354:
	movslq	%eax, %rax
Ltmp355:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$339, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp356:
LBB20_2:
Ltmp357:
	movq	(%r15), %r12
	cmpq	%r14, %r12
	jne	LBB20_4
	movq	%rbx, (%r15)
LBB20_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp358:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp359:
	je	LBB20_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp360:
Ltmp361:
	movslq	%eax, %rax
Ltmp362:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$339, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB20_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB20_8
	movq	%r12, %rax
Ltmp363:
Ltmp364:
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB20_8:
	callq	___stack_chk_fail
Ltmp365:
Lfunc_end20:
Leh_func_end20:

	.globl	_caslong
	.align	4, 0x90
_caslong:
Leh_func_begin21:
Lfunc_begin21:
Ltmp368:
	pushq	%rbp
Ltmp366:
	movq	%rsp, %rbp
Ltmp367:
Ltmp369:
Ltmp370:
Ltmp371:
Ltmp372:
Ltmp373:
Ltmp374:
Ltmp375:
	popq	%rbp
	jmp	_atomic_cas_ulong  # TAILCALL
Ltmp376:
Lfunc_end21:
Leh_func_end21:

	.globl	_atomic_cas_uint
	.align	4, 0x90
_atomic_cas_uint:
Leh_func_begin22:
Lfunc_begin22:
Ltmp380:
	pushq	%rbp
Ltmp377:
	movq	%rsp, %rbp
Ltmp378:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp379:
	movl	%edx, %ebx
Ltmp381:
	movl	%esi, %r14d
Ltmp382:
	movq	%rdi, %r15
Ltmp383:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp384:
Ltmp385:
Ltmp386:
Ltmp387:
	je	LBB22_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp388:
Ltmp389:
	movslq	%eax, %rax
Ltmp390:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$338, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp391:
LBB22_2:
Ltmp392:
	movl	(%r15), %r12d
	cmpl	%r14d, %r12d
	jne	LBB22_4
	movl	%ebx, (%r15)
LBB22_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp393:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp394:
	je	LBB22_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp395:
Ltmp396:
	movslq	%eax, %rax
Ltmp397:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$338, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB22_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB22_8
	movl	%r12d, %eax
Ltmp398:
Ltmp399:
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB22_8:
	callq	___stack_chk_fail
Ltmp400:
Lfunc_end22:
Leh_func_end22:

	.globl	_atomic_cas_32
	.align	4, 0x90
_atomic_cas_32:
Leh_func_begin23:
Lfunc_begin23:
Ltmp404:
	pushq	%rbp
Ltmp401:
	movq	%rsp, %rbp
Ltmp402:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp403:
	movl	%edx, %ebx
Ltmp405:
	movl	%esi, %r14d
Ltmp406:
	movq	%rdi, %r15
Ltmp407:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp408:
Ltmp409:
Ltmp410:
Ltmp411:
	je	LBB23_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp412:
Ltmp413:
	movslq	%eax, %rax
Ltmp414:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$337, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp415:
LBB23_2:
Ltmp416:
	movl	(%r15), %r12d
	cmpl	%r14d, %r12d
	jne	LBB23_4
	movl	%ebx, (%r15)
LBB23_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp417:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp418:
	je	LBB23_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp419:
Ltmp420:
	movslq	%eax, %rax
Ltmp421:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$337, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB23_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB23_8
	movl	%r12d, %eax
Ltmp422:
Ltmp423:
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB23_8:
	callq	___stack_chk_fail
Ltmp424:
Lfunc_end23:
Leh_func_end23:

	.globl	_cas32
	.align	4, 0x90
_cas32:
Leh_func_begin24:
Lfunc_begin24:
Ltmp427:
	pushq	%rbp
Ltmp425:
	movq	%rsp, %rbp
Ltmp426:
Ltmp428:
Ltmp429:
Ltmp430:
Ltmp431:
Ltmp432:
Ltmp433:
Ltmp434:
	popq	%rbp
	jmp	_atomic_cas_32  # TAILCALL
Ltmp435:
Lfunc_end24:
Leh_func_end24:

	.globl	_atomic_cas_ushort
	.align	4, 0x90
_atomic_cas_ushort:
Leh_func_begin25:
Lfunc_begin25:
Ltmp439:
	pushq	%rbp
Ltmp436:
	movq	%rsp, %rbp
Ltmp437:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp438:
	movl	%edx, %ebx
	movl	%esi, %r14d
	movq	%rdi, %r15
Ltmp440:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp441:
Ltmp442:
	je	LBB25_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp443:
Ltmp444:
	movslq	%eax, %rax
Ltmp445:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$336, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp446:
LBB25_2:
Ltmp447:
	movw	(%r15), %r12w
	cmpw	%r14w, %r12w
	jne	LBB25_4
	movw	%bx, (%r15)
LBB25_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp448:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp449:
	je	LBB25_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp450:
Ltmp451:
	movslq	%eax, %rax
Ltmp452:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$336, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB25_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB25_8
Ltmp453:
Ltmp454:
	movzwl	%r12w, %eax
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB25_8:
	callq	___stack_chk_fail
Ltmp455:
Lfunc_end25:
Leh_func_end25:

	.globl	_atomic_cas_16
	.align	4, 0x90
_atomic_cas_16:
Leh_func_begin26:
Lfunc_begin26:
Ltmp459:
	pushq	%rbp
Ltmp456:
	movq	%rsp, %rbp
Ltmp457:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp458:
	movl	%edx, %ebx
	movl	%esi, %r14d
	movq	%rdi, %r15
Ltmp460:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp461:
Ltmp462:
	je	LBB26_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp463:
Ltmp464:
	movslq	%eax, %rax
Ltmp465:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$335, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp466:
LBB26_2:
Ltmp467:
	movw	(%r15), %r12w
	cmpw	%r14w, %r12w
	jne	LBB26_4
	movw	%bx, (%r15)
LBB26_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp468:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp469:
	je	LBB26_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp470:
Ltmp471:
	movslq	%eax, %rax
Ltmp472:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$335, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB26_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB26_8
Ltmp473:
Ltmp474:
	movzwl	%r12w, %eax
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB26_8:
	callq	___stack_chk_fail
Ltmp475:
Lfunc_end26:
Leh_func_end26:

	.globl	_atomic_cas_uchar
	.align	4, 0x90
_atomic_cas_uchar:
Leh_func_begin27:
Lfunc_begin27:
Ltmp479:
	pushq	%rbp
Ltmp476:
	movq	%rsp, %rbp
Ltmp477:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp478:
	movl	%edx, %ebx
	movl	%esi, %r14d
	movq	%rdi, %r15
Ltmp480:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp481:
Ltmp482:
	je	LBB27_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp483:
Ltmp484:
	movslq	%eax, %rax
Ltmp485:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$334, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp486:
LBB27_2:
Ltmp487:
	movb	(%r15), %r12b
	cmpb	%r14b, %r12b
	jne	LBB27_4
	movb	%bl, (%r15)
LBB27_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp488:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp489:
	je	LBB27_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp490:
Ltmp491:
	movslq	%eax, %rax
Ltmp492:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$334, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB27_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB27_8
Ltmp493:
Ltmp494:
	movzbl	%r12b, %eax
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB27_8:
	callq	___stack_chk_fail
Ltmp495:
Lfunc_end27:
Leh_func_end27:

	.globl	_atomic_cas_8
	.align	4, 0x90
_atomic_cas_8:
Leh_func_begin28:
Lfunc_begin28:
Ltmp499:
	pushq	%rbp
Ltmp496:
	movq	%rsp, %rbp
Ltmp497:
	pushq	%r15
	pushq	%r14
	pushq	%r12
	pushq	%rbx
	subq	$16, %rsp
Ltmp498:
	movl	%edx, %ebx
	movl	%esi, %r14d
	movq	%rdi, %r15
Ltmp500:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -40(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp501:
Ltmp502:
	je	LBB28_2
	leaq	-256(%rsp), %r12
	movq	%r12, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp503:
Ltmp504:
	movslq	%eax, %rax
Ltmp505:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r12, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$333, %edx
	movq	%r12, %rdi
	callq	___assert
Ltmp506:
LBB28_2:
Ltmp507:
	movb	(%r15), %r12b
	cmpb	%r14b, %r12b
	jne	LBB28_4
	movb	%bl, (%r15)
LBB28_4:
	leaq	_atomic_lock(%rip), %rdi
Ltmp508:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp509:
	je	LBB28_6
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp510:
Ltmp511:
	movslq	%eax, %rax
Ltmp512:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$333, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB28_6:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-40(%rbp), %rax
	jne	LBB28_8
Ltmp513:
Ltmp514:
	movzbl	%r12b, %eax
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB28_8:
	callq	___stack_chk_fail
Ltmp515:
Lfunc_end28:
Leh_func_end28:

	.globl	_cas8
	.align	4, 0x90
_cas8:
Leh_func_begin29:
Lfunc_begin29:
Ltmp518:
	pushq	%rbp
Ltmp516:
	movq	%rsp, %rbp
Ltmp517:
Ltmp519:
Ltmp520:
Ltmp521:
	callq	_atomic_cas_8
	movzbl	%al, %eax
	popq	%rbp
	ret
Ltmp522:
Lfunc_end29:
Leh_func_end29:

	.globl	_atomic_and_64_nv
	.align	4, 0x90
_atomic_and_64_nv:
Leh_func_begin30:
Lfunc_begin30:
Ltmp526:
	pushq	%rbp
Ltmp523:
	movq	%rsp, %rbp
Ltmp524:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp525:
	movq	%rsi, %rbx
Ltmp527:
	movq	%rdi, %r14
Ltmp528:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp529:
Ltmp530:
Ltmp531:
	je	LBB30_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp532:
Ltmp533:
	movslq	%eax, %rax
Ltmp534:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$314, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp535:
LBB30_2:
Ltmp536:
	andq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp537:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp538:
	je	LBB30_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp539:
Ltmp540:
	movslq	%eax, %rax
Ltmp541:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$314, %edx
	movq	%r14, %rdi
	callq	___assert
LBB30_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB30_6
	movq	%rbx, %rax
Ltmp542:
Ltmp543:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB30_6:
	callq	___stack_chk_fail
Ltmp544:
Lfunc_end30:
Leh_func_end30:

	.globl	_atomic_and_ulong_nv
	.align	4, 0x90
_atomic_and_ulong_nv:
Leh_func_begin31:
Lfunc_begin31:
Ltmp548:
	pushq	%rbp
Ltmp545:
	movq	%rsp, %rbp
Ltmp546:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp547:
	movq	%rsi, %rbx
Ltmp549:
	movq	%rdi, %r14
Ltmp550:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp551:
Ltmp552:
Ltmp553:
	je	LBB31_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp554:
Ltmp555:
	movslq	%eax, %rax
Ltmp556:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$313, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp557:
LBB31_2:
Ltmp558:
	andq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp559:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp560:
	je	LBB31_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp561:
Ltmp562:
	movslq	%eax, %rax
Ltmp563:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$313, %edx
	movq	%r14, %rdi
	callq	___assert
LBB31_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB31_6
	movq	%rbx, %rax
Ltmp564:
Ltmp565:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB31_6:
	callq	___stack_chk_fail
Ltmp566:
Lfunc_end31:
Leh_func_end31:

	.globl	_atomic_and_uint_nv
	.align	4, 0x90
_atomic_and_uint_nv:
Leh_func_begin32:
Lfunc_begin32:
Ltmp570:
	pushq	%rbp
Ltmp567:
	movq	%rsp, %rbp
Ltmp568:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp569:
	movl	%esi, %ebx
Ltmp571:
	movq	%rdi, %r14
Ltmp572:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp573:
Ltmp574:
Ltmp575:
	je	LBB32_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp576:
Ltmp577:
	movslq	%eax, %rax
Ltmp578:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$312, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp579:
LBB32_2:
Ltmp580:
	andl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp581:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp582:
	je	LBB32_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp583:
Ltmp584:
	movslq	%eax, %rax
Ltmp585:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$312, %edx
	movq	%r14, %rdi
	callq	___assert
LBB32_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB32_6
	movl	%ebx, %eax
Ltmp586:
Ltmp587:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB32_6:
	callq	___stack_chk_fail
Ltmp588:
Lfunc_end32:
Leh_func_end32:

	.globl	_atomic_and_32_nv
	.align	4, 0x90
_atomic_and_32_nv:
Leh_func_begin33:
Lfunc_begin33:
Ltmp592:
	pushq	%rbp
Ltmp589:
	movq	%rsp, %rbp
Ltmp590:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp591:
	movl	%esi, %ebx
Ltmp593:
	movq	%rdi, %r14
Ltmp594:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp595:
Ltmp596:
Ltmp597:
	je	LBB33_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp598:
Ltmp599:
	movslq	%eax, %rax
Ltmp600:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$311, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp601:
LBB33_2:
Ltmp602:
	andl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp603:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp604:
	je	LBB33_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp605:
Ltmp606:
	movslq	%eax, %rax
Ltmp607:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$311, %edx
	movq	%r14, %rdi
	callq	___assert
LBB33_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB33_6
	movl	%ebx, %eax
Ltmp608:
Ltmp609:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB33_6:
	callq	___stack_chk_fail
Ltmp610:
Lfunc_end33:
Leh_func_end33:

	.globl	_atomic_and_ushort_nv
	.align	4, 0x90
_atomic_and_ushort_nv:
Leh_func_begin34:
Lfunc_begin34:
Ltmp614:
	pushq	%rbp
Ltmp611:
	movq	%rsp, %rbp
Ltmp612:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp613:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp615:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp616:
Ltmp617:
	je	LBB34_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp618:
Ltmp619:
	movslq	%eax, %rax
Ltmp620:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$310, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp621:
LBB34_2:
Ltmp622:
	andw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp623:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp624:
	je	LBB34_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp625:
Ltmp626:
	movslq	%eax, %rax
Ltmp627:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$310, %edx
	movq	%r14, %rdi
	callq	___assert
LBB34_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB34_6
Ltmp628:
Ltmp629:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB34_6:
	callq	___stack_chk_fail
Ltmp630:
Lfunc_end34:
Leh_func_end34:

	.globl	_atomic_and_16_nv
	.align	4, 0x90
_atomic_and_16_nv:
Leh_func_begin35:
Lfunc_begin35:
Ltmp634:
	pushq	%rbp
Ltmp631:
	movq	%rsp, %rbp
Ltmp632:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp633:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp635:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp636:
Ltmp637:
	je	LBB35_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp638:
Ltmp639:
	movslq	%eax, %rax
Ltmp640:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$309, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp641:
LBB35_2:
Ltmp642:
	andw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp643:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp644:
	je	LBB35_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp645:
Ltmp646:
	movslq	%eax, %rax
Ltmp647:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$309, %edx
	movq	%r14, %rdi
	callq	___assert
LBB35_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB35_6
Ltmp648:
Ltmp649:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB35_6:
	callq	___stack_chk_fail
Ltmp650:
Lfunc_end35:
Leh_func_end35:

	.globl	_atomic_and_uchar_nv
	.align	4, 0x90
_atomic_and_uchar_nv:
Leh_func_begin36:
Lfunc_begin36:
Ltmp654:
	pushq	%rbp
Ltmp651:
	movq	%rsp, %rbp
Ltmp652:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp653:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp655:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp656:
Ltmp657:
	je	LBB36_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp658:
Ltmp659:
	movslq	%eax, %rax
Ltmp660:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$308, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp661:
LBB36_2:
Ltmp662:
	andb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp663:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp664:
	je	LBB36_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp665:
Ltmp666:
	movslq	%eax, %rax
Ltmp667:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$308, %edx
	movq	%r14, %rdi
	callq	___assert
LBB36_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB36_6
Ltmp668:
Ltmp669:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB36_6:
	callq	___stack_chk_fail
Ltmp670:
Lfunc_end36:
Leh_func_end36:

	.globl	_atomic_and_8_nv
	.align	4, 0x90
_atomic_and_8_nv:
Leh_func_begin37:
Lfunc_begin37:
Ltmp674:
	pushq	%rbp
Ltmp671:
	movq	%rsp, %rbp
Ltmp672:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp673:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp675:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp676:
Ltmp677:
	je	LBB37_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp678:
Ltmp679:
	movslq	%eax, %rax
Ltmp680:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$307, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp681:
LBB37_2:
Ltmp682:
	andb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp683:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp684:
	je	LBB37_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp685:
Ltmp686:
	movslq	%eax, %rax
Ltmp687:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$307, %edx
	movq	%r14, %rdi
	callq	___assert
LBB37_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB37_6
Ltmp688:
Ltmp689:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB37_6:
	callq	___stack_chk_fail
Ltmp690:
Lfunc_end37:
Leh_func_end37:

	.globl	_atomic_and_long_nv
	.align	4, 0x90
_atomic_and_long_nv:
Leh_func_begin38:
Lfunc_begin38:
Ltmp694:
	pushq	%rbp
Ltmp691:
	movq	%rsp, %rbp
Ltmp692:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp693:
	movq	%rsi, %rbx
Ltmp695:
	movq	%rdi, %r14
Ltmp696:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp697:
Ltmp698:
Ltmp699:
	je	LBB38_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp700:
Ltmp701:
	movslq	%eax, %rax
Ltmp702:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$306, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp703:
LBB38_2:
Ltmp704:
	andq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp705:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp706:
	je	LBB38_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp707:
Ltmp708:
	movslq	%eax, %rax
Ltmp709:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$306, %edx
	movq	%r14, %rdi
	callq	___assert
LBB38_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB38_6
	movq	%rbx, %rax
Ltmp710:
Ltmp711:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB38_6:
	callq	___stack_chk_fail
Ltmp712:
Lfunc_end38:
Leh_func_end38:

	.globl	_atomic_or_64_nv
	.align	4, 0x90
_atomic_or_64_nv:
Leh_func_begin39:
Lfunc_begin39:
Ltmp716:
	pushq	%rbp
Ltmp713:
	movq	%rsp, %rbp
Ltmp714:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp715:
	movq	%rsi, %rbx
Ltmp717:
	movq	%rdi, %r14
Ltmp718:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp719:
Ltmp720:
Ltmp721:
	je	LBB39_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp722:
Ltmp723:
	movslq	%eax, %rax
Ltmp724:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$293, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp725:
LBB39_2:
Ltmp726:
	orq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp727:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp728:
	je	LBB39_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp729:
Ltmp730:
	movslq	%eax, %rax
Ltmp731:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$293, %edx
	movq	%r14, %rdi
	callq	___assert
LBB39_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB39_6
	movq	%rbx, %rax
Ltmp732:
Ltmp733:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB39_6:
	callq	___stack_chk_fail
Ltmp734:
Lfunc_end39:
Leh_func_end39:

	.globl	_atomic_or_ulong_nv
	.align	4, 0x90
_atomic_or_ulong_nv:
Leh_func_begin40:
Lfunc_begin40:
Ltmp738:
	pushq	%rbp
Ltmp735:
	movq	%rsp, %rbp
Ltmp736:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp737:
	movq	%rsi, %rbx
Ltmp739:
	movq	%rdi, %r14
Ltmp740:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp741:
Ltmp742:
Ltmp743:
	je	LBB40_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp744:
Ltmp745:
	movslq	%eax, %rax
Ltmp746:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$292, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp747:
LBB40_2:
Ltmp748:
	orq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp749:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp750:
	je	LBB40_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp751:
Ltmp752:
	movslq	%eax, %rax
Ltmp753:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$292, %edx
	movq	%r14, %rdi
	callq	___assert
LBB40_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB40_6
	movq	%rbx, %rax
Ltmp754:
Ltmp755:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB40_6:
	callq	___stack_chk_fail
Ltmp756:
Lfunc_end40:
Leh_func_end40:

	.globl	_atomic_or_uint_nv
	.align	4, 0x90
_atomic_or_uint_nv:
Leh_func_begin41:
Lfunc_begin41:
Ltmp760:
	pushq	%rbp
Ltmp757:
	movq	%rsp, %rbp
Ltmp758:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp759:
	movl	%esi, %ebx
Ltmp761:
	movq	%rdi, %r14
Ltmp762:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp763:
Ltmp764:
Ltmp765:
	je	LBB41_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp766:
Ltmp767:
	movslq	%eax, %rax
Ltmp768:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$291, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp769:
LBB41_2:
Ltmp770:
	orl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp771:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp772:
	je	LBB41_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp773:
Ltmp774:
	movslq	%eax, %rax
Ltmp775:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$291, %edx
	movq	%r14, %rdi
	callq	___assert
LBB41_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB41_6
	movl	%ebx, %eax
Ltmp776:
Ltmp777:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB41_6:
	callq	___stack_chk_fail
Ltmp778:
Lfunc_end41:
Leh_func_end41:

	.globl	_atomic_or_32_nv
	.align	4, 0x90
_atomic_or_32_nv:
Leh_func_begin42:
Lfunc_begin42:
Ltmp782:
	pushq	%rbp
Ltmp779:
	movq	%rsp, %rbp
Ltmp780:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp781:
	movl	%esi, %ebx
Ltmp783:
	movq	%rdi, %r14
Ltmp784:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp785:
Ltmp786:
Ltmp787:
	je	LBB42_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp788:
Ltmp789:
	movslq	%eax, %rax
Ltmp790:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$290, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp791:
LBB42_2:
Ltmp792:
	orl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp793:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp794:
	je	LBB42_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp795:
Ltmp796:
	movslq	%eax, %rax
Ltmp797:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$290, %edx
	movq	%r14, %rdi
	callq	___assert
LBB42_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB42_6
	movl	%ebx, %eax
Ltmp798:
Ltmp799:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB42_6:
	callq	___stack_chk_fail
Ltmp800:
Lfunc_end42:
Leh_func_end42:

	.globl	_atomic_or_ushort_nv
	.align	4, 0x90
_atomic_or_ushort_nv:
Leh_func_begin43:
Lfunc_begin43:
Ltmp804:
	pushq	%rbp
Ltmp801:
	movq	%rsp, %rbp
Ltmp802:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp803:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp805:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp806:
Ltmp807:
	je	LBB43_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp808:
Ltmp809:
	movslq	%eax, %rax
Ltmp810:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$289, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp811:
LBB43_2:
Ltmp812:
	orw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp813:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp814:
	je	LBB43_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp815:
Ltmp816:
	movslq	%eax, %rax
Ltmp817:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$289, %edx
	movq	%r14, %rdi
	callq	___assert
LBB43_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB43_6
Ltmp818:
Ltmp819:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB43_6:
	callq	___stack_chk_fail
Ltmp820:
Lfunc_end43:
Leh_func_end43:

	.globl	_atomic_or_16_nv
	.align	4, 0x90
_atomic_or_16_nv:
Leh_func_begin44:
Lfunc_begin44:
Ltmp824:
	pushq	%rbp
Ltmp821:
	movq	%rsp, %rbp
Ltmp822:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp823:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp825:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp826:
Ltmp827:
	je	LBB44_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp828:
Ltmp829:
	movslq	%eax, %rax
Ltmp830:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$288, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp831:
LBB44_2:
Ltmp832:
	orw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp833:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp834:
	je	LBB44_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp835:
Ltmp836:
	movslq	%eax, %rax
Ltmp837:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$288, %edx
	movq	%r14, %rdi
	callq	___assert
LBB44_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB44_6
Ltmp838:
Ltmp839:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB44_6:
	callq	___stack_chk_fail
Ltmp840:
Lfunc_end44:
Leh_func_end44:

	.globl	_atomic_or_uchar_nv
	.align	4, 0x90
_atomic_or_uchar_nv:
Leh_func_begin45:
Lfunc_begin45:
Ltmp844:
	pushq	%rbp
Ltmp841:
	movq	%rsp, %rbp
Ltmp842:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp843:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp845:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp846:
Ltmp847:
	je	LBB45_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp848:
Ltmp849:
	movslq	%eax, %rax
Ltmp850:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$287, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp851:
LBB45_2:
Ltmp852:
	orb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp853:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp854:
	je	LBB45_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp855:
Ltmp856:
	movslq	%eax, %rax
Ltmp857:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$287, %edx
	movq	%r14, %rdi
	callq	___assert
LBB45_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB45_6
Ltmp858:
Ltmp859:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB45_6:
	callq	___stack_chk_fail
Ltmp860:
Lfunc_end45:
Leh_func_end45:

	.globl	_atomic_or_8_nv
	.align	4, 0x90
_atomic_or_8_nv:
Leh_func_begin46:
Lfunc_begin46:
Ltmp864:
	pushq	%rbp
Ltmp861:
	movq	%rsp, %rbp
Ltmp862:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp863:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp865:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp866:
Ltmp867:
	je	LBB46_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp868:
Ltmp869:
	movslq	%eax, %rax
Ltmp870:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$286, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp871:
LBB46_2:
Ltmp872:
	orb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp873:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp874:
	je	LBB46_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp875:
Ltmp876:
	movslq	%eax, %rax
Ltmp877:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$286, %edx
	movq	%r14, %rdi
	callq	___assert
LBB46_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB46_6
Ltmp878:
Ltmp879:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB46_6:
	callq	___stack_chk_fail
Ltmp880:
Lfunc_end46:
Leh_func_end46:

	.globl	_atomic_or_long_nv
	.align	4, 0x90
_atomic_or_long_nv:
Leh_func_begin47:
Lfunc_begin47:
Ltmp884:
	pushq	%rbp
Ltmp881:
	movq	%rsp, %rbp
Ltmp882:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp883:
	movq	%rsi, %rbx
Ltmp885:
	movq	%rdi, %r14
Ltmp886:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp887:
Ltmp888:
Ltmp889:
	je	LBB47_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp890:
Ltmp891:
	movslq	%eax, %rax
Ltmp892:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$285, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp893:
LBB47_2:
Ltmp894:
	orq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp895:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp896:
	je	LBB47_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp897:
Ltmp898:
	movslq	%eax, %rax
Ltmp899:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$285, %edx
	movq	%r14, %rdi
	callq	___assert
LBB47_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB47_6
	movq	%rbx, %rax
Ltmp900:
Ltmp901:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB47_6:
	callq	___stack_chk_fail
Ltmp902:
Lfunc_end47:
Leh_func_end47:

	.globl	_atomic_sub_ptr_nv
	.align	4, 0x90
_atomic_sub_ptr_nv:
Leh_func_begin48:
Lfunc_begin48:
Ltmp906:
	pushq	%rbp
Ltmp903:
	movq	%rsp, %rbp
Ltmp904:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp905:
	movq	%rsi, %rbx
Ltmp907:
	movq	%rdi, %r14
Ltmp908:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp909:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp910:
Ltmp911:
Ltmp912:
	je	LBB48_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp913:
Ltmp914:
	movslq	%eax, %rax
Ltmp915:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$267, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp916:
LBB48_2:
Ltmp917:
	movq	(%r14), %r15
	subq	%rbx, %r15
	movq	%r15, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp918:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp919:
	je	LBB48_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp920:
Ltmp921:
	movslq	%eax, %rax
Ltmp922:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$269, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB48_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB48_6
	movq	%r15, %rax
Ltmp923:
Ltmp924:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB48_6:
	callq	___stack_chk_fail
Ltmp925:
Lfunc_end48:
Leh_func_end48:

	.globl	_atomic_sub_64_nv
	.align	4, 0x90
_atomic_sub_64_nv:
Leh_func_begin49:
Lfunc_begin49:
Ltmp929:
	pushq	%rbp
Ltmp926:
	movq	%rsp, %rbp
Ltmp927:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp928:
	movq	%rsi, %rbx
Ltmp930:
	movq	%rdi, %r14
Ltmp931:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp932:
Ltmp933:
Ltmp934:
	je	LBB49_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp935:
Ltmp936:
	movslq	%eax, %rax
Ltmp937:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$261, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp938:
LBB49_2:
Ltmp939:
	subq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp940:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp941:
	je	LBB49_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp942:
Ltmp943:
	movslq	%eax, %rax
Ltmp944:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$261, %edx
	movq	%r14, %rdi
	callq	___assert
LBB49_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB49_6
	movq	%rbx, %rax
Ltmp945:
Ltmp946:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB49_6:
	callq	___stack_chk_fail
Ltmp947:
Lfunc_end49:
Leh_func_end49:

	.globl	_atomic_sub_long_nv
	.align	4, 0x90
_atomic_sub_long_nv:
Leh_func_begin50:
Lfunc_begin50:
Ltmp951:
	pushq	%rbp
Ltmp948:
	movq	%rsp, %rbp
Ltmp949:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp950:
	movq	%rsi, %rbx
Ltmp952:
	movq	%rdi, %r14
Ltmp953:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp954:
Ltmp955:
Ltmp956:
	je	LBB50_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp957:
Ltmp958:
	movslq	%eax, %rax
Ltmp959:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$260, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp960:
LBB50_2:
Ltmp961:
	subq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp962:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp963:
	je	LBB50_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp964:
Ltmp965:
	movslq	%eax, %rax
Ltmp966:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$260, %edx
	movq	%r14, %rdi
	callq	___assert
LBB50_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB50_6
	movq	%rbx, %rax
Ltmp967:
Ltmp968:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB50_6:
	callq	___stack_chk_fail
Ltmp969:
Lfunc_end50:
Leh_func_end50:

	.globl	_atomic_sub_int_nv
	.align	4, 0x90
_atomic_sub_int_nv:
Leh_func_begin51:
Lfunc_begin51:
Ltmp973:
	pushq	%rbp
Ltmp970:
	movq	%rsp, %rbp
Ltmp971:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp972:
	movl	%esi, %ebx
Ltmp974:
	movq	%rdi, %r14
Ltmp975:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp976:
Ltmp977:
Ltmp978:
	je	LBB51_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp979:
Ltmp980:
	movslq	%eax, %rax
Ltmp981:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$259, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp982:
LBB51_2:
Ltmp983:
	subl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp984:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp985:
	je	LBB51_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp986:
Ltmp987:
	movslq	%eax, %rax
Ltmp988:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$259, %edx
	movq	%r14, %rdi
	callq	___assert
LBB51_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB51_6
	movl	%ebx, %eax
Ltmp989:
Ltmp990:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB51_6:
	callq	___stack_chk_fail
Ltmp991:
Lfunc_end51:
Leh_func_end51:

	.globl	_atomic_sub_32_nv
	.align	4, 0x90
_atomic_sub_32_nv:
Leh_func_begin52:
Lfunc_begin52:
Ltmp995:
	pushq	%rbp
Ltmp992:
	movq	%rsp, %rbp
Ltmp993:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp994:
	movl	%esi, %ebx
Ltmp996:
	movq	%rdi, %r14
Ltmp997:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp998:
Ltmp999:
Ltmp1000:
	je	LBB52_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1001:
Ltmp1002:
	movslq	%eax, %rax
Ltmp1003:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$258, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1004:
LBB52_2:
Ltmp1005:
	subl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp1006:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1007:
	je	LBB52_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1008:
Ltmp1009:
	movslq	%eax, %rax
Ltmp1010:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$258, %edx
	movq	%r14, %rdi
	callq	___assert
LBB52_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB52_6
	movl	%ebx, %eax
Ltmp1011:
Ltmp1012:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB52_6:
	callq	___stack_chk_fail
Ltmp1013:
Lfunc_end52:
Leh_func_end52:

	.globl	_atomic_sub_short_nv
	.align	4, 0x90
_atomic_sub_short_nv:
Leh_func_begin53:
Lfunc_begin53:
Ltmp1017:
	pushq	%rbp
Ltmp1014:
	movq	%rsp, %rbp
Ltmp1015:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1016:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1018:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1019:
Ltmp1020:
	je	LBB53_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1021:
Ltmp1022:
	movslq	%eax, %rax
Ltmp1023:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$257, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1024:
LBB53_2:
Ltmp1025:
	subw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp1026:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1027:
	je	LBB53_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1028:
Ltmp1029:
	movslq	%eax, %rax
Ltmp1030:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$257, %edx
	movq	%r14, %rdi
	callq	___assert
LBB53_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB53_6
Ltmp1031:
Ltmp1032:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB53_6:
	callq	___stack_chk_fail
Ltmp1033:
Lfunc_end53:
Leh_func_end53:

	.globl	_atomic_sub_16_nv
	.align	4, 0x90
_atomic_sub_16_nv:
Leh_func_begin54:
Lfunc_begin54:
Ltmp1037:
	pushq	%rbp
Ltmp1034:
	movq	%rsp, %rbp
Ltmp1035:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1036:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1038:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1039:
Ltmp1040:
	je	LBB54_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1041:
Ltmp1042:
	movslq	%eax, %rax
Ltmp1043:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$256, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1044:
LBB54_2:
Ltmp1045:
	subw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp1046:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1047:
	je	LBB54_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1048:
Ltmp1049:
	movslq	%eax, %rax
Ltmp1050:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$256, %edx
	movq	%r14, %rdi
	callq	___assert
LBB54_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB54_6
Ltmp1051:
Ltmp1052:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB54_6:
	callq	___stack_chk_fail
Ltmp1053:
Lfunc_end54:
Leh_func_end54:

	.globl	_atomic_sub_char_nv
	.align	4, 0x90
_atomic_sub_char_nv:
Leh_func_begin55:
Lfunc_begin55:
Ltmp1057:
	pushq	%rbp
Ltmp1054:
	movq	%rsp, %rbp
Ltmp1055:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1056:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1058:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1059:
Ltmp1060:
	je	LBB55_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1061:
Ltmp1062:
	movslq	%eax, %rax
Ltmp1063:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$255, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1064:
LBB55_2:
Ltmp1065:
	subb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp1066:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1067:
	je	LBB55_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1068:
Ltmp1069:
	movslq	%eax, %rax
Ltmp1070:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$255, %edx
	movq	%r14, %rdi
	callq	___assert
LBB55_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB55_6
Ltmp1071:
Ltmp1072:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB55_6:
	callq	___stack_chk_fail
Ltmp1073:
Lfunc_end55:
Leh_func_end55:

	.globl	_atomic_sub_8_nv
	.align	4, 0x90
_atomic_sub_8_nv:
Leh_func_begin56:
Lfunc_begin56:
Ltmp1077:
	pushq	%rbp
Ltmp1074:
	movq	%rsp, %rbp
Ltmp1075:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1076:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1078:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1079:
Ltmp1080:
	je	LBB56_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1081:
Ltmp1082:
	movslq	%eax, %rax
Ltmp1083:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$254, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1084:
LBB56_2:
Ltmp1085:
	subb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp1086:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1087:
	je	LBB56_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1088:
Ltmp1089:
	movslq	%eax, %rax
Ltmp1090:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$254, %edx
	movq	%r14, %rdi
	callq	___assert
LBB56_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB56_6
Ltmp1091:
Ltmp1092:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB56_6:
	callq	___stack_chk_fail
Ltmp1093:
Lfunc_end56:
Leh_func_end56:

	.globl	_atomic_add_ptr_nv
	.align	4, 0x90
_atomic_add_ptr_nv:
Leh_func_begin57:
Lfunc_begin57:
Ltmp1097:
	pushq	%rbp
Ltmp1094:
	movq	%rsp, %rbp
Ltmp1095:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1096:
	movq	%rsi, %rbx
Ltmp1098:
	movq	%rdi, %r14
Ltmp1099:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp1100:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1101:
Ltmp1102:
Ltmp1103:
	je	LBB57_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1104:
Ltmp1105:
	movslq	%eax, %rax
Ltmp1106:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$236, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1107:
LBB57_2:
Ltmp1108:
	addq	(%r14), %rbx
	movq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp1109:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1110:
	je	LBB57_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1111:
Ltmp1112:
	movslq	%eax, %rax
Ltmp1113:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$238, %edx
	movq	%r14, %rdi
	callq	___assert
LBB57_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB57_6
	movq	%rbx, %rax
Ltmp1114:
Ltmp1115:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB57_6:
	callq	___stack_chk_fail
Ltmp1116:
Lfunc_end57:
Leh_func_end57:

	.globl	_atomic_add_64_nv
	.align	4, 0x90
_atomic_add_64_nv:
Leh_func_begin58:
Lfunc_begin58:
Ltmp1120:
	pushq	%rbp
Ltmp1117:
	movq	%rsp, %rbp
Ltmp1118:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1119:
	movq	%rsi, %rbx
Ltmp1121:
	movq	%rdi, %r14
Ltmp1122:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1123:
Ltmp1124:
Ltmp1125:
	je	LBB58_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1126:
Ltmp1127:
	movslq	%eax, %rax
Ltmp1128:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$230, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1129:
LBB58_2:
Ltmp1130:
	addq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp1131:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1132:
	je	LBB58_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1133:
Ltmp1134:
	movslq	%eax, %rax
Ltmp1135:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$230, %edx
	movq	%r14, %rdi
	callq	___assert
LBB58_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB58_6
	movq	%rbx, %rax
Ltmp1136:
Ltmp1137:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB58_6:
	callq	___stack_chk_fail
Ltmp1138:
Lfunc_end58:
Leh_func_end58:

	.globl	_atomic_add_long_nv
	.align	4, 0x90
_atomic_add_long_nv:
Leh_func_begin59:
Lfunc_begin59:
Ltmp1142:
	pushq	%rbp
Ltmp1139:
	movq	%rsp, %rbp
Ltmp1140:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1141:
	movq	%rsi, %rbx
Ltmp1143:
	movq	%rdi, %r14
Ltmp1144:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1145:
Ltmp1146:
Ltmp1147:
	je	LBB59_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1148:
Ltmp1149:
	movslq	%eax, %rax
Ltmp1150:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$229, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1151:
LBB59_2:
Ltmp1152:
	addq	%rbx, (%r14)
	movq	(%r14), %rbx
Ltmp1153:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1154:
	je	LBB59_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1155:
Ltmp1156:
	movslq	%eax, %rax
Ltmp1157:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$229, %edx
	movq	%r14, %rdi
	callq	___assert
LBB59_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB59_6
	movq	%rbx, %rax
Ltmp1158:
Ltmp1159:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB59_6:
	callq	___stack_chk_fail
Ltmp1160:
Lfunc_end59:
Leh_func_end59:

	.globl	_atomic_add_int_nv
	.align	4, 0x90
_atomic_add_int_nv:
Leh_func_begin60:
Lfunc_begin60:
Ltmp1164:
	pushq	%rbp
Ltmp1161:
	movq	%rsp, %rbp
Ltmp1162:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1163:
	movl	%esi, %ebx
Ltmp1165:
	movq	%rdi, %r14
Ltmp1166:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1167:
Ltmp1168:
Ltmp1169:
	je	LBB60_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1170:
Ltmp1171:
	movslq	%eax, %rax
Ltmp1172:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$228, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1173:
LBB60_2:
Ltmp1174:
	addl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp1175:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1176:
	je	LBB60_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1177:
Ltmp1178:
	movslq	%eax, %rax
Ltmp1179:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$228, %edx
	movq	%r14, %rdi
	callq	___assert
LBB60_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB60_6
	movl	%ebx, %eax
Ltmp1180:
Ltmp1181:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB60_6:
	callq	___stack_chk_fail
Ltmp1182:
Lfunc_end60:
Leh_func_end60:

	.globl	_atomic_add_32_nv
	.align	4, 0x90
_atomic_add_32_nv:
Leh_func_begin61:
Lfunc_begin61:
Ltmp1186:
	pushq	%rbp
Ltmp1183:
	movq	%rsp, %rbp
Ltmp1184:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1185:
	movl	%esi, %ebx
Ltmp1187:
	movq	%rdi, %r14
Ltmp1188:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1189:
Ltmp1190:
Ltmp1191:
	je	LBB61_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1192:
Ltmp1193:
	movslq	%eax, %rax
Ltmp1194:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$227, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1195:
LBB61_2:
Ltmp1196:
	addl	%ebx, (%r14)
	movl	(%r14), %ebx
Ltmp1197:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1198:
	je	LBB61_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1199:
Ltmp1200:
	movslq	%eax, %rax
Ltmp1201:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$227, %edx
	movq	%r14, %rdi
	callq	___assert
LBB61_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB61_6
	movl	%ebx, %eax
Ltmp1202:
Ltmp1203:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB61_6:
	callq	___stack_chk_fail
Ltmp1204:
Lfunc_end61:
Leh_func_end61:

	.globl	_atomic_add_short_nv
	.align	4, 0x90
_atomic_add_short_nv:
Leh_func_begin62:
Lfunc_begin62:
Ltmp1208:
	pushq	%rbp
Ltmp1205:
	movq	%rsp, %rbp
Ltmp1206:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1207:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1209:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1210:
Ltmp1211:
	je	LBB62_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1212:
Ltmp1213:
	movslq	%eax, %rax
Ltmp1214:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$226, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1215:
LBB62_2:
Ltmp1216:
	addw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp1217:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1218:
	je	LBB62_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1219:
Ltmp1220:
	movslq	%eax, %rax
Ltmp1221:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$226, %edx
	movq	%r14, %rdi
	callq	___assert
LBB62_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB62_6
Ltmp1222:
Ltmp1223:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB62_6:
	callq	___stack_chk_fail
Ltmp1224:
Lfunc_end62:
Leh_func_end62:

	.globl	_atomic_add_16_nv
	.align	4, 0x90
_atomic_add_16_nv:
Leh_func_begin63:
Lfunc_begin63:
Ltmp1228:
	pushq	%rbp
Ltmp1225:
	movq	%rsp, %rbp
Ltmp1226:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1227:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1229:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1230:
Ltmp1231:
	je	LBB63_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1232:
Ltmp1233:
	movslq	%eax, %rax
Ltmp1234:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$225, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1235:
LBB63_2:
Ltmp1236:
	addw	%bx, (%r14)
	movw	(%r14), %bx
Ltmp1237:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1238:
	je	LBB63_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1239:
Ltmp1240:
	movslq	%eax, %rax
Ltmp1241:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$225, %edx
	movq	%r14, %rdi
	callq	___assert
LBB63_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB63_6
Ltmp1242:
Ltmp1243:
	movzwl	%bx, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB63_6:
	callq	___stack_chk_fail
Ltmp1244:
Lfunc_end63:
Leh_func_end63:

	.globl	_atomic_add_char_nv
	.align	4, 0x90
_atomic_add_char_nv:
Leh_func_begin64:
Lfunc_begin64:
Ltmp1248:
	pushq	%rbp
Ltmp1245:
	movq	%rsp, %rbp
Ltmp1246:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1247:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1249:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1250:
Ltmp1251:
	je	LBB64_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1252:
Ltmp1253:
	movslq	%eax, %rax
Ltmp1254:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$224, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1255:
LBB64_2:
Ltmp1256:
	addb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp1257:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1258:
	je	LBB64_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1259:
Ltmp1260:
	movslq	%eax, %rax
Ltmp1261:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$224, %edx
	movq	%r14, %rdi
	callq	___assert
LBB64_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB64_6
Ltmp1262:
Ltmp1263:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB64_6:
	callq	___stack_chk_fail
Ltmp1264:
Lfunc_end64:
Leh_func_end64:

	.globl	_atomic_add_8_nv
	.align	4, 0x90
_atomic_add_8_nv:
Leh_func_begin65:
Lfunc_begin65:
Ltmp1268:
	pushq	%rbp
Ltmp1265:
	movq	%rsp, %rbp
Ltmp1266:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1267:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1269:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1270:
Ltmp1271:
	je	LBB65_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1272:
Ltmp1273:
	movslq	%eax, %rax
Ltmp1274:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$223, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1275:
LBB65_2:
Ltmp1276:
	addb	%bl, (%r14)
	movb	(%r14), %bl
Ltmp1277:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1278:
	je	LBB65_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1279:
Ltmp1280:
	movslq	%eax, %rax
Ltmp1281:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$223, %edx
	movq	%r14, %rdi
	callq	___assert
LBB65_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB65_6
Ltmp1282:
Ltmp1283:
	movzbl	%bl, %eax
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB65_6:
	callq	___stack_chk_fail
Ltmp1284:
Lfunc_end65:
Leh_func_end65:

	.globl	_atomic_dec_64_nv
	.align	4, 0x90
_atomic_dec_64_nv:
Leh_func_begin66:
Lfunc_begin66:
Ltmp1288:
	pushq	%rbp
Ltmp1285:
	movq	%rsp, %rbp
Ltmp1286:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1287:
	movq	%rdi, %rbx
Ltmp1289:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1290:
Ltmp1291:
	je	LBB66_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1292:
Ltmp1293:
	movslq	%eax, %rax
Ltmp1294:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$210, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1295:
LBB66_2:
Ltmp1296:
	decq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1297:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1298:
	je	LBB66_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1299:
Ltmp1300:
	movslq	%eax, %rax
Ltmp1301:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$210, %edx
	movq	%r14, %rdi
	callq	___assert
LBB66_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB66_6
	movq	%rbx, %rax
Ltmp1302:
Ltmp1303:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB66_6:
	callq	___stack_chk_fail
Ltmp1304:
Lfunc_end66:
Leh_func_end66:

	.globl	_atomic_dec_ulong_nv
	.align	4, 0x90
_atomic_dec_ulong_nv:
Leh_func_begin67:
Lfunc_begin67:
Ltmp1308:
	pushq	%rbp
Ltmp1305:
	movq	%rsp, %rbp
Ltmp1306:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1307:
	movq	%rdi, %rbx
Ltmp1309:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1310:
Ltmp1311:
	je	LBB67_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1312:
Ltmp1313:
	movslq	%eax, %rax
Ltmp1314:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$209, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1315:
LBB67_2:
Ltmp1316:
	decq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1317:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1318:
	je	LBB67_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1319:
Ltmp1320:
	movslq	%eax, %rax
Ltmp1321:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$209, %edx
	movq	%r14, %rdi
	callq	___assert
LBB67_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB67_6
	movq	%rbx, %rax
Ltmp1322:
Ltmp1323:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB67_6:
	callq	___stack_chk_fail
Ltmp1324:
Lfunc_end67:
Leh_func_end67:

	.globl	_atomic_dec_uint_nv
	.align	4, 0x90
_atomic_dec_uint_nv:
Leh_func_begin68:
Lfunc_begin68:
Ltmp1328:
	pushq	%rbp
Ltmp1325:
	movq	%rsp, %rbp
Ltmp1326:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1327:
	movq	%rdi, %rbx
Ltmp1329:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1330:
Ltmp1331:
	je	LBB68_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1332:
Ltmp1333:
	movslq	%eax, %rax
Ltmp1334:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$208, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1335:
LBB68_2:
Ltmp1336:
	decl	(%rbx)
	movl	(%rbx), %ebx
Ltmp1337:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1338:
	je	LBB68_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1339:
Ltmp1340:
	movslq	%eax, %rax
Ltmp1341:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$208, %edx
	movq	%r14, %rdi
	callq	___assert
LBB68_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB68_6
	movl	%ebx, %eax
Ltmp1342:
Ltmp1343:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB68_6:
	callq	___stack_chk_fail
Ltmp1344:
Lfunc_end68:
Leh_func_end68:

	.globl	_atomic_dec_32_nv
	.align	4, 0x90
_atomic_dec_32_nv:
Leh_func_begin69:
Lfunc_begin69:
Ltmp1348:
	pushq	%rbp
Ltmp1345:
	movq	%rsp, %rbp
Ltmp1346:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1347:
	movq	%rdi, %rbx
Ltmp1349:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1350:
Ltmp1351:
	je	LBB69_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1352:
Ltmp1353:
	movslq	%eax, %rax
Ltmp1354:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$207, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1355:
LBB69_2:
Ltmp1356:
	decl	(%rbx)
	movl	(%rbx), %ebx
Ltmp1357:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1358:
	je	LBB69_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1359:
Ltmp1360:
	movslq	%eax, %rax
Ltmp1361:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$207, %edx
	movq	%r14, %rdi
	callq	___assert
LBB69_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB69_6
	movl	%ebx, %eax
Ltmp1362:
Ltmp1363:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB69_6:
	callq	___stack_chk_fail
Ltmp1364:
Lfunc_end69:
Leh_func_end69:

	.globl	_atomic_dec_ushort_nv
	.align	4, 0x90
_atomic_dec_ushort_nv:
Leh_func_begin70:
Lfunc_begin70:
Ltmp1368:
	pushq	%rbp
Ltmp1365:
	movq	%rsp, %rbp
Ltmp1366:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1367:
	movq	%rdi, %rbx
Ltmp1369:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1370:
Ltmp1371:
	je	LBB70_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1372:
Ltmp1373:
	movslq	%eax, %rax
Ltmp1374:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$206, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1375:
LBB70_2:
Ltmp1376:
	decw	(%rbx)
	movw	(%rbx), %bx
Ltmp1377:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1378:
	je	LBB70_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1379:
Ltmp1380:
	movslq	%eax, %rax
Ltmp1381:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$206, %edx
	movq	%r14, %rdi
	callq	___assert
LBB70_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB70_6
Ltmp1382:
Ltmp1383:
	movzwl	%bx, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB70_6:
	callq	___stack_chk_fail
Ltmp1384:
Lfunc_end70:
Leh_func_end70:

	.globl	_atomic_dec_16_nv
	.align	4, 0x90
_atomic_dec_16_nv:
Leh_func_begin71:
Lfunc_begin71:
Ltmp1388:
	pushq	%rbp
Ltmp1385:
	movq	%rsp, %rbp
Ltmp1386:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1387:
	movq	%rdi, %rbx
Ltmp1389:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1390:
Ltmp1391:
	je	LBB71_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1392:
Ltmp1393:
	movslq	%eax, %rax
Ltmp1394:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$205, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1395:
LBB71_2:
Ltmp1396:
	decw	(%rbx)
	movw	(%rbx), %bx
Ltmp1397:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1398:
	je	LBB71_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1399:
Ltmp1400:
	movslq	%eax, %rax
Ltmp1401:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$205, %edx
	movq	%r14, %rdi
	callq	___assert
LBB71_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB71_6
Ltmp1402:
Ltmp1403:
	movzwl	%bx, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB71_6:
	callq	___stack_chk_fail
Ltmp1404:
Lfunc_end71:
Leh_func_end71:

	.globl	_atomic_dec_uchar_nv
	.align	4, 0x90
_atomic_dec_uchar_nv:
Leh_func_begin72:
Lfunc_begin72:
Ltmp1408:
	pushq	%rbp
Ltmp1405:
	movq	%rsp, %rbp
Ltmp1406:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1407:
	movq	%rdi, %rbx
Ltmp1409:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1410:
Ltmp1411:
	je	LBB72_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1412:
Ltmp1413:
	movslq	%eax, %rax
Ltmp1414:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$204, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1415:
LBB72_2:
Ltmp1416:
	decb	(%rbx)
	movb	(%rbx), %bl
Ltmp1417:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1418:
	je	LBB72_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1419:
Ltmp1420:
	movslq	%eax, %rax
Ltmp1421:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$204, %edx
	movq	%r14, %rdi
	callq	___assert
LBB72_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB72_6
Ltmp1422:
Ltmp1423:
	movzbl	%bl, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB72_6:
	callq	___stack_chk_fail
Ltmp1424:
Lfunc_end72:
Leh_func_end72:

	.globl	_atomic_dec_8_nv
	.align	4, 0x90
_atomic_dec_8_nv:
Leh_func_begin73:
Lfunc_begin73:
Ltmp1428:
	pushq	%rbp
Ltmp1425:
	movq	%rsp, %rbp
Ltmp1426:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1427:
	movq	%rdi, %rbx
Ltmp1429:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1430:
Ltmp1431:
	je	LBB73_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1432:
Ltmp1433:
	movslq	%eax, %rax
Ltmp1434:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$203, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1435:
LBB73_2:
Ltmp1436:
	decb	(%rbx)
	movb	(%rbx), %bl
Ltmp1437:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1438:
	je	LBB73_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1439:
Ltmp1440:
	movslq	%eax, %rax
Ltmp1441:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$203, %edx
	movq	%r14, %rdi
	callq	___assert
LBB73_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB73_6
Ltmp1442:
Ltmp1443:
	movzbl	%bl, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB73_6:
	callq	___stack_chk_fail
Ltmp1444:
Lfunc_end73:
Leh_func_end73:

	.globl	_atomic_dec_long_nv
	.align	4, 0x90
_atomic_dec_long_nv:
Leh_func_begin74:
Lfunc_begin74:
Ltmp1448:
	pushq	%rbp
Ltmp1445:
	movq	%rsp, %rbp
Ltmp1446:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1447:
	movq	%rdi, %rbx
Ltmp1449:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1450:
Ltmp1451:
	je	LBB74_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1452:
Ltmp1453:
	movslq	%eax, %rax
Ltmp1454:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$202, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1455:
LBB74_2:
Ltmp1456:
	decq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1457:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1458:
	je	LBB74_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1459:
Ltmp1460:
	movslq	%eax, %rax
Ltmp1461:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$202, %edx
	movq	%r14, %rdi
	callq	___assert
LBB74_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB74_6
	movq	%rbx, %rax
Ltmp1462:
Ltmp1463:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB74_6:
	callq	___stack_chk_fail
Ltmp1464:
Lfunc_end74:
Leh_func_end74:

	.globl	_atomic_inc_64_nv
	.align	4, 0x90
_atomic_inc_64_nv:
Leh_func_begin75:
Lfunc_begin75:
Ltmp1468:
	pushq	%rbp
Ltmp1465:
	movq	%rsp, %rbp
Ltmp1466:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1467:
	movq	%rdi, %rbx
Ltmp1469:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1470:
Ltmp1471:
	je	LBB75_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1472:
Ltmp1473:
	movslq	%eax, %rax
Ltmp1474:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$189, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1475:
LBB75_2:
Ltmp1476:
	incq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1477:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1478:
	je	LBB75_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1479:
Ltmp1480:
	movslq	%eax, %rax
Ltmp1481:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$189, %edx
	movq	%r14, %rdi
	callq	___assert
LBB75_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB75_6
	movq	%rbx, %rax
Ltmp1482:
Ltmp1483:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB75_6:
	callq	___stack_chk_fail
Ltmp1484:
Lfunc_end75:
Leh_func_end75:

	.globl	_atomic_inc_ulong_nv
	.align	4, 0x90
_atomic_inc_ulong_nv:
Leh_func_begin76:
Lfunc_begin76:
Ltmp1488:
	pushq	%rbp
Ltmp1485:
	movq	%rsp, %rbp
Ltmp1486:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1487:
	movq	%rdi, %rbx
Ltmp1489:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1490:
Ltmp1491:
	je	LBB76_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1492:
Ltmp1493:
	movslq	%eax, %rax
Ltmp1494:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$188, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1495:
LBB76_2:
Ltmp1496:
	incq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1497:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1498:
	je	LBB76_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1499:
Ltmp1500:
	movslq	%eax, %rax
Ltmp1501:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$188, %edx
	movq	%r14, %rdi
	callq	___assert
LBB76_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB76_6
	movq	%rbx, %rax
Ltmp1502:
Ltmp1503:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB76_6:
	callq	___stack_chk_fail
Ltmp1504:
Lfunc_end76:
Leh_func_end76:

	.globl	_atomic_inc_uint_nv
	.align	4, 0x90
_atomic_inc_uint_nv:
Leh_func_begin77:
Lfunc_begin77:
Ltmp1508:
	pushq	%rbp
Ltmp1505:
	movq	%rsp, %rbp
Ltmp1506:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1507:
	movq	%rdi, %rbx
Ltmp1509:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1510:
Ltmp1511:
	je	LBB77_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1512:
Ltmp1513:
	movslq	%eax, %rax
Ltmp1514:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$187, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1515:
LBB77_2:
Ltmp1516:
	incl	(%rbx)
	movl	(%rbx), %ebx
Ltmp1517:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1518:
	je	LBB77_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1519:
Ltmp1520:
	movslq	%eax, %rax
Ltmp1521:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$187, %edx
	movq	%r14, %rdi
	callq	___assert
LBB77_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB77_6
	movl	%ebx, %eax
Ltmp1522:
Ltmp1523:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB77_6:
	callq	___stack_chk_fail
Ltmp1524:
Lfunc_end77:
Leh_func_end77:

	.globl	_atomic_inc_32_nv
	.align	4, 0x90
_atomic_inc_32_nv:
Leh_func_begin78:
Lfunc_begin78:
Ltmp1528:
	pushq	%rbp
Ltmp1525:
	movq	%rsp, %rbp
Ltmp1526:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1527:
	movq	%rdi, %rbx
Ltmp1529:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1530:
Ltmp1531:
	je	LBB78_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1532:
Ltmp1533:
	movslq	%eax, %rax
Ltmp1534:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$186, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1535:
LBB78_2:
Ltmp1536:
	incl	(%rbx)
	movl	(%rbx), %ebx
Ltmp1537:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1538:
	je	LBB78_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1539:
Ltmp1540:
	movslq	%eax, %rax
Ltmp1541:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$186, %edx
	movq	%r14, %rdi
	callq	___assert
LBB78_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB78_6
	movl	%ebx, %eax
Ltmp1542:
Ltmp1543:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB78_6:
	callq	___stack_chk_fail
Ltmp1544:
Lfunc_end78:
Leh_func_end78:

	.globl	_atomic_inc_ushort_nv
	.align	4, 0x90
_atomic_inc_ushort_nv:
Leh_func_begin79:
Lfunc_begin79:
Ltmp1548:
	pushq	%rbp
Ltmp1545:
	movq	%rsp, %rbp
Ltmp1546:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1547:
	movq	%rdi, %rbx
Ltmp1549:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1550:
Ltmp1551:
	je	LBB79_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1552:
Ltmp1553:
	movslq	%eax, %rax
Ltmp1554:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$185, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1555:
LBB79_2:
Ltmp1556:
	incw	(%rbx)
	movw	(%rbx), %bx
Ltmp1557:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1558:
	je	LBB79_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1559:
Ltmp1560:
	movslq	%eax, %rax
Ltmp1561:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$185, %edx
	movq	%r14, %rdi
	callq	___assert
LBB79_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB79_6
Ltmp1562:
Ltmp1563:
	movzwl	%bx, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB79_6:
	callq	___stack_chk_fail
Ltmp1564:
Lfunc_end79:
Leh_func_end79:

	.globl	_atomic_inc_16_nv
	.align	4, 0x90
_atomic_inc_16_nv:
Leh_func_begin80:
Lfunc_begin80:
Ltmp1568:
	pushq	%rbp
Ltmp1565:
	movq	%rsp, %rbp
Ltmp1566:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1567:
	movq	%rdi, %rbx
Ltmp1569:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1570:
Ltmp1571:
	je	LBB80_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1572:
Ltmp1573:
	movslq	%eax, %rax
Ltmp1574:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$184, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1575:
LBB80_2:
Ltmp1576:
	incw	(%rbx)
	movw	(%rbx), %bx
Ltmp1577:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1578:
	je	LBB80_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1579:
Ltmp1580:
	movslq	%eax, %rax
Ltmp1581:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$184, %edx
	movq	%r14, %rdi
	callq	___assert
LBB80_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB80_6
Ltmp1582:
Ltmp1583:
	movzwl	%bx, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB80_6:
	callq	___stack_chk_fail
Ltmp1584:
Lfunc_end80:
Leh_func_end80:

	.globl	_atomic_inc_uchar_nv
	.align	4, 0x90
_atomic_inc_uchar_nv:
Leh_func_begin81:
Lfunc_begin81:
Ltmp1588:
	pushq	%rbp
Ltmp1585:
	movq	%rsp, %rbp
Ltmp1586:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1587:
	movq	%rdi, %rbx
Ltmp1589:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1590:
Ltmp1591:
	je	LBB81_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1592:
Ltmp1593:
	movslq	%eax, %rax
Ltmp1594:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$183, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1595:
LBB81_2:
Ltmp1596:
	incb	(%rbx)
	movb	(%rbx), %bl
Ltmp1597:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1598:
	je	LBB81_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1599:
Ltmp1600:
	movslq	%eax, %rax
Ltmp1601:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$183, %edx
	movq	%r14, %rdi
	callq	___assert
LBB81_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB81_6
Ltmp1602:
Ltmp1603:
	movzbl	%bl, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB81_6:
	callq	___stack_chk_fail
Ltmp1604:
Lfunc_end81:
Leh_func_end81:

	.globl	_atomic_inc_8_nv
	.align	4, 0x90
_atomic_inc_8_nv:
Leh_func_begin82:
Lfunc_begin82:
Ltmp1608:
	pushq	%rbp
Ltmp1605:
	movq	%rsp, %rbp
Ltmp1606:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1607:
	movq	%rdi, %rbx
Ltmp1609:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1610:
Ltmp1611:
	je	LBB82_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1612:
Ltmp1613:
	movslq	%eax, %rax
Ltmp1614:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$182, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1615:
LBB82_2:
Ltmp1616:
	incb	(%rbx)
	movb	(%rbx), %bl
Ltmp1617:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1618:
	je	LBB82_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1619:
Ltmp1620:
	movslq	%eax, %rax
Ltmp1621:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$182, %edx
	movq	%r14, %rdi
	callq	___assert
LBB82_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB82_6
Ltmp1622:
Ltmp1623:
	movzbl	%bl, %eax
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB82_6:
	callq	___stack_chk_fail
Ltmp1624:
Lfunc_end82:
Leh_func_end82:

	.globl	_atomic_inc_long_nv
	.align	4, 0x90
_atomic_inc_long_nv:
Leh_func_begin83:
Lfunc_begin83:
Ltmp1628:
	pushq	%rbp
Ltmp1625:
	movq	%rsp, %rbp
Ltmp1626:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp1627:
	movq	%rdi, %rbx
Ltmp1629:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1630:
Ltmp1631:
	je	LBB83_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1632:
Ltmp1633:
	movslq	%eax, %rax
Ltmp1634:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$181, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp1635:
LBB83_2:
Ltmp1636:
	incq	(%rbx)
	movq	(%rbx), %rbx
Ltmp1637:
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1638:
	je	LBB83_4
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1639:
Ltmp1640:
	movslq	%eax, %rax
Ltmp1641:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$181, %edx
	movq	%r14, %rdi
	callq	___assert
LBB83_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB83_6
	movq	%rbx, %rax
Ltmp1642:
Ltmp1643:
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB83_6:
	callq	___stack_chk_fail
Ltmp1644:
Lfunc_end83:
Leh_func_end83:

	.globl	_atomic_and_64
	.align	4, 0x90
_atomic_and_64:
Leh_func_begin84:
Lfunc_begin84:
Ltmp1648:
	pushq	%rbp
Ltmp1645:
	movq	%rsp, %rbp
Ltmp1646:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1647:
	movq	%rsi, %rbx
Ltmp1649:
	movq	%rdi, %r14
Ltmp1650:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1651:
Ltmp1652:
Ltmp1653:
	je	LBB84_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1654:
Ltmp1655:
	movslq	%eax, %rax
Ltmp1656:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$164, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1657:
LBB84_2:
Ltmp1658:
	andq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1659:
	je	LBB84_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1660:
Ltmp1661:
	movslq	%eax, %rax
Ltmp1662:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$164, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB84_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB84_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB84_6:
	callq	___stack_chk_fail
Ltmp1663:
Lfunc_end84:
Leh_func_end84:

	.globl	_atomic_and_ulong
	.align	4, 0x90
_atomic_and_ulong:
Leh_func_begin85:
Lfunc_begin85:
Ltmp1667:
	pushq	%rbp
Ltmp1664:
	movq	%rsp, %rbp
Ltmp1665:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1666:
	movq	%rsi, %rbx
Ltmp1668:
	movq	%rdi, %r14
Ltmp1669:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1670:
Ltmp1671:
Ltmp1672:
	je	LBB85_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1673:
Ltmp1674:
	movslq	%eax, %rax
Ltmp1675:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$163, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1676:
LBB85_2:
Ltmp1677:
	andq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1678:
	je	LBB85_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1679:
Ltmp1680:
	movslq	%eax, %rax
Ltmp1681:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$163, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB85_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB85_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB85_6:
	callq	___stack_chk_fail
Ltmp1682:
Lfunc_end85:
Leh_func_end85:

	.globl	_atomic_and_long
	.align	4, 0x90
_atomic_and_long:
Leh_func_begin86:
Lfunc_begin86:
Ltmp1685:
	pushq	%rbp
Ltmp1683:
	movq	%rsp, %rbp
Ltmp1684:
Ltmp1686:
Ltmp1687:
Ltmp1688:
Ltmp1689:
Ltmp1690:
	popq	%rbp
	jmp	_atomic_and_ulong  # TAILCALL
Ltmp1691:
Lfunc_end86:
Leh_func_end86:

	.globl	_atomic_and_uint
	.align	4, 0x90
_atomic_and_uint:
Leh_func_begin87:
Lfunc_begin87:
Ltmp1695:
	pushq	%rbp
Ltmp1692:
	movq	%rsp, %rbp
Ltmp1693:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1694:
	movl	%esi, %ebx
Ltmp1696:
	movq	%rdi, %r14
Ltmp1697:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1698:
Ltmp1699:
Ltmp1700:
	je	LBB87_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1701:
Ltmp1702:
	movslq	%eax, %rax
Ltmp1703:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$162, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1704:
LBB87_2:
Ltmp1705:
	andl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1706:
	je	LBB87_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1707:
Ltmp1708:
	movslq	%eax, %rax
Ltmp1709:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$162, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB87_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB87_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB87_6:
	callq	___stack_chk_fail
Ltmp1710:
Lfunc_end87:
Leh_func_end87:

	.globl	_atomic_and_32
	.align	4, 0x90
_atomic_and_32:
Leh_func_begin88:
Lfunc_begin88:
Ltmp1714:
	pushq	%rbp
Ltmp1711:
	movq	%rsp, %rbp
Ltmp1712:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1713:
	movl	%esi, %ebx
Ltmp1715:
	movq	%rdi, %r14
Ltmp1716:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1717:
Ltmp1718:
Ltmp1719:
	je	LBB88_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1720:
Ltmp1721:
	movslq	%eax, %rax
Ltmp1722:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$161, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1723:
LBB88_2:
Ltmp1724:
	andl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1725:
	je	LBB88_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1726:
Ltmp1727:
	movslq	%eax, %rax
Ltmp1728:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$161, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB88_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB88_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB88_6:
	callq	___stack_chk_fail
Ltmp1729:
Lfunc_end88:
Leh_func_end88:

	.globl	_atomic_and_ushort
	.align	4, 0x90
_atomic_and_ushort:
Leh_func_begin89:
Lfunc_begin89:
Ltmp1733:
	pushq	%rbp
Ltmp1730:
	movq	%rsp, %rbp
Ltmp1731:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1732:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1734:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1735:
Ltmp1736:
	je	LBB89_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1737:
Ltmp1738:
	movslq	%eax, %rax
Ltmp1739:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$160, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1740:
LBB89_2:
Ltmp1741:
	andw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1742:
	je	LBB89_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1743:
Ltmp1744:
	movslq	%eax, %rax
Ltmp1745:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$160, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB89_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB89_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB89_6:
	callq	___stack_chk_fail
Ltmp1746:
Lfunc_end89:
Leh_func_end89:

	.globl	_atomic_and_16
	.align	4, 0x90
_atomic_and_16:
Leh_func_begin90:
Lfunc_begin90:
Ltmp1750:
	pushq	%rbp
Ltmp1747:
	movq	%rsp, %rbp
Ltmp1748:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1749:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1751:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1752:
Ltmp1753:
	je	LBB90_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1754:
Ltmp1755:
	movslq	%eax, %rax
Ltmp1756:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$159, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1757:
LBB90_2:
Ltmp1758:
	andw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1759:
	je	LBB90_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1760:
Ltmp1761:
	movslq	%eax, %rax
Ltmp1762:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$159, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB90_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB90_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB90_6:
	callq	___stack_chk_fail
Ltmp1763:
Lfunc_end90:
Leh_func_end90:

	.globl	_atomic_and_uchar
	.align	4, 0x90
_atomic_and_uchar:
Leh_func_begin91:
Lfunc_begin91:
Ltmp1767:
	pushq	%rbp
Ltmp1764:
	movq	%rsp, %rbp
Ltmp1765:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1766:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1768:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1769:
Ltmp1770:
	je	LBB91_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1771:
Ltmp1772:
	movslq	%eax, %rax
Ltmp1773:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$158, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1774:
LBB91_2:
Ltmp1775:
	andb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1776:
	je	LBB91_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1777:
Ltmp1778:
	movslq	%eax, %rax
Ltmp1779:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$158, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB91_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB91_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB91_6:
	callq	___stack_chk_fail
Ltmp1780:
Lfunc_end91:
Leh_func_end91:

	.globl	_atomic_and_8
	.align	4, 0x90
_atomic_and_8:
Leh_func_begin92:
Lfunc_begin92:
Ltmp1784:
	pushq	%rbp
Ltmp1781:
	movq	%rsp, %rbp
Ltmp1782:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1783:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1785:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1786:
Ltmp1787:
	je	LBB92_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1788:
Ltmp1789:
	movslq	%eax, %rax
Ltmp1790:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$157, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1791:
LBB92_2:
Ltmp1792:
	andb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1793:
	je	LBB92_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1794:
Ltmp1795:
	movslq	%eax, %rax
Ltmp1796:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$157, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB92_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB92_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB92_6:
	callq	___stack_chk_fail
Ltmp1797:
Lfunc_end92:
Leh_func_end92:

	.globl	_atomic_or_64
	.align	4, 0x90
_atomic_or_64:
Leh_func_begin93:
Lfunc_begin93:
Ltmp1801:
	pushq	%rbp
Ltmp1798:
	movq	%rsp, %rbp
Ltmp1799:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1800:
	movq	%rsi, %rbx
Ltmp1802:
	movq	%rdi, %r14
Ltmp1803:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1804:
Ltmp1805:
Ltmp1806:
	je	LBB93_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1807:
Ltmp1808:
	movslq	%eax, %rax
Ltmp1809:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$146, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1810:
LBB93_2:
Ltmp1811:
	orq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1812:
	je	LBB93_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1813:
Ltmp1814:
	movslq	%eax, %rax
Ltmp1815:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$146, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB93_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB93_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB93_6:
	callq	___stack_chk_fail
Ltmp1816:
Lfunc_end93:
Leh_func_end93:

	.globl	_atomic_or_ulong
	.align	4, 0x90
_atomic_or_ulong:
Leh_func_begin94:
Lfunc_begin94:
Ltmp1820:
	pushq	%rbp
Ltmp1817:
	movq	%rsp, %rbp
Ltmp1818:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1819:
	movq	%rsi, %rbx
Ltmp1821:
	movq	%rdi, %r14
Ltmp1822:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1823:
Ltmp1824:
Ltmp1825:
	je	LBB94_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1826:
Ltmp1827:
	movslq	%eax, %rax
Ltmp1828:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$145, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1829:
LBB94_2:
Ltmp1830:
	orq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1831:
	je	LBB94_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1832:
Ltmp1833:
	movslq	%eax, %rax
Ltmp1834:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$145, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB94_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB94_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB94_6:
	callq	___stack_chk_fail
Ltmp1835:
Lfunc_end94:
Leh_func_end94:

	.globl	_atomic_or_long
	.align	4, 0x90
_atomic_or_long:
Leh_func_begin95:
Lfunc_begin95:
Ltmp1838:
	pushq	%rbp
Ltmp1836:
	movq	%rsp, %rbp
Ltmp1837:
Ltmp1839:
Ltmp1840:
Ltmp1841:
Ltmp1842:
Ltmp1843:
	popq	%rbp
	jmp	_atomic_or_ulong  # TAILCALL
Ltmp1844:
Lfunc_end95:
Leh_func_end95:

	.globl	_atomic_or_uint
	.align	4, 0x90
_atomic_or_uint:
Leh_func_begin96:
Lfunc_begin96:
Ltmp1848:
	pushq	%rbp
Ltmp1845:
	movq	%rsp, %rbp
Ltmp1846:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1847:
	movl	%esi, %ebx
Ltmp1849:
	movq	%rdi, %r14
Ltmp1850:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1851:
Ltmp1852:
Ltmp1853:
	je	LBB96_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1854:
Ltmp1855:
	movslq	%eax, %rax
Ltmp1856:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$144, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1857:
LBB96_2:
Ltmp1858:
	orl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1859:
	je	LBB96_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1860:
Ltmp1861:
	movslq	%eax, %rax
Ltmp1862:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$144, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB96_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB96_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB96_6:
	callq	___stack_chk_fail
Ltmp1863:
Lfunc_end96:
Leh_func_end96:

	.globl	_atomic_or_32
	.align	4, 0x90
_atomic_or_32:
Leh_func_begin97:
Lfunc_begin97:
Ltmp1867:
	pushq	%rbp
Ltmp1864:
	movq	%rsp, %rbp
Ltmp1865:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1866:
	movl	%esi, %ebx
Ltmp1868:
	movq	%rdi, %r14
Ltmp1869:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1870:
Ltmp1871:
Ltmp1872:
	je	LBB97_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1873:
Ltmp1874:
	movslq	%eax, %rax
Ltmp1875:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$143, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1876:
LBB97_2:
Ltmp1877:
	orl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1878:
	je	LBB97_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1879:
Ltmp1880:
	movslq	%eax, %rax
Ltmp1881:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$143, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB97_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB97_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB97_6:
	callq	___stack_chk_fail
Ltmp1882:
Lfunc_end97:
Leh_func_end97:

	.globl	_atomic_or_ushort
	.align	4, 0x90
_atomic_or_ushort:
Leh_func_begin98:
Lfunc_begin98:
Ltmp1886:
	pushq	%rbp
Ltmp1883:
	movq	%rsp, %rbp
Ltmp1884:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1885:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1887:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1888:
Ltmp1889:
	je	LBB98_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1890:
Ltmp1891:
	movslq	%eax, %rax
Ltmp1892:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$142, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1893:
LBB98_2:
Ltmp1894:
	orw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1895:
	je	LBB98_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1896:
Ltmp1897:
	movslq	%eax, %rax
Ltmp1898:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$142, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB98_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB98_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB98_6:
	callq	___stack_chk_fail
Ltmp1899:
Lfunc_end98:
Leh_func_end98:

	.globl	_atomic_or_16
	.align	4, 0x90
_atomic_or_16:
Leh_func_begin99:
Lfunc_begin99:
Ltmp1903:
	pushq	%rbp
Ltmp1900:
	movq	%rsp, %rbp
Ltmp1901:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1902:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1904:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1905:
Ltmp1906:
	je	LBB99_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1907:
Ltmp1908:
	movslq	%eax, %rax
Ltmp1909:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$141, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1910:
LBB99_2:
Ltmp1911:
	orw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1912:
	je	LBB99_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1913:
Ltmp1914:
	movslq	%eax, %rax
Ltmp1915:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$141, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB99_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB99_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB99_6:
	callq	___stack_chk_fail
Ltmp1916:
Lfunc_end99:
Leh_func_end99:

	.globl	_atomic_or_uchar
	.align	4, 0x90
_atomic_or_uchar:
Leh_func_begin100:
Lfunc_begin100:
Ltmp1920:
	pushq	%rbp
Ltmp1917:
	movq	%rsp, %rbp
Ltmp1918:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1919:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1921:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1922:
Ltmp1923:
	je	LBB100_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1924:
Ltmp1925:
	movslq	%eax, %rax
Ltmp1926:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$140, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1927:
LBB100_2:
Ltmp1928:
	orb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1929:
	je	LBB100_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1930:
Ltmp1931:
	movslq	%eax, %rax
Ltmp1932:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$140, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB100_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB100_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB100_6:
	callq	___stack_chk_fail
Ltmp1933:
Lfunc_end100:
Leh_func_end100:

	.globl	_atomic_or_8
	.align	4, 0x90
_atomic_or_8:
Leh_func_begin101:
Lfunc_begin101:
Ltmp1937:
	pushq	%rbp
Ltmp1934:
	movq	%rsp, %rbp
Ltmp1935:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1936:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp1938:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1939:
Ltmp1940:
	je	LBB101_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1941:
Ltmp1942:
	movslq	%eax, %rax
Ltmp1943:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$139, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1944:
LBB101_2:
Ltmp1945:
	orb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1946:
	je	LBB101_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1947:
Ltmp1948:
	movslq	%eax, %rax
Ltmp1949:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$139, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB101_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB101_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB101_6:
	callq	___stack_chk_fail
Ltmp1950:
Lfunc_end101:
Leh_func_end101:

	.globl	_atomic_sub_ptr
	.align	4, 0x90
_atomic_sub_ptr:
Leh_func_begin102:
Lfunc_begin102:
Ltmp1954:
	pushq	%rbp
Ltmp1951:
	movq	%rsp, %rbp
Ltmp1952:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1953:
	movq	%rsi, %rbx
Ltmp1955:
	movq	%rdi, %r14
Ltmp1956:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp1957:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1958:
Ltmp1959:
Ltmp1960:
	je	LBB102_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1961:
Ltmp1962:
	movslq	%eax, %rax
Ltmp1963:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$125, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1964:
LBB102_2:
Ltmp1965:
	subq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp1966:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1967:
	je	LBB102_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1968:
Ltmp1969:
	movslq	%eax, %rax
Ltmp1970:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$127, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB102_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB102_6
Ltmp1971:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB102_6:
	callq	___stack_chk_fail
Ltmp1972:
Lfunc_end102:
Leh_func_end102:

	.globl	_atomic_sub_64
	.align	4, 0x90
_atomic_sub_64:
Leh_func_begin103:
Lfunc_begin103:
Ltmp1976:
	pushq	%rbp
Ltmp1973:
	movq	%rsp, %rbp
Ltmp1974:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1975:
	movq	%rsi, %rbx
Ltmp1977:
	movq	%rdi, %r14
Ltmp1978:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1979:
Ltmp1980:
Ltmp1981:
	je	LBB103_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1982:
Ltmp1983:
	movslq	%eax, %rax
Ltmp1984:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$121, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp1985:
LBB103_2:
Ltmp1986:
	subq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp1987:
	je	LBB103_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp1988:
Ltmp1989:
	movslq	%eax, %rax
Ltmp1990:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$121, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB103_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB103_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB103_6:
	callq	___stack_chk_fail
Ltmp1991:
Lfunc_end103:
Leh_func_end103:

	.globl	_atomic_sub_long
	.align	4, 0x90
_atomic_sub_long:
Leh_func_begin104:
Lfunc_begin104:
Ltmp1995:
	pushq	%rbp
Ltmp1992:
	movq	%rsp, %rbp
Ltmp1993:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp1994:
	movq	%rsi, %rbx
Ltmp1996:
	movq	%rdi, %r14
Ltmp1997:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp1998:
Ltmp1999:
Ltmp2000:
	je	LBB104_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2001:
Ltmp2002:
	movslq	%eax, %rax
Ltmp2003:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$120, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2004:
LBB104_2:
Ltmp2005:
	subq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2006:
	je	LBB104_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2007:
Ltmp2008:
	movslq	%eax, %rax
Ltmp2009:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$120, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB104_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB104_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB104_6:
	callq	___stack_chk_fail
Ltmp2010:
Lfunc_end104:
Leh_func_end104:

	.globl	_atomic_sub_int
	.align	4, 0x90
_atomic_sub_int:
Leh_func_begin105:
Lfunc_begin105:
Ltmp2014:
	pushq	%rbp
Ltmp2011:
	movq	%rsp, %rbp
Ltmp2012:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2013:
	movl	%esi, %ebx
Ltmp2015:
	movq	%rdi, %r14
Ltmp2016:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2017:
Ltmp2018:
Ltmp2019:
	je	LBB105_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2020:
Ltmp2021:
	movslq	%eax, %rax
Ltmp2022:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$119, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2023:
LBB105_2:
Ltmp2024:
	subl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2025:
	je	LBB105_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2026:
Ltmp2027:
	movslq	%eax, %rax
Ltmp2028:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$119, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB105_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB105_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB105_6:
	callq	___stack_chk_fail
Ltmp2029:
Lfunc_end105:
Leh_func_end105:

	.globl	_atomic_sub_32
	.align	4, 0x90
_atomic_sub_32:
Leh_func_begin106:
Lfunc_begin106:
Ltmp2033:
	pushq	%rbp
Ltmp2030:
	movq	%rsp, %rbp
Ltmp2031:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2032:
	movl	%esi, %ebx
Ltmp2034:
	movq	%rdi, %r14
Ltmp2035:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2036:
Ltmp2037:
Ltmp2038:
	je	LBB106_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2039:
Ltmp2040:
	movslq	%eax, %rax
Ltmp2041:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$118, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2042:
LBB106_2:
Ltmp2043:
	subl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2044:
	je	LBB106_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2045:
Ltmp2046:
	movslq	%eax, %rax
Ltmp2047:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$118, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB106_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB106_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB106_6:
	callq	___stack_chk_fail
Ltmp2048:
Lfunc_end106:
Leh_func_end106:

	.globl	_atomic_sub_short
	.align	4, 0x90
_atomic_sub_short:
Leh_func_begin107:
Lfunc_begin107:
Ltmp2052:
	pushq	%rbp
Ltmp2049:
	movq	%rsp, %rbp
Ltmp2050:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2051:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2053:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2054:
Ltmp2055:
	je	LBB107_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2056:
Ltmp2057:
	movslq	%eax, %rax
Ltmp2058:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$117, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2059:
LBB107_2:
Ltmp2060:
	subw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2061:
	je	LBB107_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2062:
Ltmp2063:
	movslq	%eax, %rax
Ltmp2064:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$117, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB107_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB107_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB107_6:
	callq	___stack_chk_fail
Ltmp2065:
Lfunc_end107:
Leh_func_end107:

	.globl	_atomic_sub_16
	.align	4, 0x90
_atomic_sub_16:
Leh_func_begin108:
Lfunc_begin108:
Ltmp2069:
	pushq	%rbp
Ltmp2066:
	movq	%rsp, %rbp
Ltmp2067:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2068:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2070:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2071:
Ltmp2072:
	je	LBB108_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2073:
Ltmp2074:
	movslq	%eax, %rax
Ltmp2075:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$116, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2076:
LBB108_2:
Ltmp2077:
	subw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2078:
	je	LBB108_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2079:
Ltmp2080:
	movslq	%eax, %rax
Ltmp2081:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$116, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB108_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB108_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB108_6:
	callq	___stack_chk_fail
Ltmp2082:
Lfunc_end108:
Leh_func_end108:

	.globl	_atomic_sub_char
	.align	4, 0x90
_atomic_sub_char:
Leh_func_begin109:
Lfunc_begin109:
Ltmp2086:
	pushq	%rbp
Ltmp2083:
	movq	%rsp, %rbp
Ltmp2084:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2085:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2087:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2088:
Ltmp2089:
	je	LBB109_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2090:
Ltmp2091:
	movslq	%eax, %rax
Ltmp2092:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$115, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2093:
LBB109_2:
Ltmp2094:
	subb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2095:
	je	LBB109_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2096:
Ltmp2097:
	movslq	%eax, %rax
Ltmp2098:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$115, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB109_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB109_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB109_6:
	callq	___stack_chk_fail
Ltmp2099:
Lfunc_end109:
Leh_func_end109:

	.globl	_atomic_sub_8
	.align	4, 0x90
_atomic_sub_8:
Leh_func_begin110:
Lfunc_begin110:
Ltmp2103:
	pushq	%rbp
Ltmp2100:
	movq	%rsp, %rbp
Ltmp2101:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2102:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2104:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2105:
Ltmp2106:
	je	LBB110_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2107:
Ltmp2108:
	movslq	%eax, %rax
Ltmp2109:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$114, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2110:
LBB110_2:
Ltmp2111:
	subb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2112:
	je	LBB110_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2113:
Ltmp2114:
	movslq	%eax, %rax
Ltmp2115:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$114, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB110_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB110_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB110_6:
	callq	___stack_chk_fail
Ltmp2116:
Lfunc_end110:
Leh_func_end110:

	.globl	_atomic_add_ptr
	.align	4, 0x90
_atomic_add_ptr:
Leh_func_begin111:
Lfunc_begin111:
Ltmp2120:
	pushq	%rbp
Ltmp2117:
	movq	%rsp, %rbp
Ltmp2118:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2119:
	movq	%rsi, %rbx
Ltmp2121:
	movq	%rdi, %r14
Ltmp2122:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
Ltmp2123:
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2124:
Ltmp2125:
Ltmp2126:
	je	LBB111_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2127:
Ltmp2128:
	movslq	%eax, %rax
Ltmp2129:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$100, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2130:
LBB111_2:
Ltmp2131:
	addq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
Ltmp2132:
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2133:
	je	LBB111_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2134:
Ltmp2135:
	movslq	%eax, %rax
Ltmp2136:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$102, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB111_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB111_6
Ltmp2137:
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB111_6:
	callq	___stack_chk_fail
Ltmp2138:
Lfunc_end111:
Leh_func_end111:

	.globl	_atomic_add_64
	.align	4, 0x90
_atomic_add_64:
Leh_func_begin112:
Lfunc_begin112:
Ltmp2142:
	pushq	%rbp
Ltmp2139:
	movq	%rsp, %rbp
Ltmp2140:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2141:
	movq	%rsi, %rbx
Ltmp2143:
	movq	%rdi, %r14
Ltmp2144:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2145:
Ltmp2146:
Ltmp2147:
	je	LBB112_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2148:
Ltmp2149:
	movslq	%eax, %rax
Ltmp2150:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$96, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2151:
LBB112_2:
Ltmp2152:
	addq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2153:
	je	LBB112_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2154:
Ltmp2155:
	movslq	%eax, %rax
Ltmp2156:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$96, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB112_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB112_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB112_6:
	callq	___stack_chk_fail
Ltmp2157:
Lfunc_end112:
Leh_func_end112:

	.globl	_atomic_add_long
	.align	4, 0x90
_atomic_add_long:
Leh_func_begin113:
Lfunc_begin113:
Ltmp2161:
	pushq	%rbp
Ltmp2158:
	movq	%rsp, %rbp
Ltmp2159:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2160:
	movq	%rsi, %rbx
Ltmp2162:
	movq	%rdi, %r14
Ltmp2163:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2164:
Ltmp2165:
Ltmp2166:
	je	LBB113_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2167:
Ltmp2168:
	movslq	%eax, %rax
Ltmp2169:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$95, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2170:
LBB113_2:
Ltmp2171:
	addq	%rbx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2172:
	je	LBB113_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2173:
Ltmp2174:
	movslq	%eax, %rax
Ltmp2175:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$95, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB113_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB113_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB113_6:
	callq	___stack_chk_fail
Ltmp2176:
Lfunc_end113:
Leh_func_end113:

	.globl	_atomic_add_int
	.align	4, 0x90
_atomic_add_int:
Leh_func_begin114:
Lfunc_begin114:
Ltmp2180:
	pushq	%rbp
Ltmp2177:
	movq	%rsp, %rbp
Ltmp2178:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2179:
	movl	%esi, %ebx
Ltmp2181:
	movq	%rdi, %r14
Ltmp2182:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2183:
Ltmp2184:
Ltmp2185:
	je	LBB114_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2186:
Ltmp2187:
	movslq	%eax, %rax
Ltmp2188:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$94, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2189:
LBB114_2:
Ltmp2190:
	addl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2191:
	je	LBB114_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2192:
Ltmp2193:
	movslq	%eax, %rax
Ltmp2194:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$94, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB114_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB114_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB114_6:
	callq	___stack_chk_fail
Ltmp2195:
Lfunc_end114:
Leh_func_end114:

	.globl	_atomic_add_32
	.align	4, 0x90
_atomic_add_32:
Leh_func_begin115:
Lfunc_begin115:
Ltmp2199:
	pushq	%rbp
Ltmp2196:
	movq	%rsp, %rbp
Ltmp2197:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2198:
	movl	%esi, %ebx
Ltmp2200:
	movq	%rdi, %r14
Ltmp2201:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2202:
Ltmp2203:
Ltmp2204:
	je	LBB115_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2205:
Ltmp2206:
	movslq	%eax, %rax
Ltmp2207:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$93, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2208:
LBB115_2:
Ltmp2209:
	addl	%ebx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2210:
	je	LBB115_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2211:
Ltmp2212:
	movslq	%eax, %rax
Ltmp2213:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$93, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB115_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB115_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB115_6:
	callq	___stack_chk_fail
Ltmp2214:
Lfunc_end115:
Leh_func_end115:

	.globl	_atomic_add_short
	.align	4, 0x90
_atomic_add_short:
Leh_func_begin116:
Lfunc_begin116:
Ltmp2218:
	pushq	%rbp
Ltmp2215:
	movq	%rsp, %rbp
Ltmp2216:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2217:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2219:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2220:
Ltmp2221:
	je	LBB116_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2222:
Ltmp2223:
	movslq	%eax, %rax
Ltmp2224:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$92, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2225:
LBB116_2:
Ltmp2226:
	addw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2227:
	je	LBB116_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2228:
Ltmp2229:
	movslq	%eax, %rax
Ltmp2230:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$92, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB116_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB116_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB116_6:
	callq	___stack_chk_fail
Ltmp2231:
Lfunc_end116:
Leh_func_end116:

	.globl	_atomic_add_16
	.align	4, 0x90
_atomic_add_16:
Leh_func_begin117:
Lfunc_begin117:
Ltmp2235:
	pushq	%rbp
Ltmp2232:
	movq	%rsp, %rbp
Ltmp2233:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2234:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2236:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2237:
Ltmp2238:
	je	LBB117_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2239:
Ltmp2240:
	movslq	%eax, %rax
Ltmp2241:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$91, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2242:
LBB117_2:
Ltmp2243:
	addw	%bx, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2244:
	je	LBB117_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2245:
Ltmp2246:
	movslq	%eax, %rax
Ltmp2247:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$91, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB117_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB117_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB117_6:
	callq	___stack_chk_fail
Ltmp2248:
Lfunc_end117:
Leh_func_end117:

	.globl	_atomic_add_char
	.align	4, 0x90
_atomic_add_char:
Leh_func_begin118:
Lfunc_begin118:
Ltmp2252:
	pushq	%rbp
Ltmp2249:
	movq	%rsp, %rbp
Ltmp2250:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2251:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2253:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2254:
Ltmp2255:
	je	LBB118_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2256:
Ltmp2257:
	movslq	%eax, %rax
Ltmp2258:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$90, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2259:
LBB118_2:
Ltmp2260:
	addb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2261:
	je	LBB118_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2262:
Ltmp2263:
	movslq	%eax, %rax
Ltmp2264:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$90, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB118_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB118_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB118_6:
	callq	___stack_chk_fail
Ltmp2265:
Lfunc_end118:
Leh_func_end118:

	.globl	_atomic_add_8
	.align	4, 0x90
_atomic_add_8:
Leh_func_begin119:
Lfunc_begin119:
Ltmp2269:
	pushq	%rbp
Ltmp2266:
	movq	%rsp, %rbp
Ltmp2267:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$8, %rsp
Ltmp2268:
	movl	%esi, %ebx
	movq	%rdi, %r14
Ltmp2270:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2271:
Ltmp2272:
	je	LBB119_2
	leaq	-256(%rsp), %r15
	movq	%r15, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2273:
Ltmp2274:
	movslq	%eax, %rax
Ltmp2275:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r15, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$89, %edx
	movq	%r15, %rdi
	callq	___assert
Ltmp2276:
LBB119_2:
Ltmp2277:
	addb	%bl, (%r14)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2278:
	je	LBB119_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2279:
Ltmp2280:
	movslq	%eax, %rax
Ltmp2281:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$89, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB119_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-32(%rbp), %rax
	jne	LBB119_6
	leaq	-24(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	popq	%rbp
	ret
LBB119_6:
	callq	___stack_chk_fail
Ltmp2282:
Lfunc_end119:
Leh_func_end119:

	.globl	_atomic_dec_64
	.align	4, 0x90
_atomic_dec_64:
Leh_func_begin120:
Lfunc_begin120:
Ltmp2286:
	pushq	%rbp
Ltmp2283:
	movq	%rsp, %rbp
Ltmp2284:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2285:
	movq	%rdi, %rbx
Ltmp2287:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2288:
Ltmp2289:
	je	LBB120_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2290:
Ltmp2291:
	movslq	%eax, %rax
Ltmp2292:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$78, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2293:
LBB120_2:
Ltmp2294:
	decq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2295:
	je	LBB120_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2296:
Ltmp2297:
	movslq	%eax, %rax
Ltmp2298:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$78, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB120_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB120_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB120_6:
	callq	___stack_chk_fail
Ltmp2299:
Lfunc_end120:
Leh_func_end120:

	.globl	_atomic_dec_ulong
	.align	4, 0x90
_atomic_dec_ulong:
Leh_func_begin121:
Lfunc_begin121:
Ltmp2303:
	pushq	%rbp
Ltmp2300:
	movq	%rsp, %rbp
Ltmp2301:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2302:
	movq	%rdi, %rbx
Ltmp2304:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2305:
Ltmp2306:
	je	LBB121_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2307:
Ltmp2308:
	movslq	%eax, %rax
Ltmp2309:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$77, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2310:
LBB121_2:
Ltmp2311:
	decq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2312:
	je	LBB121_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2313:
Ltmp2314:
	movslq	%eax, %rax
Ltmp2315:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$77, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB121_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB121_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB121_6:
	callq	___stack_chk_fail
Ltmp2316:
Lfunc_end121:
Leh_func_end121:

	.globl	_atomic_dec_uint
	.align	4, 0x90
_atomic_dec_uint:
Leh_func_begin122:
Lfunc_begin122:
Ltmp2320:
	pushq	%rbp
Ltmp2317:
	movq	%rsp, %rbp
Ltmp2318:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2319:
	movq	%rdi, %rbx
Ltmp2321:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2322:
Ltmp2323:
	je	LBB122_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2324:
Ltmp2325:
	movslq	%eax, %rax
Ltmp2326:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$76, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2327:
LBB122_2:
Ltmp2328:
	decl	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2329:
	je	LBB122_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2330:
Ltmp2331:
	movslq	%eax, %rax
Ltmp2332:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$76, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB122_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB122_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB122_6:
	callq	___stack_chk_fail
Ltmp2333:
Lfunc_end122:
Leh_func_end122:

	.globl	_atomic_dec_32
	.align	4, 0x90
_atomic_dec_32:
Leh_func_begin123:
Lfunc_begin123:
Ltmp2337:
	pushq	%rbp
Ltmp2334:
	movq	%rsp, %rbp
Ltmp2335:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2336:
	movq	%rdi, %rbx
Ltmp2338:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2339:
Ltmp2340:
	je	LBB123_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2341:
Ltmp2342:
	movslq	%eax, %rax
Ltmp2343:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$75, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2344:
LBB123_2:
Ltmp2345:
	decl	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2346:
	je	LBB123_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2347:
Ltmp2348:
	movslq	%eax, %rax
Ltmp2349:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$75, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB123_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB123_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB123_6:
	callq	___stack_chk_fail
Ltmp2350:
Lfunc_end123:
Leh_func_end123:

	.globl	_atomic_dec_ushort
	.align	4, 0x90
_atomic_dec_ushort:
Leh_func_begin124:
Lfunc_begin124:
Ltmp2354:
	pushq	%rbp
Ltmp2351:
	movq	%rsp, %rbp
Ltmp2352:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2353:
	movq	%rdi, %rbx
Ltmp2355:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2356:
Ltmp2357:
	je	LBB124_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2358:
Ltmp2359:
	movslq	%eax, %rax
Ltmp2360:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$74, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2361:
LBB124_2:
Ltmp2362:
	decw	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2363:
	je	LBB124_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2364:
Ltmp2365:
	movslq	%eax, %rax
Ltmp2366:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$74, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB124_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB124_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB124_6:
	callq	___stack_chk_fail
Ltmp2367:
Lfunc_end124:
Leh_func_end124:

	.globl	_atomic_dec_16
	.align	4, 0x90
_atomic_dec_16:
Leh_func_begin125:
Lfunc_begin125:
Ltmp2371:
	pushq	%rbp
Ltmp2368:
	movq	%rsp, %rbp
Ltmp2369:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2370:
	movq	%rdi, %rbx
Ltmp2372:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2373:
Ltmp2374:
	je	LBB125_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2375:
Ltmp2376:
	movslq	%eax, %rax
Ltmp2377:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$73, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2378:
LBB125_2:
Ltmp2379:
	decw	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2380:
	je	LBB125_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2381:
Ltmp2382:
	movslq	%eax, %rax
Ltmp2383:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$73, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB125_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB125_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB125_6:
	callq	___stack_chk_fail
Ltmp2384:
Lfunc_end125:
Leh_func_end125:

	.globl	_atomic_dec_uchar
	.align	4, 0x90
_atomic_dec_uchar:
Leh_func_begin126:
Lfunc_begin126:
Ltmp2388:
	pushq	%rbp
Ltmp2385:
	movq	%rsp, %rbp
Ltmp2386:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2387:
	movq	%rdi, %rbx
Ltmp2389:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2390:
Ltmp2391:
	je	LBB126_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2392:
Ltmp2393:
	movslq	%eax, %rax
Ltmp2394:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$72, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2395:
LBB126_2:
Ltmp2396:
	decb	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2397:
	je	LBB126_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2398:
Ltmp2399:
	movslq	%eax, %rax
Ltmp2400:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$72, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB126_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB126_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB126_6:
	callq	___stack_chk_fail
Ltmp2401:
Lfunc_end126:
Leh_func_end126:

	.globl	_atomic_dec_8
	.align	4, 0x90
_atomic_dec_8:
Leh_func_begin127:
Lfunc_begin127:
Ltmp2405:
	pushq	%rbp
Ltmp2402:
	movq	%rsp, %rbp
Ltmp2403:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2404:
	movq	%rdi, %rbx
Ltmp2406:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2407:
Ltmp2408:
	je	LBB127_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2409:
Ltmp2410:
	movslq	%eax, %rax
Ltmp2411:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$71, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2412:
LBB127_2:
Ltmp2413:
	decb	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2414:
	je	LBB127_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2415:
Ltmp2416:
	movslq	%eax, %rax
Ltmp2417:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$71, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB127_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB127_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB127_6:
	callq	___stack_chk_fail
Ltmp2418:
Lfunc_end127:
Leh_func_end127:

	.globl	_atomic_dec_long
	.align	4, 0x90
_atomic_dec_long:
Leh_func_begin128:
Lfunc_begin128:
Ltmp2422:
	pushq	%rbp
Ltmp2419:
	movq	%rsp, %rbp
Ltmp2420:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2421:
	movq	%rdi, %rbx
Ltmp2423:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2424:
Ltmp2425:
	je	LBB128_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2426:
Ltmp2427:
	movslq	%eax, %rax
Ltmp2428:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$70, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2429:
LBB128_2:
Ltmp2430:
	decq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2431:
	je	LBB128_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2432:
Ltmp2433:
	movslq	%eax, %rax
Ltmp2434:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$70, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB128_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB128_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB128_6:
	callq	___stack_chk_fail
Ltmp2435:
Lfunc_end128:
Leh_func_end128:

	.globl	_atomic_inc_64
	.align	4, 0x90
_atomic_inc_64:
Leh_func_begin129:
Lfunc_begin129:
Ltmp2439:
	pushq	%rbp
Ltmp2436:
	movq	%rsp, %rbp
Ltmp2437:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2438:
	movq	%rdi, %rbx
Ltmp2440:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2441:
Ltmp2442:
	je	LBB129_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2443:
Ltmp2444:
	movslq	%eax, %rax
Ltmp2445:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$59, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2446:
LBB129_2:
Ltmp2447:
	incq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2448:
	je	LBB129_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2449:
Ltmp2450:
	movslq	%eax, %rax
Ltmp2451:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$59, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB129_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB129_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB129_6:
	callq	___stack_chk_fail
Ltmp2452:
Lfunc_end129:
Leh_func_end129:

	.globl	_atomic_inc_ulong
	.align	4, 0x90
_atomic_inc_ulong:
Leh_func_begin130:
Lfunc_begin130:
Ltmp2456:
	pushq	%rbp
Ltmp2453:
	movq	%rsp, %rbp
Ltmp2454:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2455:
	movq	%rdi, %rbx
Ltmp2457:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2458:
Ltmp2459:
	je	LBB130_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2460:
Ltmp2461:
	movslq	%eax, %rax
Ltmp2462:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$58, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2463:
LBB130_2:
Ltmp2464:
	incq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2465:
	je	LBB130_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2466:
Ltmp2467:
	movslq	%eax, %rax
Ltmp2468:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$58, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB130_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB130_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB130_6:
	callq	___stack_chk_fail
Ltmp2469:
Lfunc_end130:
Leh_func_end130:

	.globl	_atomic_inc_uint
	.align	4, 0x90
_atomic_inc_uint:
Leh_func_begin131:
Lfunc_begin131:
Ltmp2473:
	pushq	%rbp
Ltmp2470:
	movq	%rsp, %rbp
Ltmp2471:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2472:
	movq	%rdi, %rbx
Ltmp2474:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2475:
Ltmp2476:
	je	LBB131_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2477:
Ltmp2478:
	movslq	%eax, %rax
Ltmp2479:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$57, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2480:
LBB131_2:
Ltmp2481:
	incl	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2482:
	je	LBB131_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2483:
Ltmp2484:
	movslq	%eax, %rax
Ltmp2485:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$57, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB131_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB131_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB131_6:
	callq	___stack_chk_fail
Ltmp2486:
Lfunc_end131:
Leh_func_end131:

	.globl	_atomic_inc_32
	.align	4, 0x90
_atomic_inc_32:
Leh_func_begin132:
Lfunc_begin132:
Ltmp2490:
	pushq	%rbp
Ltmp2487:
	movq	%rsp, %rbp
Ltmp2488:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2489:
	movq	%rdi, %rbx
Ltmp2491:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2492:
Ltmp2493:
	je	LBB132_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2494:
Ltmp2495:
	movslq	%eax, %rax
Ltmp2496:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$56, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2497:
LBB132_2:
Ltmp2498:
	incl	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2499:
	je	LBB132_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2500:
Ltmp2501:
	movslq	%eax, %rax
Ltmp2502:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$56, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB132_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB132_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB132_6:
	callq	___stack_chk_fail
Ltmp2503:
Lfunc_end132:
Leh_func_end132:

	.globl	_atomic_inc_ushort
	.align	4, 0x90
_atomic_inc_ushort:
Leh_func_begin133:
Lfunc_begin133:
Ltmp2507:
	pushq	%rbp
Ltmp2504:
	movq	%rsp, %rbp
Ltmp2505:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2506:
	movq	%rdi, %rbx
Ltmp2508:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2509:
Ltmp2510:
	je	LBB133_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2511:
Ltmp2512:
	movslq	%eax, %rax
Ltmp2513:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$55, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2514:
LBB133_2:
Ltmp2515:
	incw	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2516:
	je	LBB133_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2517:
Ltmp2518:
	movslq	%eax, %rax
Ltmp2519:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$55, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB133_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB133_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB133_6:
	callq	___stack_chk_fail
Ltmp2520:
Lfunc_end133:
Leh_func_end133:

	.globl	_atomic_inc_16
	.align	4, 0x90
_atomic_inc_16:
Leh_func_begin134:
Lfunc_begin134:
Ltmp2524:
	pushq	%rbp
Ltmp2521:
	movq	%rsp, %rbp
Ltmp2522:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2523:
	movq	%rdi, %rbx
Ltmp2525:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2526:
Ltmp2527:
	je	LBB134_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2528:
Ltmp2529:
	movslq	%eax, %rax
Ltmp2530:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$54, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2531:
LBB134_2:
Ltmp2532:
	incw	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2533:
	je	LBB134_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2534:
Ltmp2535:
	movslq	%eax, %rax
Ltmp2536:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$54, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB134_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB134_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB134_6:
	callq	___stack_chk_fail
Ltmp2537:
Lfunc_end134:
Leh_func_end134:

	.globl	_atomic_inc_uchar
	.align	4, 0x90
_atomic_inc_uchar:
Leh_func_begin135:
Lfunc_begin135:
Ltmp2541:
	pushq	%rbp
Ltmp2538:
	movq	%rsp, %rbp
Ltmp2539:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2540:
	movq	%rdi, %rbx
Ltmp2542:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2543:
Ltmp2544:
	je	LBB135_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2545:
Ltmp2546:
	movslq	%eax, %rax
Ltmp2547:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$53, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2548:
LBB135_2:
Ltmp2549:
	incb	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2550:
	je	LBB135_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2551:
Ltmp2552:
	movslq	%eax, %rax
Ltmp2553:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$53, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB135_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB135_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB135_6:
	callq	___stack_chk_fail
Ltmp2554:
Lfunc_end135:
Leh_func_end135:

	.globl	_atomic_inc_8
	.align	4, 0x90
_atomic_inc_8:
Leh_func_begin136:
Lfunc_begin136:
Ltmp2558:
	pushq	%rbp
Ltmp2555:
	movq	%rsp, %rbp
Ltmp2556:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2557:
	movq	%rdi, %rbx
Ltmp2559:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2560:
Ltmp2561:
	je	LBB136_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2562:
Ltmp2563:
	movslq	%eax, %rax
Ltmp2564:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$52, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2565:
LBB136_2:
Ltmp2566:
	incb	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2567:
	je	LBB136_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2568:
Ltmp2569:
	movslq	%eax, %rax
Ltmp2570:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$52, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB136_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB136_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB136_6:
	callq	___stack_chk_fail
Ltmp2571:
Lfunc_end136:
Leh_func_end136:

	.globl	_atomic_inc_long
	.align	4, 0x90
_atomic_inc_long:
Leh_func_begin137:
Lfunc_begin137:
Ltmp2575:
	pushq	%rbp
Ltmp2572:
	movq	%rsp, %rbp
Ltmp2573:
	pushq	%r14
	pushq	%rbx
	subq	$16, %rsp
Ltmp2574:
	movq	%rdi, %rbx
Ltmp2576:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_lock
	testl	%eax, %eax
Ltmp2577:
Ltmp2578:
	je	LBB137_2
	leaq	-256(%rsp), %r14
	movq	%r14, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2579:
Ltmp2580:
	movslq	%eax, %rax
Ltmp2581:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str1(%rip), %r9
	xorb	%al, %al
	movq	%r14, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$51, %edx
	movq	%r14, %rdi
	callq	___assert
Ltmp2582:
LBB137_2:
Ltmp2583:
	incq	(%rbx)
	leaq	_atomic_lock(%rip), %rdi
	callq	_pthread_mutex_unlock
	testl	%eax, %eax
Ltmp2584:
	je	LBB137_4
	leaq	-256(%rsp), %rbx
	movq	%rbx, %rsp
	subq	$48, %rsp
	leaq	L_.str2(%rip), %rcx
	movq	%rcx, 24(%rsp)
Ltmp2585:
Ltmp2586:
	movslq	%eax, %rax
Ltmp2587:
	movq	%rax, 16(%rsp)
	leaq	L_.str3(%rip), %rax
	movq	%rax, 8(%rsp)
	movq	%rcx, (%rsp)
	movq	$0, 32(%rsp)
	xorl	%edx, %edx
	movl	$256, %esi
	leaq	L_.str(%rip), %r8
	leaq	L_.str5(%rip), %r9
	xorb	%al, %al
	movq	%rbx, %rdi
	movl	$256, %ecx
	callq	___snprintf_chk
	addq	$48, %rsp
	leaq	L_.str4(%rip), %rsi
	movl	$51, %edx
	movq	%rbx, %rdi
	callq	___assert
LBB137_4:
	movq	___stack_chk_guard@GOTPCREL(%rip), %rax
	movq	(%rax), %rax
	cmpq	-24(%rbp), %rax
	jne	LBB137_6
	leaq	-16(%rbp), %rsp
	popq	%rbx
	popq	%r14
	popq	%rbp
	ret
LBB137_6:
	callq	___stack_chk_fail
Ltmp2588:
Lfunc_end137:
Leh_func_end137:

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
L_.str5:
	.asciz	 "pthread_mutex_unlock(&atomic_lock)"

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
	.globl	_membar_enter.eh
_membar_enter.eh:
Lset1 = Leh_frame_end1-Leh_frame_begin1
	.long	Lset1
Leh_frame_begin1:
Lset2 = Leh_frame_begin1-Leh_frame_common
	.long	Lset2
Ltmp2589:
	.quad	Leh_func_begin1-Ltmp2589
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

	.globl	_membar_exit.eh
_membar_exit.eh:
Lset6 = Leh_frame_end2-Leh_frame_begin2
	.long	Lset6
Leh_frame_begin2:
Lset7 = Leh_frame_begin2-Leh_frame_common
	.long	Lset7
Ltmp2590:
	.quad	Leh_func_begin2-Ltmp2590
Lset8 = Leh_func_end2-Leh_func_begin2
	.quad	Lset8
	.byte	0
	.byte	4
Lset9 = Ltmp5-Leh_func_begin2
	.long	Lset9
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset10 = Ltmp6-Ltmp5
	.long	Lset10
	.byte	13
	.byte	6
	.align	3
Leh_frame_end2:

	.globl	_membar_producer.eh
_membar_producer.eh:
Lset11 = Leh_frame_end3-Leh_frame_begin3
	.long	Lset11
Leh_frame_begin3:
Lset12 = Leh_frame_begin3-Leh_frame_common
	.long	Lset12
Ltmp2591:
	.quad	Leh_func_begin3-Ltmp2591
Lset13 = Leh_func_end3-Leh_func_begin3
	.quad	Lset13
	.byte	0
	.byte	4
Lset14 = Ltmp10-Leh_func_begin3
	.long	Lset14
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset15 = Ltmp11-Ltmp10
	.long	Lset15
	.byte	13
	.byte	6
	.align	3
Leh_frame_end3:

	.globl	_membar_consumer.eh
_membar_consumer.eh:
Lset16 = Leh_frame_end4-Leh_frame_begin4
	.long	Lset16
Leh_frame_begin4:
Lset17 = Leh_frame_begin4-Leh_frame_common
	.long	Lset17
Ltmp2592:
	.quad	Leh_func_begin4-Ltmp2592
Lset18 = Leh_func_end4-Leh_func_begin4
	.quad	Lset18
	.byte	0
	.byte	4
Lset19 = Ltmp15-Leh_func_begin4
	.long	Lset19
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset20 = Ltmp16-Ltmp15
	.long	Lset20
	.byte	13
	.byte	6
	.align	3
Leh_frame_end4:

	.globl	_atomic_clear_long_excl.eh
_atomic_clear_long_excl.eh:
Lset21 = Leh_frame_end5-Leh_frame_begin5
	.long	Lset21
Leh_frame_begin5:
Lset22 = Leh_frame_begin5-Leh_frame_common
	.long	Lset22
Ltmp2593:
	.quad	Leh_func_begin5-Ltmp2593
Lset23 = Leh_func_end5-Leh_func_begin5
	.quad	Lset23
	.byte	0
	.byte	4
Lset24 = Ltmp20-Leh_func_begin5
	.long	Lset24
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset25 = Ltmp21-Ltmp20
	.long	Lset25
	.byte	13
	.byte	6
	.byte	4
Lset26 = Ltmp22-Ltmp21
	.long	Lset26
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end5:

	.globl	_atomic_set_long_excl.eh
_atomic_set_long_excl.eh:
Lset27 = Leh_frame_end6-Leh_frame_begin6
	.long	Lset27
Leh_frame_begin6:
Lset28 = Leh_frame_begin6-Leh_frame_common
	.long	Lset28
Ltmp2594:
	.quad	Leh_func_begin6-Ltmp2594
Lset29 = Leh_func_end6-Leh_func_begin6
	.quad	Lset29
	.byte	0
	.byte	4
Lset30 = Ltmp52-Leh_func_begin6
	.long	Lset30
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset31 = Ltmp53-Ltmp52
	.long	Lset31
	.byte	13
	.byte	6
	.byte	4
Lset32 = Ltmp54-Ltmp53
	.long	Lset32
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end6:

	.globl	_atomic_swap_ptr.eh
_atomic_swap_ptr.eh:
Lset33 = Leh_frame_end7-Leh_frame_begin7
	.long	Lset33
Leh_frame_begin7:
Lset34 = Leh_frame_begin7-Leh_frame_common
	.long	Lset34
Ltmp2595:
	.quad	Leh_func_begin7-Ltmp2595
Lset35 = Leh_func_end7-Leh_func_begin7
	.quad	Lset35
	.byte	0
	.byte	4
Lset36 = Ltmp84-Leh_func_begin7
	.long	Lset36
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset37 = Ltmp85-Ltmp84
	.long	Lset37
	.byte	13
	.byte	6
	.byte	4
Lset38 = Ltmp86-Ltmp85
	.long	Lset38
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end7:

	.globl	_atomic_swap_64.eh
_atomic_swap_64.eh:
Lset39 = Leh_frame_end8-Leh_frame_begin8
	.long	Lset39
Leh_frame_begin8:
Lset40 = Leh_frame_begin8-Leh_frame_common
	.long	Lset40
Ltmp2596:
	.quad	Leh_func_begin8-Ltmp2596
Lset41 = Leh_func_end8-Leh_func_begin8
	.quad	Lset41
	.byte	0
	.byte	4
Lset42 = Ltmp109-Leh_func_begin8
	.long	Lset42
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset43 = Ltmp110-Ltmp109
	.long	Lset43
	.byte	13
	.byte	6
	.byte	4
Lset44 = Ltmp111-Ltmp110
	.long	Lset44
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end8:

	.globl	_atomic_swap_ulong.eh
_atomic_swap_ulong.eh:
Lset45 = Leh_frame_end9-Leh_frame_begin9
	.long	Lset45
Leh_frame_begin9:
Lset46 = Leh_frame_begin9-Leh_frame_common
	.long	Lset46
Ltmp2597:
	.quad	Leh_func_begin9-Ltmp2597
Lset47 = Leh_func_end9-Leh_func_begin9
	.quad	Lset47
	.byte	0
	.byte	4
Lset48 = Ltmp130-Leh_func_begin9
	.long	Lset48
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset49 = Ltmp131-Ltmp130
	.long	Lset49
	.byte	13
	.byte	6
	.byte	4
Lset50 = Ltmp132-Ltmp131
	.long	Lset50
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end9:

	.globl	_atomic_swap_uint.eh
_atomic_swap_uint.eh:
Lset51 = Leh_frame_end10-Leh_frame_begin10
	.long	Lset51
Leh_frame_begin10:
Lset52 = Leh_frame_begin10-Leh_frame_common
	.long	Lset52
Ltmp2598:
	.quad	Leh_func_begin10-Ltmp2598
Lset53 = Leh_func_end10-Leh_func_begin10
	.quad	Lset53
	.byte	0
	.byte	4
Lset54 = Ltmp151-Leh_func_begin10
	.long	Lset54
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset55 = Ltmp152-Ltmp151
	.long	Lset55
	.byte	13
	.byte	6
	.byte	4
Lset56 = Ltmp153-Ltmp152
	.long	Lset56
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end10:

	.globl	_atomic_swap_32.eh
_atomic_swap_32.eh:
Lset57 = Leh_frame_end11-Leh_frame_begin11
	.long	Lset57
Leh_frame_begin11:
Lset58 = Leh_frame_begin11-Leh_frame_common
	.long	Lset58
Ltmp2599:
	.quad	Leh_func_begin11-Ltmp2599
Lset59 = Leh_func_end11-Leh_func_begin11
	.quad	Lset59
	.byte	0
	.byte	4
Lset60 = Ltmp172-Leh_func_begin11
	.long	Lset60
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset61 = Ltmp173-Ltmp172
	.long	Lset61
	.byte	13
	.byte	6
	.byte	4
Lset62 = Ltmp174-Ltmp173
	.long	Lset62
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end11:

	.globl	_atomic_swap_ushort.eh
_atomic_swap_ushort.eh:
Lset63 = Leh_frame_end12-Leh_frame_begin12
	.long	Lset63
Leh_frame_begin12:
Lset64 = Leh_frame_begin12-Leh_frame_common
	.long	Lset64
Ltmp2600:
	.quad	Leh_func_begin12-Ltmp2600
Lset65 = Leh_func_end12-Leh_func_begin12
	.quad	Lset65
	.byte	0
	.byte	4
Lset66 = Ltmp193-Leh_func_begin12
	.long	Lset66
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset67 = Ltmp194-Ltmp193
	.long	Lset67
	.byte	13
	.byte	6
	.byte	4
Lset68 = Ltmp195-Ltmp194
	.long	Lset68
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end12:

	.globl	_atomic_swap_16.eh
_atomic_swap_16.eh:
Lset69 = Leh_frame_end13-Leh_frame_begin13
	.long	Lset69
Leh_frame_begin13:
Lset70 = Leh_frame_begin13-Leh_frame_common
	.long	Lset70
Ltmp2601:
	.quad	Leh_func_begin13-Ltmp2601
Lset71 = Leh_func_end13-Leh_func_begin13
	.quad	Lset71
	.byte	0
	.byte	4
Lset72 = Ltmp212-Leh_func_begin13
	.long	Lset72
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset73 = Ltmp213-Ltmp212
	.long	Lset73
	.byte	13
	.byte	6
	.byte	4
Lset74 = Ltmp214-Ltmp213
	.long	Lset74
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end13:

	.globl	_atomic_swap_uchar.eh
_atomic_swap_uchar.eh:
Lset75 = Leh_frame_end14-Leh_frame_begin14
	.long	Lset75
Leh_frame_begin14:
Lset76 = Leh_frame_begin14-Leh_frame_common
	.long	Lset76
Ltmp2602:
	.quad	Leh_func_begin14-Ltmp2602
Lset77 = Leh_func_end14-Leh_func_begin14
	.quad	Lset77
	.byte	0
	.byte	4
Lset78 = Ltmp231-Leh_func_begin14
	.long	Lset78
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset79 = Ltmp232-Ltmp231
	.long	Lset79
	.byte	13
	.byte	6
	.byte	4
Lset80 = Ltmp233-Ltmp232
	.long	Lset80
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end14:

	.globl	_atomic_swap_8.eh
_atomic_swap_8.eh:
Lset81 = Leh_frame_end15-Leh_frame_begin15
	.long	Lset81
Leh_frame_begin15:
Lset82 = Leh_frame_begin15-Leh_frame_common
	.long	Lset82
Ltmp2603:
	.quad	Leh_func_begin15-Ltmp2603
Lset83 = Leh_func_end15-Leh_func_begin15
	.quad	Lset83
	.byte	0
	.byte	4
Lset84 = Ltmp250-Leh_func_begin15
	.long	Lset84
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset85 = Ltmp251-Ltmp250
	.long	Lset85
	.byte	13
	.byte	6
	.byte	4
Lset86 = Ltmp252-Ltmp251
	.long	Lset86
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end15:

	.globl	_atomic_cas_ptr.eh
_atomic_cas_ptr.eh:
Lset87 = Leh_frame_end16-Leh_frame_begin16
	.long	Lset87
Leh_frame_begin16:
Lset88 = Leh_frame_begin16-Leh_frame_common
	.long	Lset88
Ltmp2604:
	.quad	Leh_func_begin16-Ltmp2604
Lset89 = Leh_func_end16-Leh_func_begin16
	.quad	Lset89
	.byte	0
	.byte	4
Lset90 = Ltmp269-Leh_func_begin16
	.long	Lset90
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset91 = Ltmp270-Ltmp269
	.long	Lset91
	.byte	13
	.byte	6
	.byte	4
Lset92 = Ltmp271-Ltmp270
	.long	Lset92
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end16:

	.globl	_casptr.eh
_casptr.eh:
Lset93 = Leh_frame_end17-Leh_frame_begin17
	.long	Lset93
Leh_frame_begin17:
Lset94 = Leh_frame_begin17-Leh_frame_common
	.long	Lset94
Ltmp2605:
	.quad	Leh_func_begin17-Ltmp2605
Lset95 = Leh_func_end17-Leh_func_begin17
	.quad	Lset95
	.byte	0
	.byte	4
Lset96 = Ltmp296-Leh_func_begin17
	.long	Lset96
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset97 = Ltmp297-Ltmp296
	.long	Lset97
	.byte	13
	.byte	6
	.align	3
Leh_frame_end17:

	.globl	_atomic_cas_64.eh
_atomic_cas_64.eh:
Lset98 = Leh_frame_end18-Leh_frame_begin18
	.long	Lset98
Leh_frame_begin18:
Lset99 = Leh_frame_begin18-Leh_frame_common
	.long	Lset99
Ltmp2606:
	.quad	Leh_func_begin18-Ltmp2606
Lset100 = Leh_func_end18-Leh_func_begin18
	.quad	Lset100
	.byte	0
	.byte	4
Lset101 = Ltmp307-Leh_func_begin18
	.long	Lset101
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset102 = Ltmp308-Ltmp307
	.long	Lset102
	.byte	13
	.byte	6
	.byte	4
Lset103 = Ltmp309-Ltmp308
	.long	Lset103
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end18:

	.globl	_cas64.eh
_cas64.eh:
Lset104 = Leh_frame_end19-Leh_frame_begin19
	.long	Lset104
Leh_frame_begin19:
Lset105 = Leh_frame_begin19-Leh_frame_common
	.long	Lset105
Ltmp2607:
	.quad	Leh_func_begin19-Ltmp2607
Lset106 = Leh_func_end19-Leh_func_begin19
	.quad	Lset106
	.byte	0
	.byte	4
Lset107 = Ltmp331-Leh_func_begin19
	.long	Lset107
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset108 = Ltmp332-Ltmp331
	.long	Lset108
	.byte	13
	.byte	6
	.align	3
Leh_frame_end19:

	.globl	_atomic_cas_ulong.eh
_atomic_cas_ulong.eh:
Lset109 = Leh_frame_end20-Leh_frame_begin20
	.long	Lset109
Leh_frame_begin20:
Lset110 = Leh_frame_begin20-Leh_frame_common
	.long	Lset110
Ltmp2608:
	.quad	Leh_func_begin20-Ltmp2608
Lset111 = Leh_func_end20-Leh_func_begin20
	.quad	Lset111
	.byte	0
	.byte	4
Lset112 = Ltmp342-Leh_func_begin20
	.long	Lset112
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset113 = Ltmp343-Ltmp342
	.long	Lset113
	.byte	13
	.byte	6
	.byte	4
Lset114 = Ltmp344-Ltmp343
	.long	Lset114
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end20:

	.globl	_caslong.eh
_caslong.eh:
Lset115 = Leh_frame_end21-Leh_frame_begin21
	.long	Lset115
Leh_frame_begin21:
Lset116 = Leh_frame_begin21-Leh_frame_common
	.long	Lset116
Ltmp2609:
	.quad	Leh_func_begin21-Ltmp2609
Lset117 = Leh_func_end21-Leh_func_begin21
	.quad	Lset117
	.byte	0
	.byte	4
Lset118 = Ltmp366-Leh_func_begin21
	.long	Lset118
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset119 = Ltmp367-Ltmp366
	.long	Lset119
	.byte	13
	.byte	6
	.align	3
Leh_frame_end21:

	.globl	_atomic_cas_uint.eh
_atomic_cas_uint.eh:
Lset120 = Leh_frame_end22-Leh_frame_begin22
	.long	Lset120
Leh_frame_begin22:
Lset121 = Leh_frame_begin22-Leh_frame_common
	.long	Lset121
Ltmp2610:
	.quad	Leh_func_begin22-Ltmp2610
Lset122 = Leh_func_end22-Leh_func_begin22
	.quad	Lset122
	.byte	0
	.byte	4
Lset123 = Ltmp377-Leh_func_begin22
	.long	Lset123
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset124 = Ltmp378-Ltmp377
	.long	Lset124
	.byte	13
	.byte	6
	.byte	4
Lset125 = Ltmp379-Ltmp378
	.long	Lset125
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end22:

	.globl	_atomic_cas_32.eh
_atomic_cas_32.eh:
Lset126 = Leh_frame_end23-Leh_frame_begin23
	.long	Lset126
Leh_frame_begin23:
Lset127 = Leh_frame_begin23-Leh_frame_common
	.long	Lset127
Ltmp2611:
	.quad	Leh_func_begin23-Ltmp2611
Lset128 = Leh_func_end23-Leh_func_begin23
	.quad	Lset128
	.byte	0
	.byte	4
Lset129 = Ltmp401-Leh_func_begin23
	.long	Lset129
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset130 = Ltmp402-Ltmp401
	.long	Lset130
	.byte	13
	.byte	6
	.byte	4
Lset131 = Ltmp403-Ltmp402
	.long	Lset131
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end23:

	.globl	_cas32.eh
_cas32.eh:
Lset132 = Leh_frame_end24-Leh_frame_begin24
	.long	Lset132
Leh_frame_begin24:
Lset133 = Leh_frame_begin24-Leh_frame_common
	.long	Lset133
Ltmp2612:
	.quad	Leh_func_begin24-Ltmp2612
Lset134 = Leh_func_end24-Leh_func_begin24
	.quad	Lset134
	.byte	0
	.byte	4
Lset135 = Ltmp425-Leh_func_begin24
	.long	Lset135
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset136 = Ltmp426-Ltmp425
	.long	Lset136
	.byte	13
	.byte	6
	.align	3
Leh_frame_end24:

	.globl	_atomic_cas_ushort.eh
_atomic_cas_ushort.eh:
Lset137 = Leh_frame_end25-Leh_frame_begin25
	.long	Lset137
Leh_frame_begin25:
Lset138 = Leh_frame_begin25-Leh_frame_common
	.long	Lset138
Ltmp2613:
	.quad	Leh_func_begin25-Ltmp2613
Lset139 = Leh_func_end25-Leh_func_begin25
	.quad	Lset139
	.byte	0
	.byte	4
Lset140 = Ltmp436-Leh_func_begin25
	.long	Lset140
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset141 = Ltmp437-Ltmp436
	.long	Lset141
	.byte	13
	.byte	6
	.byte	4
Lset142 = Ltmp438-Ltmp437
	.long	Lset142
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end25:

	.globl	_atomic_cas_16.eh
_atomic_cas_16.eh:
Lset143 = Leh_frame_end26-Leh_frame_begin26
	.long	Lset143
Leh_frame_begin26:
Lset144 = Leh_frame_begin26-Leh_frame_common
	.long	Lset144
Ltmp2614:
	.quad	Leh_func_begin26-Ltmp2614
Lset145 = Leh_func_end26-Leh_func_begin26
	.quad	Lset145
	.byte	0
	.byte	4
Lset146 = Ltmp456-Leh_func_begin26
	.long	Lset146
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset147 = Ltmp457-Ltmp456
	.long	Lset147
	.byte	13
	.byte	6
	.byte	4
Lset148 = Ltmp458-Ltmp457
	.long	Lset148
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end26:

	.globl	_atomic_cas_uchar.eh
_atomic_cas_uchar.eh:
Lset149 = Leh_frame_end27-Leh_frame_begin27
	.long	Lset149
Leh_frame_begin27:
Lset150 = Leh_frame_begin27-Leh_frame_common
	.long	Lset150
Ltmp2615:
	.quad	Leh_func_begin27-Ltmp2615
Lset151 = Leh_func_end27-Leh_func_begin27
	.quad	Lset151
	.byte	0
	.byte	4
Lset152 = Ltmp476-Leh_func_begin27
	.long	Lset152
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset153 = Ltmp477-Ltmp476
	.long	Lset153
	.byte	13
	.byte	6
	.byte	4
Lset154 = Ltmp478-Ltmp477
	.long	Lset154
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end27:

	.globl	_atomic_cas_8.eh
_atomic_cas_8.eh:
Lset155 = Leh_frame_end28-Leh_frame_begin28
	.long	Lset155
Leh_frame_begin28:
Lset156 = Leh_frame_begin28-Leh_frame_common
	.long	Lset156
Ltmp2616:
	.quad	Leh_func_begin28-Ltmp2616
Lset157 = Leh_func_end28-Leh_func_begin28
	.quad	Lset157
	.byte	0
	.byte	4
Lset158 = Ltmp496-Leh_func_begin28
	.long	Lset158
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset159 = Ltmp497-Ltmp496
	.long	Lset159
	.byte	13
	.byte	6
	.byte	4
Lset160 = Ltmp498-Ltmp497
	.long	Lset160
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end28:

	.globl	_cas8.eh
_cas8.eh:
Lset161 = Leh_frame_end29-Leh_frame_begin29
	.long	Lset161
Leh_frame_begin29:
Lset162 = Leh_frame_begin29-Leh_frame_common
	.long	Lset162
Ltmp2617:
	.quad	Leh_func_begin29-Ltmp2617
Lset163 = Leh_func_end29-Leh_func_begin29
	.quad	Lset163
	.byte	0
	.byte	4
Lset164 = Ltmp516-Leh_func_begin29
	.long	Lset164
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset165 = Ltmp517-Ltmp516
	.long	Lset165
	.byte	13
	.byte	6
	.align	3
Leh_frame_end29:

	.globl	_atomic_and_64_nv.eh
_atomic_and_64_nv.eh:
Lset166 = Leh_frame_end30-Leh_frame_begin30
	.long	Lset166
Leh_frame_begin30:
Lset167 = Leh_frame_begin30-Leh_frame_common
	.long	Lset167
Ltmp2618:
	.quad	Leh_func_begin30-Ltmp2618
Lset168 = Leh_func_end30-Leh_func_begin30
	.quad	Lset168
	.byte	0
	.byte	4
Lset169 = Ltmp523-Leh_func_begin30
	.long	Lset169
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset170 = Ltmp524-Ltmp523
	.long	Lset170
	.byte	13
	.byte	6
	.byte	4
Lset171 = Ltmp525-Ltmp524
	.long	Lset171
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end30:

	.globl	_atomic_and_ulong_nv.eh
_atomic_and_ulong_nv.eh:
Lset172 = Leh_frame_end31-Leh_frame_begin31
	.long	Lset172
Leh_frame_begin31:
Lset173 = Leh_frame_begin31-Leh_frame_common
	.long	Lset173
Ltmp2619:
	.quad	Leh_func_begin31-Ltmp2619
Lset174 = Leh_func_end31-Leh_func_begin31
	.quad	Lset174
	.byte	0
	.byte	4
Lset175 = Ltmp545-Leh_func_begin31
	.long	Lset175
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset176 = Ltmp546-Ltmp545
	.long	Lset176
	.byte	13
	.byte	6
	.byte	4
Lset177 = Ltmp547-Ltmp546
	.long	Lset177
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end31:

	.globl	_atomic_and_uint_nv.eh
_atomic_and_uint_nv.eh:
Lset178 = Leh_frame_end32-Leh_frame_begin32
	.long	Lset178
Leh_frame_begin32:
Lset179 = Leh_frame_begin32-Leh_frame_common
	.long	Lset179
Ltmp2620:
	.quad	Leh_func_begin32-Ltmp2620
Lset180 = Leh_func_end32-Leh_func_begin32
	.quad	Lset180
	.byte	0
	.byte	4
Lset181 = Ltmp567-Leh_func_begin32
	.long	Lset181
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset182 = Ltmp568-Ltmp567
	.long	Lset182
	.byte	13
	.byte	6
	.byte	4
Lset183 = Ltmp569-Ltmp568
	.long	Lset183
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end32:

	.globl	_atomic_and_32_nv.eh
_atomic_and_32_nv.eh:
Lset184 = Leh_frame_end33-Leh_frame_begin33
	.long	Lset184
Leh_frame_begin33:
Lset185 = Leh_frame_begin33-Leh_frame_common
	.long	Lset185
Ltmp2621:
	.quad	Leh_func_begin33-Ltmp2621
Lset186 = Leh_func_end33-Leh_func_begin33
	.quad	Lset186
	.byte	0
	.byte	4
Lset187 = Ltmp589-Leh_func_begin33
	.long	Lset187
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset188 = Ltmp590-Ltmp589
	.long	Lset188
	.byte	13
	.byte	6
	.byte	4
Lset189 = Ltmp591-Ltmp590
	.long	Lset189
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end33:

	.globl	_atomic_and_ushort_nv.eh
_atomic_and_ushort_nv.eh:
Lset190 = Leh_frame_end34-Leh_frame_begin34
	.long	Lset190
Leh_frame_begin34:
Lset191 = Leh_frame_begin34-Leh_frame_common
	.long	Lset191
Ltmp2622:
	.quad	Leh_func_begin34-Ltmp2622
Lset192 = Leh_func_end34-Leh_func_begin34
	.quad	Lset192
	.byte	0
	.byte	4
Lset193 = Ltmp611-Leh_func_begin34
	.long	Lset193
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset194 = Ltmp612-Ltmp611
	.long	Lset194
	.byte	13
	.byte	6
	.byte	4
Lset195 = Ltmp613-Ltmp612
	.long	Lset195
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end34:

	.globl	_atomic_and_16_nv.eh
_atomic_and_16_nv.eh:
Lset196 = Leh_frame_end35-Leh_frame_begin35
	.long	Lset196
Leh_frame_begin35:
Lset197 = Leh_frame_begin35-Leh_frame_common
	.long	Lset197
Ltmp2623:
	.quad	Leh_func_begin35-Ltmp2623
Lset198 = Leh_func_end35-Leh_func_begin35
	.quad	Lset198
	.byte	0
	.byte	4
Lset199 = Ltmp631-Leh_func_begin35
	.long	Lset199
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset200 = Ltmp632-Ltmp631
	.long	Lset200
	.byte	13
	.byte	6
	.byte	4
Lset201 = Ltmp633-Ltmp632
	.long	Lset201
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end35:

	.globl	_atomic_and_uchar_nv.eh
_atomic_and_uchar_nv.eh:
Lset202 = Leh_frame_end36-Leh_frame_begin36
	.long	Lset202
Leh_frame_begin36:
Lset203 = Leh_frame_begin36-Leh_frame_common
	.long	Lset203
Ltmp2624:
	.quad	Leh_func_begin36-Ltmp2624
Lset204 = Leh_func_end36-Leh_func_begin36
	.quad	Lset204
	.byte	0
	.byte	4
Lset205 = Ltmp651-Leh_func_begin36
	.long	Lset205
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset206 = Ltmp652-Ltmp651
	.long	Lset206
	.byte	13
	.byte	6
	.byte	4
Lset207 = Ltmp653-Ltmp652
	.long	Lset207
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end36:

	.globl	_atomic_and_8_nv.eh
_atomic_and_8_nv.eh:
Lset208 = Leh_frame_end37-Leh_frame_begin37
	.long	Lset208
Leh_frame_begin37:
Lset209 = Leh_frame_begin37-Leh_frame_common
	.long	Lset209
Ltmp2625:
	.quad	Leh_func_begin37-Ltmp2625
Lset210 = Leh_func_end37-Leh_func_begin37
	.quad	Lset210
	.byte	0
	.byte	4
Lset211 = Ltmp671-Leh_func_begin37
	.long	Lset211
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset212 = Ltmp672-Ltmp671
	.long	Lset212
	.byte	13
	.byte	6
	.byte	4
Lset213 = Ltmp673-Ltmp672
	.long	Lset213
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end37:

	.globl	_atomic_and_long_nv.eh
_atomic_and_long_nv.eh:
Lset214 = Leh_frame_end38-Leh_frame_begin38
	.long	Lset214
Leh_frame_begin38:
Lset215 = Leh_frame_begin38-Leh_frame_common
	.long	Lset215
Ltmp2626:
	.quad	Leh_func_begin38-Ltmp2626
Lset216 = Leh_func_end38-Leh_func_begin38
	.quad	Lset216
	.byte	0
	.byte	4
Lset217 = Ltmp691-Leh_func_begin38
	.long	Lset217
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset218 = Ltmp692-Ltmp691
	.long	Lset218
	.byte	13
	.byte	6
	.byte	4
Lset219 = Ltmp693-Ltmp692
	.long	Lset219
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end38:

	.globl	_atomic_or_64_nv.eh
_atomic_or_64_nv.eh:
Lset220 = Leh_frame_end39-Leh_frame_begin39
	.long	Lset220
Leh_frame_begin39:
Lset221 = Leh_frame_begin39-Leh_frame_common
	.long	Lset221
Ltmp2627:
	.quad	Leh_func_begin39-Ltmp2627
Lset222 = Leh_func_end39-Leh_func_begin39
	.quad	Lset222
	.byte	0
	.byte	4
Lset223 = Ltmp713-Leh_func_begin39
	.long	Lset223
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset224 = Ltmp714-Ltmp713
	.long	Lset224
	.byte	13
	.byte	6
	.byte	4
Lset225 = Ltmp715-Ltmp714
	.long	Lset225
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end39:

	.globl	_atomic_or_ulong_nv.eh
_atomic_or_ulong_nv.eh:
Lset226 = Leh_frame_end40-Leh_frame_begin40
	.long	Lset226
Leh_frame_begin40:
Lset227 = Leh_frame_begin40-Leh_frame_common
	.long	Lset227
Ltmp2628:
	.quad	Leh_func_begin40-Ltmp2628
Lset228 = Leh_func_end40-Leh_func_begin40
	.quad	Lset228
	.byte	0
	.byte	4
Lset229 = Ltmp735-Leh_func_begin40
	.long	Lset229
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset230 = Ltmp736-Ltmp735
	.long	Lset230
	.byte	13
	.byte	6
	.byte	4
Lset231 = Ltmp737-Ltmp736
	.long	Lset231
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end40:

	.globl	_atomic_or_uint_nv.eh
_atomic_or_uint_nv.eh:
Lset232 = Leh_frame_end41-Leh_frame_begin41
	.long	Lset232
Leh_frame_begin41:
Lset233 = Leh_frame_begin41-Leh_frame_common
	.long	Lset233
Ltmp2629:
	.quad	Leh_func_begin41-Ltmp2629
Lset234 = Leh_func_end41-Leh_func_begin41
	.quad	Lset234
	.byte	0
	.byte	4
Lset235 = Ltmp757-Leh_func_begin41
	.long	Lset235
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset236 = Ltmp758-Ltmp757
	.long	Lset236
	.byte	13
	.byte	6
	.byte	4
Lset237 = Ltmp759-Ltmp758
	.long	Lset237
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end41:

	.globl	_atomic_or_32_nv.eh
_atomic_or_32_nv.eh:
Lset238 = Leh_frame_end42-Leh_frame_begin42
	.long	Lset238
Leh_frame_begin42:
Lset239 = Leh_frame_begin42-Leh_frame_common
	.long	Lset239
Ltmp2630:
	.quad	Leh_func_begin42-Ltmp2630
Lset240 = Leh_func_end42-Leh_func_begin42
	.quad	Lset240
	.byte	0
	.byte	4
Lset241 = Ltmp779-Leh_func_begin42
	.long	Lset241
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset242 = Ltmp780-Ltmp779
	.long	Lset242
	.byte	13
	.byte	6
	.byte	4
Lset243 = Ltmp781-Ltmp780
	.long	Lset243
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end42:

	.globl	_atomic_or_ushort_nv.eh
_atomic_or_ushort_nv.eh:
Lset244 = Leh_frame_end43-Leh_frame_begin43
	.long	Lset244
Leh_frame_begin43:
Lset245 = Leh_frame_begin43-Leh_frame_common
	.long	Lset245
Ltmp2631:
	.quad	Leh_func_begin43-Ltmp2631
Lset246 = Leh_func_end43-Leh_func_begin43
	.quad	Lset246
	.byte	0
	.byte	4
Lset247 = Ltmp801-Leh_func_begin43
	.long	Lset247
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset248 = Ltmp802-Ltmp801
	.long	Lset248
	.byte	13
	.byte	6
	.byte	4
Lset249 = Ltmp803-Ltmp802
	.long	Lset249
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end43:

	.globl	_atomic_or_16_nv.eh
_atomic_or_16_nv.eh:
Lset250 = Leh_frame_end44-Leh_frame_begin44
	.long	Lset250
Leh_frame_begin44:
Lset251 = Leh_frame_begin44-Leh_frame_common
	.long	Lset251
Ltmp2632:
	.quad	Leh_func_begin44-Ltmp2632
Lset252 = Leh_func_end44-Leh_func_begin44
	.quad	Lset252
	.byte	0
	.byte	4
Lset253 = Ltmp821-Leh_func_begin44
	.long	Lset253
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset254 = Ltmp822-Ltmp821
	.long	Lset254
	.byte	13
	.byte	6
	.byte	4
Lset255 = Ltmp823-Ltmp822
	.long	Lset255
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end44:

	.globl	_atomic_or_uchar_nv.eh
_atomic_or_uchar_nv.eh:
Lset256 = Leh_frame_end45-Leh_frame_begin45
	.long	Lset256
Leh_frame_begin45:
Lset257 = Leh_frame_begin45-Leh_frame_common
	.long	Lset257
Ltmp2633:
	.quad	Leh_func_begin45-Ltmp2633
Lset258 = Leh_func_end45-Leh_func_begin45
	.quad	Lset258
	.byte	0
	.byte	4
Lset259 = Ltmp841-Leh_func_begin45
	.long	Lset259
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset260 = Ltmp842-Ltmp841
	.long	Lset260
	.byte	13
	.byte	6
	.byte	4
Lset261 = Ltmp843-Ltmp842
	.long	Lset261
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end45:

	.globl	_atomic_or_8_nv.eh
_atomic_or_8_nv.eh:
Lset262 = Leh_frame_end46-Leh_frame_begin46
	.long	Lset262
Leh_frame_begin46:
Lset263 = Leh_frame_begin46-Leh_frame_common
	.long	Lset263
Ltmp2634:
	.quad	Leh_func_begin46-Ltmp2634
Lset264 = Leh_func_end46-Leh_func_begin46
	.quad	Lset264
	.byte	0
	.byte	4
Lset265 = Ltmp861-Leh_func_begin46
	.long	Lset265
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset266 = Ltmp862-Ltmp861
	.long	Lset266
	.byte	13
	.byte	6
	.byte	4
Lset267 = Ltmp863-Ltmp862
	.long	Lset267
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end46:

	.globl	_atomic_or_long_nv.eh
_atomic_or_long_nv.eh:
Lset268 = Leh_frame_end47-Leh_frame_begin47
	.long	Lset268
Leh_frame_begin47:
Lset269 = Leh_frame_begin47-Leh_frame_common
	.long	Lset269
Ltmp2635:
	.quad	Leh_func_begin47-Ltmp2635
Lset270 = Leh_func_end47-Leh_func_begin47
	.quad	Lset270
	.byte	0
	.byte	4
Lset271 = Ltmp881-Leh_func_begin47
	.long	Lset271
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset272 = Ltmp882-Ltmp881
	.long	Lset272
	.byte	13
	.byte	6
	.byte	4
Lset273 = Ltmp883-Ltmp882
	.long	Lset273
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end47:

	.globl	_atomic_sub_ptr_nv.eh
_atomic_sub_ptr_nv.eh:
Lset274 = Leh_frame_end48-Leh_frame_begin48
	.long	Lset274
Leh_frame_begin48:
Lset275 = Leh_frame_begin48-Leh_frame_common
	.long	Lset275
Ltmp2636:
	.quad	Leh_func_begin48-Ltmp2636
Lset276 = Leh_func_end48-Leh_func_begin48
	.quad	Lset276
	.byte	0
	.byte	4
Lset277 = Ltmp903-Leh_func_begin48
	.long	Lset277
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset278 = Ltmp904-Ltmp903
	.long	Lset278
	.byte	13
	.byte	6
	.byte	4
Lset279 = Ltmp905-Ltmp904
	.long	Lset279
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end48:

	.globl	_atomic_sub_64_nv.eh
_atomic_sub_64_nv.eh:
Lset280 = Leh_frame_end49-Leh_frame_begin49
	.long	Lset280
Leh_frame_begin49:
Lset281 = Leh_frame_begin49-Leh_frame_common
	.long	Lset281
Ltmp2637:
	.quad	Leh_func_begin49-Ltmp2637
Lset282 = Leh_func_end49-Leh_func_begin49
	.quad	Lset282
	.byte	0
	.byte	4
Lset283 = Ltmp926-Leh_func_begin49
	.long	Lset283
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset284 = Ltmp927-Ltmp926
	.long	Lset284
	.byte	13
	.byte	6
	.byte	4
Lset285 = Ltmp928-Ltmp927
	.long	Lset285
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end49:

	.globl	_atomic_sub_long_nv.eh
_atomic_sub_long_nv.eh:
Lset286 = Leh_frame_end50-Leh_frame_begin50
	.long	Lset286
Leh_frame_begin50:
Lset287 = Leh_frame_begin50-Leh_frame_common
	.long	Lset287
Ltmp2638:
	.quad	Leh_func_begin50-Ltmp2638
Lset288 = Leh_func_end50-Leh_func_begin50
	.quad	Lset288
	.byte	0
	.byte	4
Lset289 = Ltmp948-Leh_func_begin50
	.long	Lset289
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset290 = Ltmp949-Ltmp948
	.long	Lset290
	.byte	13
	.byte	6
	.byte	4
Lset291 = Ltmp950-Ltmp949
	.long	Lset291
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end50:

	.globl	_atomic_sub_int_nv.eh
_atomic_sub_int_nv.eh:
Lset292 = Leh_frame_end51-Leh_frame_begin51
	.long	Lset292
Leh_frame_begin51:
Lset293 = Leh_frame_begin51-Leh_frame_common
	.long	Lset293
Ltmp2639:
	.quad	Leh_func_begin51-Ltmp2639
Lset294 = Leh_func_end51-Leh_func_begin51
	.quad	Lset294
	.byte	0
	.byte	4
Lset295 = Ltmp970-Leh_func_begin51
	.long	Lset295
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset296 = Ltmp971-Ltmp970
	.long	Lset296
	.byte	13
	.byte	6
	.byte	4
Lset297 = Ltmp972-Ltmp971
	.long	Lset297
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end51:

	.globl	_atomic_sub_32_nv.eh
_atomic_sub_32_nv.eh:
Lset298 = Leh_frame_end52-Leh_frame_begin52
	.long	Lset298
Leh_frame_begin52:
Lset299 = Leh_frame_begin52-Leh_frame_common
	.long	Lset299
Ltmp2640:
	.quad	Leh_func_begin52-Ltmp2640
Lset300 = Leh_func_end52-Leh_func_begin52
	.quad	Lset300
	.byte	0
	.byte	4
Lset301 = Ltmp992-Leh_func_begin52
	.long	Lset301
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset302 = Ltmp993-Ltmp992
	.long	Lset302
	.byte	13
	.byte	6
	.byte	4
Lset303 = Ltmp994-Ltmp993
	.long	Lset303
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end52:

	.globl	_atomic_sub_short_nv.eh
_atomic_sub_short_nv.eh:
Lset304 = Leh_frame_end53-Leh_frame_begin53
	.long	Lset304
Leh_frame_begin53:
Lset305 = Leh_frame_begin53-Leh_frame_common
	.long	Lset305
Ltmp2641:
	.quad	Leh_func_begin53-Ltmp2641
Lset306 = Leh_func_end53-Leh_func_begin53
	.quad	Lset306
	.byte	0
	.byte	4
Lset307 = Ltmp1014-Leh_func_begin53
	.long	Lset307
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset308 = Ltmp1015-Ltmp1014
	.long	Lset308
	.byte	13
	.byte	6
	.byte	4
Lset309 = Ltmp1016-Ltmp1015
	.long	Lset309
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end53:

	.globl	_atomic_sub_16_nv.eh
_atomic_sub_16_nv.eh:
Lset310 = Leh_frame_end54-Leh_frame_begin54
	.long	Lset310
Leh_frame_begin54:
Lset311 = Leh_frame_begin54-Leh_frame_common
	.long	Lset311
Ltmp2642:
	.quad	Leh_func_begin54-Ltmp2642
Lset312 = Leh_func_end54-Leh_func_begin54
	.quad	Lset312
	.byte	0
	.byte	4
Lset313 = Ltmp1034-Leh_func_begin54
	.long	Lset313
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset314 = Ltmp1035-Ltmp1034
	.long	Lset314
	.byte	13
	.byte	6
	.byte	4
Lset315 = Ltmp1036-Ltmp1035
	.long	Lset315
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end54:

	.globl	_atomic_sub_char_nv.eh
_atomic_sub_char_nv.eh:
Lset316 = Leh_frame_end55-Leh_frame_begin55
	.long	Lset316
Leh_frame_begin55:
Lset317 = Leh_frame_begin55-Leh_frame_common
	.long	Lset317
Ltmp2643:
	.quad	Leh_func_begin55-Ltmp2643
Lset318 = Leh_func_end55-Leh_func_begin55
	.quad	Lset318
	.byte	0
	.byte	4
Lset319 = Ltmp1054-Leh_func_begin55
	.long	Lset319
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset320 = Ltmp1055-Ltmp1054
	.long	Lset320
	.byte	13
	.byte	6
	.byte	4
Lset321 = Ltmp1056-Ltmp1055
	.long	Lset321
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end55:

	.globl	_atomic_sub_8_nv.eh
_atomic_sub_8_nv.eh:
Lset322 = Leh_frame_end56-Leh_frame_begin56
	.long	Lset322
Leh_frame_begin56:
Lset323 = Leh_frame_begin56-Leh_frame_common
	.long	Lset323
Ltmp2644:
	.quad	Leh_func_begin56-Ltmp2644
Lset324 = Leh_func_end56-Leh_func_begin56
	.quad	Lset324
	.byte	0
	.byte	4
Lset325 = Ltmp1074-Leh_func_begin56
	.long	Lset325
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset326 = Ltmp1075-Ltmp1074
	.long	Lset326
	.byte	13
	.byte	6
	.byte	4
Lset327 = Ltmp1076-Ltmp1075
	.long	Lset327
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end56:

	.globl	_atomic_add_ptr_nv.eh
_atomic_add_ptr_nv.eh:
Lset328 = Leh_frame_end57-Leh_frame_begin57
	.long	Lset328
Leh_frame_begin57:
Lset329 = Leh_frame_begin57-Leh_frame_common
	.long	Lset329
Ltmp2645:
	.quad	Leh_func_begin57-Ltmp2645
Lset330 = Leh_func_end57-Leh_func_begin57
	.quad	Lset330
	.byte	0
	.byte	4
Lset331 = Ltmp1094-Leh_func_begin57
	.long	Lset331
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset332 = Ltmp1095-Ltmp1094
	.long	Lset332
	.byte	13
	.byte	6
	.byte	4
Lset333 = Ltmp1096-Ltmp1095
	.long	Lset333
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end57:

	.globl	_atomic_add_64_nv.eh
_atomic_add_64_nv.eh:
Lset334 = Leh_frame_end58-Leh_frame_begin58
	.long	Lset334
Leh_frame_begin58:
Lset335 = Leh_frame_begin58-Leh_frame_common
	.long	Lset335
Ltmp2646:
	.quad	Leh_func_begin58-Ltmp2646
Lset336 = Leh_func_end58-Leh_func_begin58
	.quad	Lset336
	.byte	0
	.byte	4
Lset337 = Ltmp1117-Leh_func_begin58
	.long	Lset337
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset338 = Ltmp1118-Ltmp1117
	.long	Lset338
	.byte	13
	.byte	6
	.byte	4
Lset339 = Ltmp1119-Ltmp1118
	.long	Lset339
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end58:

	.globl	_atomic_add_long_nv.eh
_atomic_add_long_nv.eh:
Lset340 = Leh_frame_end59-Leh_frame_begin59
	.long	Lset340
Leh_frame_begin59:
Lset341 = Leh_frame_begin59-Leh_frame_common
	.long	Lset341
Ltmp2647:
	.quad	Leh_func_begin59-Ltmp2647
Lset342 = Leh_func_end59-Leh_func_begin59
	.quad	Lset342
	.byte	0
	.byte	4
Lset343 = Ltmp1139-Leh_func_begin59
	.long	Lset343
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset344 = Ltmp1140-Ltmp1139
	.long	Lset344
	.byte	13
	.byte	6
	.byte	4
Lset345 = Ltmp1141-Ltmp1140
	.long	Lset345
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end59:

	.globl	_atomic_add_int_nv.eh
_atomic_add_int_nv.eh:
Lset346 = Leh_frame_end60-Leh_frame_begin60
	.long	Lset346
Leh_frame_begin60:
Lset347 = Leh_frame_begin60-Leh_frame_common
	.long	Lset347
Ltmp2648:
	.quad	Leh_func_begin60-Ltmp2648
Lset348 = Leh_func_end60-Leh_func_begin60
	.quad	Lset348
	.byte	0
	.byte	4
Lset349 = Ltmp1161-Leh_func_begin60
	.long	Lset349
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset350 = Ltmp1162-Ltmp1161
	.long	Lset350
	.byte	13
	.byte	6
	.byte	4
Lset351 = Ltmp1163-Ltmp1162
	.long	Lset351
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end60:

	.globl	_atomic_add_32_nv.eh
_atomic_add_32_nv.eh:
Lset352 = Leh_frame_end61-Leh_frame_begin61
	.long	Lset352
Leh_frame_begin61:
Lset353 = Leh_frame_begin61-Leh_frame_common
	.long	Lset353
Ltmp2649:
	.quad	Leh_func_begin61-Ltmp2649
Lset354 = Leh_func_end61-Leh_func_begin61
	.quad	Lset354
	.byte	0
	.byte	4
Lset355 = Ltmp1183-Leh_func_begin61
	.long	Lset355
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset356 = Ltmp1184-Ltmp1183
	.long	Lset356
	.byte	13
	.byte	6
	.byte	4
Lset357 = Ltmp1185-Ltmp1184
	.long	Lset357
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end61:

	.globl	_atomic_add_short_nv.eh
_atomic_add_short_nv.eh:
Lset358 = Leh_frame_end62-Leh_frame_begin62
	.long	Lset358
Leh_frame_begin62:
Lset359 = Leh_frame_begin62-Leh_frame_common
	.long	Lset359
Ltmp2650:
	.quad	Leh_func_begin62-Ltmp2650
Lset360 = Leh_func_end62-Leh_func_begin62
	.quad	Lset360
	.byte	0
	.byte	4
Lset361 = Ltmp1205-Leh_func_begin62
	.long	Lset361
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset362 = Ltmp1206-Ltmp1205
	.long	Lset362
	.byte	13
	.byte	6
	.byte	4
Lset363 = Ltmp1207-Ltmp1206
	.long	Lset363
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end62:

	.globl	_atomic_add_16_nv.eh
_atomic_add_16_nv.eh:
Lset364 = Leh_frame_end63-Leh_frame_begin63
	.long	Lset364
Leh_frame_begin63:
Lset365 = Leh_frame_begin63-Leh_frame_common
	.long	Lset365
Ltmp2651:
	.quad	Leh_func_begin63-Ltmp2651
Lset366 = Leh_func_end63-Leh_func_begin63
	.quad	Lset366
	.byte	0
	.byte	4
Lset367 = Ltmp1225-Leh_func_begin63
	.long	Lset367
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset368 = Ltmp1226-Ltmp1225
	.long	Lset368
	.byte	13
	.byte	6
	.byte	4
Lset369 = Ltmp1227-Ltmp1226
	.long	Lset369
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end63:

	.globl	_atomic_add_char_nv.eh
_atomic_add_char_nv.eh:
Lset370 = Leh_frame_end64-Leh_frame_begin64
	.long	Lset370
Leh_frame_begin64:
Lset371 = Leh_frame_begin64-Leh_frame_common
	.long	Lset371
Ltmp2652:
	.quad	Leh_func_begin64-Ltmp2652
Lset372 = Leh_func_end64-Leh_func_begin64
	.quad	Lset372
	.byte	0
	.byte	4
Lset373 = Ltmp1245-Leh_func_begin64
	.long	Lset373
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset374 = Ltmp1246-Ltmp1245
	.long	Lset374
	.byte	13
	.byte	6
	.byte	4
Lset375 = Ltmp1247-Ltmp1246
	.long	Lset375
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end64:

	.globl	_atomic_add_8_nv.eh
_atomic_add_8_nv.eh:
Lset376 = Leh_frame_end65-Leh_frame_begin65
	.long	Lset376
Leh_frame_begin65:
Lset377 = Leh_frame_begin65-Leh_frame_common
	.long	Lset377
Ltmp2653:
	.quad	Leh_func_begin65-Ltmp2653
Lset378 = Leh_func_end65-Leh_func_begin65
	.quad	Lset378
	.byte	0
	.byte	4
Lset379 = Ltmp1265-Leh_func_begin65
	.long	Lset379
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset380 = Ltmp1266-Ltmp1265
	.long	Lset380
	.byte	13
	.byte	6
	.byte	4
Lset381 = Ltmp1267-Ltmp1266
	.long	Lset381
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end65:

	.globl	_atomic_dec_64_nv.eh
_atomic_dec_64_nv.eh:
Lset382 = Leh_frame_end66-Leh_frame_begin66
	.long	Lset382
Leh_frame_begin66:
Lset383 = Leh_frame_begin66-Leh_frame_common
	.long	Lset383
Ltmp2654:
	.quad	Leh_func_begin66-Ltmp2654
Lset384 = Leh_func_end66-Leh_func_begin66
	.quad	Lset384
	.byte	0
	.byte	4
Lset385 = Ltmp1285-Leh_func_begin66
	.long	Lset385
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset386 = Ltmp1286-Ltmp1285
	.long	Lset386
	.byte	13
	.byte	6
	.byte	4
Lset387 = Ltmp1287-Ltmp1286
	.long	Lset387
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end66:

	.globl	_atomic_dec_ulong_nv.eh
_atomic_dec_ulong_nv.eh:
Lset388 = Leh_frame_end67-Leh_frame_begin67
	.long	Lset388
Leh_frame_begin67:
Lset389 = Leh_frame_begin67-Leh_frame_common
	.long	Lset389
Ltmp2655:
	.quad	Leh_func_begin67-Ltmp2655
Lset390 = Leh_func_end67-Leh_func_begin67
	.quad	Lset390
	.byte	0
	.byte	4
Lset391 = Ltmp1305-Leh_func_begin67
	.long	Lset391
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset392 = Ltmp1306-Ltmp1305
	.long	Lset392
	.byte	13
	.byte	6
	.byte	4
Lset393 = Ltmp1307-Ltmp1306
	.long	Lset393
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end67:

	.globl	_atomic_dec_uint_nv.eh
_atomic_dec_uint_nv.eh:
Lset394 = Leh_frame_end68-Leh_frame_begin68
	.long	Lset394
Leh_frame_begin68:
Lset395 = Leh_frame_begin68-Leh_frame_common
	.long	Lset395
Ltmp2656:
	.quad	Leh_func_begin68-Ltmp2656
Lset396 = Leh_func_end68-Leh_func_begin68
	.quad	Lset396
	.byte	0
	.byte	4
Lset397 = Ltmp1325-Leh_func_begin68
	.long	Lset397
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset398 = Ltmp1326-Ltmp1325
	.long	Lset398
	.byte	13
	.byte	6
	.byte	4
Lset399 = Ltmp1327-Ltmp1326
	.long	Lset399
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end68:

	.globl	_atomic_dec_32_nv.eh
_atomic_dec_32_nv.eh:
Lset400 = Leh_frame_end69-Leh_frame_begin69
	.long	Lset400
Leh_frame_begin69:
Lset401 = Leh_frame_begin69-Leh_frame_common
	.long	Lset401
Ltmp2657:
	.quad	Leh_func_begin69-Ltmp2657
Lset402 = Leh_func_end69-Leh_func_begin69
	.quad	Lset402
	.byte	0
	.byte	4
Lset403 = Ltmp1345-Leh_func_begin69
	.long	Lset403
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset404 = Ltmp1346-Ltmp1345
	.long	Lset404
	.byte	13
	.byte	6
	.byte	4
Lset405 = Ltmp1347-Ltmp1346
	.long	Lset405
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end69:

	.globl	_atomic_dec_ushort_nv.eh
_atomic_dec_ushort_nv.eh:
Lset406 = Leh_frame_end70-Leh_frame_begin70
	.long	Lset406
Leh_frame_begin70:
Lset407 = Leh_frame_begin70-Leh_frame_common
	.long	Lset407
Ltmp2658:
	.quad	Leh_func_begin70-Ltmp2658
Lset408 = Leh_func_end70-Leh_func_begin70
	.quad	Lset408
	.byte	0
	.byte	4
Lset409 = Ltmp1365-Leh_func_begin70
	.long	Lset409
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset410 = Ltmp1366-Ltmp1365
	.long	Lset410
	.byte	13
	.byte	6
	.byte	4
Lset411 = Ltmp1367-Ltmp1366
	.long	Lset411
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end70:

	.globl	_atomic_dec_16_nv.eh
_atomic_dec_16_nv.eh:
Lset412 = Leh_frame_end71-Leh_frame_begin71
	.long	Lset412
Leh_frame_begin71:
Lset413 = Leh_frame_begin71-Leh_frame_common
	.long	Lset413
Ltmp2659:
	.quad	Leh_func_begin71-Ltmp2659
Lset414 = Leh_func_end71-Leh_func_begin71
	.quad	Lset414
	.byte	0
	.byte	4
Lset415 = Ltmp1385-Leh_func_begin71
	.long	Lset415
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset416 = Ltmp1386-Ltmp1385
	.long	Lset416
	.byte	13
	.byte	6
	.byte	4
Lset417 = Ltmp1387-Ltmp1386
	.long	Lset417
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end71:

	.globl	_atomic_dec_uchar_nv.eh
_atomic_dec_uchar_nv.eh:
Lset418 = Leh_frame_end72-Leh_frame_begin72
	.long	Lset418
Leh_frame_begin72:
Lset419 = Leh_frame_begin72-Leh_frame_common
	.long	Lset419
Ltmp2660:
	.quad	Leh_func_begin72-Ltmp2660
Lset420 = Leh_func_end72-Leh_func_begin72
	.quad	Lset420
	.byte	0
	.byte	4
Lset421 = Ltmp1405-Leh_func_begin72
	.long	Lset421
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset422 = Ltmp1406-Ltmp1405
	.long	Lset422
	.byte	13
	.byte	6
	.byte	4
Lset423 = Ltmp1407-Ltmp1406
	.long	Lset423
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end72:

	.globl	_atomic_dec_8_nv.eh
_atomic_dec_8_nv.eh:
Lset424 = Leh_frame_end73-Leh_frame_begin73
	.long	Lset424
Leh_frame_begin73:
Lset425 = Leh_frame_begin73-Leh_frame_common
	.long	Lset425
Ltmp2661:
	.quad	Leh_func_begin73-Ltmp2661
Lset426 = Leh_func_end73-Leh_func_begin73
	.quad	Lset426
	.byte	0
	.byte	4
Lset427 = Ltmp1425-Leh_func_begin73
	.long	Lset427
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset428 = Ltmp1426-Ltmp1425
	.long	Lset428
	.byte	13
	.byte	6
	.byte	4
Lset429 = Ltmp1427-Ltmp1426
	.long	Lset429
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end73:

	.globl	_atomic_dec_long_nv.eh
_atomic_dec_long_nv.eh:
Lset430 = Leh_frame_end74-Leh_frame_begin74
	.long	Lset430
Leh_frame_begin74:
Lset431 = Leh_frame_begin74-Leh_frame_common
	.long	Lset431
Ltmp2662:
	.quad	Leh_func_begin74-Ltmp2662
Lset432 = Leh_func_end74-Leh_func_begin74
	.quad	Lset432
	.byte	0
	.byte	4
Lset433 = Ltmp1445-Leh_func_begin74
	.long	Lset433
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset434 = Ltmp1446-Ltmp1445
	.long	Lset434
	.byte	13
	.byte	6
	.byte	4
Lset435 = Ltmp1447-Ltmp1446
	.long	Lset435
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end74:

	.globl	_atomic_inc_64_nv.eh
_atomic_inc_64_nv.eh:
Lset436 = Leh_frame_end75-Leh_frame_begin75
	.long	Lset436
Leh_frame_begin75:
Lset437 = Leh_frame_begin75-Leh_frame_common
	.long	Lset437
Ltmp2663:
	.quad	Leh_func_begin75-Ltmp2663
Lset438 = Leh_func_end75-Leh_func_begin75
	.quad	Lset438
	.byte	0
	.byte	4
Lset439 = Ltmp1465-Leh_func_begin75
	.long	Lset439
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset440 = Ltmp1466-Ltmp1465
	.long	Lset440
	.byte	13
	.byte	6
	.byte	4
Lset441 = Ltmp1467-Ltmp1466
	.long	Lset441
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end75:

	.globl	_atomic_inc_ulong_nv.eh
_atomic_inc_ulong_nv.eh:
Lset442 = Leh_frame_end76-Leh_frame_begin76
	.long	Lset442
Leh_frame_begin76:
Lset443 = Leh_frame_begin76-Leh_frame_common
	.long	Lset443
Ltmp2664:
	.quad	Leh_func_begin76-Ltmp2664
Lset444 = Leh_func_end76-Leh_func_begin76
	.quad	Lset444
	.byte	0
	.byte	4
Lset445 = Ltmp1485-Leh_func_begin76
	.long	Lset445
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset446 = Ltmp1486-Ltmp1485
	.long	Lset446
	.byte	13
	.byte	6
	.byte	4
Lset447 = Ltmp1487-Ltmp1486
	.long	Lset447
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end76:

	.globl	_atomic_inc_uint_nv.eh
_atomic_inc_uint_nv.eh:
Lset448 = Leh_frame_end77-Leh_frame_begin77
	.long	Lset448
Leh_frame_begin77:
Lset449 = Leh_frame_begin77-Leh_frame_common
	.long	Lset449
Ltmp2665:
	.quad	Leh_func_begin77-Ltmp2665
Lset450 = Leh_func_end77-Leh_func_begin77
	.quad	Lset450
	.byte	0
	.byte	4
Lset451 = Ltmp1505-Leh_func_begin77
	.long	Lset451
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset452 = Ltmp1506-Ltmp1505
	.long	Lset452
	.byte	13
	.byte	6
	.byte	4
Lset453 = Ltmp1507-Ltmp1506
	.long	Lset453
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end77:

	.globl	_atomic_inc_32_nv.eh
_atomic_inc_32_nv.eh:
Lset454 = Leh_frame_end78-Leh_frame_begin78
	.long	Lset454
Leh_frame_begin78:
Lset455 = Leh_frame_begin78-Leh_frame_common
	.long	Lset455
Ltmp2666:
	.quad	Leh_func_begin78-Ltmp2666
Lset456 = Leh_func_end78-Leh_func_begin78
	.quad	Lset456
	.byte	0
	.byte	4
Lset457 = Ltmp1525-Leh_func_begin78
	.long	Lset457
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset458 = Ltmp1526-Ltmp1525
	.long	Lset458
	.byte	13
	.byte	6
	.byte	4
Lset459 = Ltmp1527-Ltmp1526
	.long	Lset459
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end78:

	.globl	_atomic_inc_ushort_nv.eh
_atomic_inc_ushort_nv.eh:
Lset460 = Leh_frame_end79-Leh_frame_begin79
	.long	Lset460
Leh_frame_begin79:
Lset461 = Leh_frame_begin79-Leh_frame_common
	.long	Lset461
Ltmp2667:
	.quad	Leh_func_begin79-Ltmp2667
Lset462 = Leh_func_end79-Leh_func_begin79
	.quad	Lset462
	.byte	0
	.byte	4
Lset463 = Ltmp1545-Leh_func_begin79
	.long	Lset463
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset464 = Ltmp1546-Ltmp1545
	.long	Lset464
	.byte	13
	.byte	6
	.byte	4
Lset465 = Ltmp1547-Ltmp1546
	.long	Lset465
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end79:

	.globl	_atomic_inc_16_nv.eh
_atomic_inc_16_nv.eh:
Lset466 = Leh_frame_end80-Leh_frame_begin80
	.long	Lset466
Leh_frame_begin80:
Lset467 = Leh_frame_begin80-Leh_frame_common
	.long	Lset467
Ltmp2668:
	.quad	Leh_func_begin80-Ltmp2668
Lset468 = Leh_func_end80-Leh_func_begin80
	.quad	Lset468
	.byte	0
	.byte	4
Lset469 = Ltmp1565-Leh_func_begin80
	.long	Lset469
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset470 = Ltmp1566-Ltmp1565
	.long	Lset470
	.byte	13
	.byte	6
	.byte	4
Lset471 = Ltmp1567-Ltmp1566
	.long	Lset471
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end80:

	.globl	_atomic_inc_uchar_nv.eh
_atomic_inc_uchar_nv.eh:
Lset472 = Leh_frame_end81-Leh_frame_begin81
	.long	Lset472
Leh_frame_begin81:
Lset473 = Leh_frame_begin81-Leh_frame_common
	.long	Lset473
Ltmp2669:
	.quad	Leh_func_begin81-Ltmp2669
Lset474 = Leh_func_end81-Leh_func_begin81
	.quad	Lset474
	.byte	0
	.byte	4
Lset475 = Ltmp1585-Leh_func_begin81
	.long	Lset475
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset476 = Ltmp1586-Ltmp1585
	.long	Lset476
	.byte	13
	.byte	6
	.byte	4
Lset477 = Ltmp1587-Ltmp1586
	.long	Lset477
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end81:

	.globl	_atomic_inc_8_nv.eh
_atomic_inc_8_nv.eh:
Lset478 = Leh_frame_end82-Leh_frame_begin82
	.long	Lset478
Leh_frame_begin82:
Lset479 = Leh_frame_begin82-Leh_frame_common
	.long	Lset479
Ltmp2670:
	.quad	Leh_func_begin82-Ltmp2670
Lset480 = Leh_func_end82-Leh_func_begin82
	.quad	Lset480
	.byte	0
	.byte	4
Lset481 = Ltmp1605-Leh_func_begin82
	.long	Lset481
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset482 = Ltmp1606-Ltmp1605
	.long	Lset482
	.byte	13
	.byte	6
	.byte	4
Lset483 = Ltmp1607-Ltmp1606
	.long	Lset483
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end82:

	.globl	_atomic_inc_long_nv.eh
_atomic_inc_long_nv.eh:
Lset484 = Leh_frame_end83-Leh_frame_begin83
	.long	Lset484
Leh_frame_begin83:
Lset485 = Leh_frame_begin83-Leh_frame_common
	.long	Lset485
Ltmp2671:
	.quad	Leh_func_begin83-Ltmp2671
Lset486 = Leh_func_end83-Leh_func_begin83
	.quad	Lset486
	.byte	0
	.byte	4
Lset487 = Ltmp1625-Leh_func_begin83
	.long	Lset487
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset488 = Ltmp1626-Ltmp1625
	.long	Lset488
	.byte	13
	.byte	6
	.byte	4
Lset489 = Ltmp1627-Ltmp1626
	.long	Lset489
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end83:

	.globl	_atomic_and_64.eh
_atomic_and_64.eh:
Lset490 = Leh_frame_end84-Leh_frame_begin84
	.long	Lset490
Leh_frame_begin84:
Lset491 = Leh_frame_begin84-Leh_frame_common
	.long	Lset491
Ltmp2672:
	.quad	Leh_func_begin84-Ltmp2672
Lset492 = Leh_func_end84-Leh_func_begin84
	.quad	Lset492
	.byte	0
	.byte	4
Lset493 = Ltmp1645-Leh_func_begin84
	.long	Lset493
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset494 = Ltmp1646-Ltmp1645
	.long	Lset494
	.byte	13
	.byte	6
	.byte	4
Lset495 = Ltmp1647-Ltmp1646
	.long	Lset495
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end84:

	.globl	_atomic_and_ulong.eh
_atomic_and_ulong.eh:
Lset496 = Leh_frame_end85-Leh_frame_begin85
	.long	Lset496
Leh_frame_begin85:
Lset497 = Leh_frame_begin85-Leh_frame_common
	.long	Lset497
Ltmp2673:
	.quad	Leh_func_begin85-Ltmp2673
Lset498 = Leh_func_end85-Leh_func_begin85
	.quad	Lset498
	.byte	0
	.byte	4
Lset499 = Ltmp1664-Leh_func_begin85
	.long	Lset499
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset500 = Ltmp1665-Ltmp1664
	.long	Lset500
	.byte	13
	.byte	6
	.byte	4
Lset501 = Ltmp1666-Ltmp1665
	.long	Lset501
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end85:

	.globl	_atomic_and_long.eh
_atomic_and_long.eh:
Lset502 = Leh_frame_end86-Leh_frame_begin86
	.long	Lset502
Leh_frame_begin86:
Lset503 = Leh_frame_begin86-Leh_frame_common
	.long	Lset503
Ltmp2674:
	.quad	Leh_func_begin86-Ltmp2674
Lset504 = Leh_func_end86-Leh_func_begin86
	.quad	Lset504
	.byte	0
	.byte	4
Lset505 = Ltmp1683-Leh_func_begin86
	.long	Lset505
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset506 = Ltmp1684-Ltmp1683
	.long	Lset506
	.byte	13
	.byte	6
	.align	3
Leh_frame_end86:

	.globl	_atomic_and_uint.eh
_atomic_and_uint.eh:
Lset507 = Leh_frame_end87-Leh_frame_begin87
	.long	Lset507
Leh_frame_begin87:
Lset508 = Leh_frame_begin87-Leh_frame_common
	.long	Lset508
Ltmp2675:
	.quad	Leh_func_begin87-Ltmp2675
Lset509 = Leh_func_end87-Leh_func_begin87
	.quad	Lset509
	.byte	0
	.byte	4
Lset510 = Ltmp1692-Leh_func_begin87
	.long	Lset510
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset511 = Ltmp1693-Ltmp1692
	.long	Lset511
	.byte	13
	.byte	6
	.byte	4
Lset512 = Ltmp1694-Ltmp1693
	.long	Lset512
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end87:

	.globl	_atomic_and_32.eh
_atomic_and_32.eh:
Lset513 = Leh_frame_end88-Leh_frame_begin88
	.long	Lset513
Leh_frame_begin88:
Lset514 = Leh_frame_begin88-Leh_frame_common
	.long	Lset514
Ltmp2676:
	.quad	Leh_func_begin88-Ltmp2676
Lset515 = Leh_func_end88-Leh_func_begin88
	.quad	Lset515
	.byte	0
	.byte	4
Lset516 = Ltmp1711-Leh_func_begin88
	.long	Lset516
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset517 = Ltmp1712-Ltmp1711
	.long	Lset517
	.byte	13
	.byte	6
	.byte	4
Lset518 = Ltmp1713-Ltmp1712
	.long	Lset518
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end88:

	.globl	_atomic_and_ushort.eh
_atomic_and_ushort.eh:
Lset519 = Leh_frame_end89-Leh_frame_begin89
	.long	Lset519
Leh_frame_begin89:
Lset520 = Leh_frame_begin89-Leh_frame_common
	.long	Lset520
Ltmp2677:
	.quad	Leh_func_begin89-Ltmp2677
Lset521 = Leh_func_end89-Leh_func_begin89
	.quad	Lset521
	.byte	0
	.byte	4
Lset522 = Ltmp1730-Leh_func_begin89
	.long	Lset522
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset523 = Ltmp1731-Ltmp1730
	.long	Lset523
	.byte	13
	.byte	6
	.byte	4
Lset524 = Ltmp1732-Ltmp1731
	.long	Lset524
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end89:

	.globl	_atomic_and_16.eh
_atomic_and_16.eh:
Lset525 = Leh_frame_end90-Leh_frame_begin90
	.long	Lset525
Leh_frame_begin90:
Lset526 = Leh_frame_begin90-Leh_frame_common
	.long	Lset526
Ltmp2678:
	.quad	Leh_func_begin90-Ltmp2678
Lset527 = Leh_func_end90-Leh_func_begin90
	.quad	Lset527
	.byte	0
	.byte	4
Lset528 = Ltmp1747-Leh_func_begin90
	.long	Lset528
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset529 = Ltmp1748-Ltmp1747
	.long	Lset529
	.byte	13
	.byte	6
	.byte	4
Lset530 = Ltmp1749-Ltmp1748
	.long	Lset530
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end90:

	.globl	_atomic_and_uchar.eh
_atomic_and_uchar.eh:
Lset531 = Leh_frame_end91-Leh_frame_begin91
	.long	Lset531
Leh_frame_begin91:
Lset532 = Leh_frame_begin91-Leh_frame_common
	.long	Lset532
Ltmp2679:
	.quad	Leh_func_begin91-Ltmp2679
Lset533 = Leh_func_end91-Leh_func_begin91
	.quad	Lset533
	.byte	0
	.byte	4
Lset534 = Ltmp1764-Leh_func_begin91
	.long	Lset534
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset535 = Ltmp1765-Ltmp1764
	.long	Lset535
	.byte	13
	.byte	6
	.byte	4
Lset536 = Ltmp1766-Ltmp1765
	.long	Lset536
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end91:

	.globl	_atomic_and_8.eh
_atomic_and_8.eh:
Lset537 = Leh_frame_end92-Leh_frame_begin92
	.long	Lset537
Leh_frame_begin92:
Lset538 = Leh_frame_begin92-Leh_frame_common
	.long	Lset538
Ltmp2680:
	.quad	Leh_func_begin92-Ltmp2680
Lset539 = Leh_func_end92-Leh_func_begin92
	.quad	Lset539
	.byte	0
	.byte	4
Lset540 = Ltmp1781-Leh_func_begin92
	.long	Lset540
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset541 = Ltmp1782-Ltmp1781
	.long	Lset541
	.byte	13
	.byte	6
	.byte	4
Lset542 = Ltmp1783-Ltmp1782
	.long	Lset542
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end92:

	.globl	_atomic_or_64.eh
_atomic_or_64.eh:
Lset543 = Leh_frame_end93-Leh_frame_begin93
	.long	Lset543
Leh_frame_begin93:
Lset544 = Leh_frame_begin93-Leh_frame_common
	.long	Lset544
Ltmp2681:
	.quad	Leh_func_begin93-Ltmp2681
Lset545 = Leh_func_end93-Leh_func_begin93
	.quad	Lset545
	.byte	0
	.byte	4
Lset546 = Ltmp1798-Leh_func_begin93
	.long	Lset546
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset547 = Ltmp1799-Ltmp1798
	.long	Lset547
	.byte	13
	.byte	6
	.byte	4
Lset548 = Ltmp1800-Ltmp1799
	.long	Lset548
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end93:

	.globl	_atomic_or_ulong.eh
_atomic_or_ulong.eh:
Lset549 = Leh_frame_end94-Leh_frame_begin94
	.long	Lset549
Leh_frame_begin94:
Lset550 = Leh_frame_begin94-Leh_frame_common
	.long	Lset550
Ltmp2682:
	.quad	Leh_func_begin94-Ltmp2682
Lset551 = Leh_func_end94-Leh_func_begin94
	.quad	Lset551
	.byte	0
	.byte	4
Lset552 = Ltmp1817-Leh_func_begin94
	.long	Lset552
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset553 = Ltmp1818-Ltmp1817
	.long	Lset553
	.byte	13
	.byte	6
	.byte	4
Lset554 = Ltmp1819-Ltmp1818
	.long	Lset554
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end94:

	.globl	_atomic_or_long.eh
_atomic_or_long.eh:
Lset555 = Leh_frame_end95-Leh_frame_begin95
	.long	Lset555
Leh_frame_begin95:
Lset556 = Leh_frame_begin95-Leh_frame_common
	.long	Lset556
Ltmp2683:
	.quad	Leh_func_begin95-Ltmp2683
Lset557 = Leh_func_end95-Leh_func_begin95
	.quad	Lset557
	.byte	0
	.byte	4
Lset558 = Ltmp1836-Leh_func_begin95
	.long	Lset558
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset559 = Ltmp1837-Ltmp1836
	.long	Lset559
	.byte	13
	.byte	6
	.align	3
Leh_frame_end95:

	.globl	_atomic_or_uint.eh
_atomic_or_uint.eh:
Lset560 = Leh_frame_end96-Leh_frame_begin96
	.long	Lset560
Leh_frame_begin96:
Lset561 = Leh_frame_begin96-Leh_frame_common
	.long	Lset561
Ltmp2684:
	.quad	Leh_func_begin96-Ltmp2684
Lset562 = Leh_func_end96-Leh_func_begin96
	.quad	Lset562
	.byte	0
	.byte	4
Lset563 = Ltmp1845-Leh_func_begin96
	.long	Lset563
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset564 = Ltmp1846-Ltmp1845
	.long	Lset564
	.byte	13
	.byte	6
	.byte	4
Lset565 = Ltmp1847-Ltmp1846
	.long	Lset565
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end96:

	.globl	_atomic_or_32.eh
_atomic_or_32.eh:
Lset566 = Leh_frame_end97-Leh_frame_begin97
	.long	Lset566
Leh_frame_begin97:
Lset567 = Leh_frame_begin97-Leh_frame_common
	.long	Lset567
Ltmp2685:
	.quad	Leh_func_begin97-Ltmp2685
Lset568 = Leh_func_end97-Leh_func_begin97
	.quad	Lset568
	.byte	0
	.byte	4
Lset569 = Ltmp1864-Leh_func_begin97
	.long	Lset569
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset570 = Ltmp1865-Ltmp1864
	.long	Lset570
	.byte	13
	.byte	6
	.byte	4
Lset571 = Ltmp1866-Ltmp1865
	.long	Lset571
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end97:

	.globl	_atomic_or_ushort.eh
_atomic_or_ushort.eh:
Lset572 = Leh_frame_end98-Leh_frame_begin98
	.long	Lset572
Leh_frame_begin98:
Lset573 = Leh_frame_begin98-Leh_frame_common
	.long	Lset573
Ltmp2686:
	.quad	Leh_func_begin98-Ltmp2686
Lset574 = Leh_func_end98-Leh_func_begin98
	.quad	Lset574
	.byte	0
	.byte	4
Lset575 = Ltmp1883-Leh_func_begin98
	.long	Lset575
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset576 = Ltmp1884-Ltmp1883
	.long	Lset576
	.byte	13
	.byte	6
	.byte	4
Lset577 = Ltmp1885-Ltmp1884
	.long	Lset577
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end98:

	.globl	_atomic_or_16.eh
_atomic_or_16.eh:
Lset578 = Leh_frame_end99-Leh_frame_begin99
	.long	Lset578
Leh_frame_begin99:
Lset579 = Leh_frame_begin99-Leh_frame_common
	.long	Lset579
Ltmp2687:
	.quad	Leh_func_begin99-Ltmp2687
Lset580 = Leh_func_end99-Leh_func_begin99
	.quad	Lset580
	.byte	0
	.byte	4
Lset581 = Ltmp1900-Leh_func_begin99
	.long	Lset581
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset582 = Ltmp1901-Ltmp1900
	.long	Lset582
	.byte	13
	.byte	6
	.byte	4
Lset583 = Ltmp1902-Ltmp1901
	.long	Lset583
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end99:

	.globl	_atomic_or_uchar.eh
_atomic_or_uchar.eh:
Lset584 = Leh_frame_end100-Leh_frame_begin100
	.long	Lset584
Leh_frame_begin100:
Lset585 = Leh_frame_begin100-Leh_frame_common
	.long	Lset585
Ltmp2688:
	.quad	Leh_func_begin100-Ltmp2688
Lset586 = Leh_func_end100-Leh_func_begin100
	.quad	Lset586
	.byte	0
	.byte	4
Lset587 = Ltmp1917-Leh_func_begin100
	.long	Lset587
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset588 = Ltmp1918-Ltmp1917
	.long	Lset588
	.byte	13
	.byte	6
	.byte	4
Lset589 = Ltmp1919-Ltmp1918
	.long	Lset589
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end100:

	.globl	_atomic_or_8.eh
_atomic_or_8.eh:
Lset590 = Leh_frame_end101-Leh_frame_begin101
	.long	Lset590
Leh_frame_begin101:
Lset591 = Leh_frame_begin101-Leh_frame_common
	.long	Lset591
Ltmp2689:
	.quad	Leh_func_begin101-Ltmp2689
Lset592 = Leh_func_end101-Leh_func_begin101
	.quad	Lset592
	.byte	0
	.byte	4
Lset593 = Ltmp1934-Leh_func_begin101
	.long	Lset593
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset594 = Ltmp1935-Ltmp1934
	.long	Lset594
	.byte	13
	.byte	6
	.byte	4
Lset595 = Ltmp1936-Ltmp1935
	.long	Lset595
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end101:

	.globl	_atomic_sub_ptr.eh
_atomic_sub_ptr.eh:
Lset596 = Leh_frame_end102-Leh_frame_begin102
	.long	Lset596
Leh_frame_begin102:
Lset597 = Leh_frame_begin102-Leh_frame_common
	.long	Lset597
Ltmp2690:
	.quad	Leh_func_begin102-Ltmp2690
Lset598 = Leh_func_end102-Leh_func_begin102
	.quad	Lset598
	.byte	0
	.byte	4
Lset599 = Ltmp1951-Leh_func_begin102
	.long	Lset599
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset600 = Ltmp1952-Ltmp1951
	.long	Lset600
	.byte	13
	.byte	6
	.byte	4
Lset601 = Ltmp1953-Ltmp1952
	.long	Lset601
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end102:

	.globl	_atomic_sub_64.eh
_atomic_sub_64.eh:
Lset602 = Leh_frame_end103-Leh_frame_begin103
	.long	Lset602
Leh_frame_begin103:
Lset603 = Leh_frame_begin103-Leh_frame_common
	.long	Lset603
Ltmp2691:
	.quad	Leh_func_begin103-Ltmp2691
Lset604 = Leh_func_end103-Leh_func_begin103
	.quad	Lset604
	.byte	0
	.byte	4
Lset605 = Ltmp1973-Leh_func_begin103
	.long	Lset605
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset606 = Ltmp1974-Ltmp1973
	.long	Lset606
	.byte	13
	.byte	6
	.byte	4
Lset607 = Ltmp1975-Ltmp1974
	.long	Lset607
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end103:

	.globl	_atomic_sub_long.eh
_atomic_sub_long.eh:
Lset608 = Leh_frame_end104-Leh_frame_begin104
	.long	Lset608
Leh_frame_begin104:
Lset609 = Leh_frame_begin104-Leh_frame_common
	.long	Lset609
Ltmp2692:
	.quad	Leh_func_begin104-Ltmp2692
Lset610 = Leh_func_end104-Leh_func_begin104
	.quad	Lset610
	.byte	0
	.byte	4
Lset611 = Ltmp1992-Leh_func_begin104
	.long	Lset611
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset612 = Ltmp1993-Ltmp1992
	.long	Lset612
	.byte	13
	.byte	6
	.byte	4
Lset613 = Ltmp1994-Ltmp1993
	.long	Lset613
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end104:

	.globl	_atomic_sub_int.eh
_atomic_sub_int.eh:
Lset614 = Leh_frame_end105-Leh_frame_begin105
	.long	Lset614
Leh_frame_begin105:
Lset615 = Leh_frame_begin105-Leh_frame_common
	.long	Lset615
Ltmp2693:
	.quad	Leh_func_begin105-Ltmp2693
Lset616 = Leh_func_end105-Leh_func_begin105
	.quad	Lset616
	.byte	0
	.byte	4
Lset617 = Ltmp2011-Leh_func_begin105
	.long	Lset617
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset618 = Ltmp2012-Ltmp2011
	.long	Lset618
	.byte	13
	.byte	6
	.byte	4
Lset619 = Ltmp2013-Ltmp2012
	.long	Lset619
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end105:

	.globl	_atomic_sub_32.eh
_atomic_sub_32.eh:
Lset620 = Leh_frame_end106-Leh_frame_begin106
	.long	Lset620
Leh_frame_begin106:
Lset621 = Leh_frame_begin106-Leh_frame_common
	.long	Lset621
Ltmp2694:
	.quad	Leh_func_begin106-Ltmp2694
Lset622 = Leh_func_end106-Leh_func_begin106
	.quad	Lset622
	.byte	0
	.byte	4
Lset623 = Ltmp2030-Leh_func_begin106
	.long	Lset623
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset624 = Ltmp2031-Ltmp2030
	.long	Lset624
	.byte	13
	.byte	6
	.byte	4
Lset625 = Ltmp2032-Ltmp2031
	.long	Lset625
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end106:

	.globl	_atomic_sub_short.eh
_atomic_sub_short.eh:
Lset626 = Leh_frame_end107-Leh_frame_begin107
	.long	Lset626
Leh_frame_begin107:
Lset627 = Leh_frame_begin107-Leh_frame_common
	.long	Lset627
Ltmp2695:
	.quad	Leh_func_begin107-Ltmp2695
Lset628 = Leh_func_end107-Leh_func_begin107
	.quad	Lset628
	.byte	0
	.byte	4
Lset629 = Ltmp2049-Leh_func_begin107
	.long	Lset629
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset630 = Ltmp2050-Ltmp2049
	.long	Lset630
	.byte	13
	.byte	6
	.byte	4
Lset631 = Ltmp2051-Ltmp2050
	.long	Lset631
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end107:

	.globl	_atomic_sub_16.eh
_atomic_sub_16.eh:
Lset632 = Leh_frame_end108-Leh_frame_begin108
	.long	Lset632
Leh_frame_begin108:
Lset633 = Leh_frame_begin108-Leh_frame_common
	.long	Lset633
Ltmp2696:
	.quad	Leh_func_begin108-Ltmp2696
Lset634 = Leh_func_end108-Leh_func_begin108
	.quad	Lset634
	.byte	0
	.byte	4
Lset635 = Ltmp2066-Leh_func_begin108
	.long	Lset635
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset636 = Ltmp2067-Ltmp2066
	.long	Lset636
	.byte	13
	.byte	6
	.byte	4
Lset637 = Ltmp2068-Ltmp2067
	.long	Lset637
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end108:

	.globl	_atomic_sub_char.eh
_atomic_sub_char.eh:
Lset638 = Leh_frame_end109-Leh_frame_begin109
	.long	Lset638
Leh_frame_begin109:
Lset639 = Leh_frame_begin109-Leh_frame_common
	.long	Lset639
Ltmp2697:
	.quad	Leh_func_begin109-Ltmp2697
Lset640 = Leh_func_end109-Leh_func_begin109
	.quad	Lset640
	.byte	0
	.byte	4
Lset641 = Ltmp2083-Leh_func_begin109
	.long	Lset641
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset642 = Ltmp2084-Ltmp2083
	.long	Lset642
	.byte	13
	.byte	6
	.byte	4
Lset643 = Ltmp2085-Ltmp2084
	.long	Lset643
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end109:

	.globl	_atomic_sub_8.eh
_atomic_sub_8.eh:
Lset644 = Leh_frame_end110-Leh_frame_begin110
	.long	Lset644
Leh_frame_begin110:
Lset645 = Leh_frame_begin110-Leh_frame_common
	.long	Lset645
Ltmp2698:
	.quad	Leh_func_begin110-Ltmp2698
Lset646 = Leh_func_end110-Leh_func_begin110
	.quad	Lset646
	.byte	0
	.byte	4
Lset647 = Ltmp2100-Leh_func_begin110
	.long	Lset647
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset648 = Ltmp2101-Ltmp2100
	.long	Lset648
	.byte	13
	.byte	6
	.byte	4
Lset649 = Ltmp2102-Ltmp2101
	.long	Lset649
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end110:

	.globl	_atomic_add_ptr.eh
_atomic_add_ptr.eh:
Lset650 = Leh_frame_end111-Leh_frame_begin111
	.long	Lset650
Leh_frame_begin111:
Lset651 = Leh_frame_begin111-Leh_frame_common
	.long	Lset651
Ltmp2699:
	.quad	Leh_func_begin111-Ltmp2699
Lset652 = Leh_func_end111-Leh_func_begin111
	.quad	Lset652
	.byte	0
	.byte	4
Lset653 = Ltmp2117-Leh_func_begin111
	.long	Lset653
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset654 = Ltmp2118-Ltmp2117
	.long	Lset654
	.byte	13
	.byte	6
	.byte	4
Lset655 = Ltmp2119-Ltmp2118
	.long	Lset655
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end111:

	.globl	_atomic_add_64.eh
_atomic_add_64.eh:
Lset656 = Leh_frame_end112-Leh_frame_begin112
	.long	Lset656
Leh_frame_begin112:
Lset657 = Leh_frame_begin112-Leh_frame_common
	.long	Lset657
Ltmp2700:
	.quad	Leh_func_begin112-Ltmp2700
Lset658 = Leh_func_end112-Leh_func_begin112
	.quad	Lset658
	.byte	0
	.byte	4
Lset659 = Ltmp2139-Leh_func_begin112
	.long	Lset659
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset660 = Ltmp2140-Ltmp2139
	.long	Lset660
	.byte	13
	.byte	6
	.byte	4
Lset661 = Ltmp2141-Ltmp2140
	.long	Lset661
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end112:

	.globl	_atomic_add_long.eh
_atomic_add_long.eh:
Lset662 = Leh_frame_end113-Leh_frame_begin113
	.long	Lset662
Leh_frame_begin113:
Lset663 = Leh_frame_begin113-Leh_frame_common
	.long	Lset663
Ltmp2701:
	.quad	Leh_func_begin113-Ltmp2701
Lset664 = Leh_func_end113-Leh_func_begin113
	.quad	Lset664
	.byte	0
	.byte	4
Lset665 = Ltmp2158-Leh_func_begin113
	.long	Lset665
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset666 = Ltmp2159-Ltmp2158
	.long	Lset666
	.byte	13
	.byte	6
	.byte	4
Lset667 = Ltmp2160-Ltmp2159
	.long	Lset667
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end113:

	.globl	_atomic_add_int.eh
_atomic_add_int.eh:
Lset668 = Leh_frame_end114-Leh_frame_begin114
	.long	Lset668
Leh_frame_begin114:
Lset669 = Leh_frame_begin114-Leh_frame_common
	.long	Lset669
Ltmp2702:
	.quad	Leh_func_begin114-Ltmp2702
Lset670 = Leh_func_end114-Leh_func_begin114
	.quad	Lset670
	.byte	0
	.byte	4
Lset671 = Ltmp2177-Leh_func_begin114
	.long	Lset671
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset672 = Ltmp2178-Ltmp2177
	.long	Lset672
	.byte	13
	.byte	6
	.byte	4
Lset673 = Ltmp2179-Ltmp2178
	.long	Lset673
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end114:

	.globl	_atomic_add_32.eh
_atomic_add_32.eh:
Lset674 = Leh_frame_end115-Leh_frame_begin115
	.long	Lset674
Leh_frame_begin115:
Lset675 = Leh_frame_begin115-Leh_frame_common
	.long	Lset675
Ltmp2703:
	.quad	Leh_func_begin115-Ltmp2703
Lset676 = Leh_func_end115-Leh_func_begin115
	.quad	Lset676
	.byte	0
	.byte	4
Lset677 = Ltmp2196-Leh_func_begin115
	.long	Lset677
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset678 = Ltmp2197-Ltmp2196
	.long	Lset678
	.byte	13
	.byte	6
	.byte	4
Lset679 = Ltmp2198-Ltmp2197
	.long	Lset679
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end115:

	.globl	_atomic_add_short.eh
_atomic_add_short.eh:
Lset680 = Leh_frame_end116-Leh_frame_begin116
	.long	Lset680
Leh_frame_begin116:
Lset681 = Leh_frame_begin116-Leh_frame_common
	.long	Lset681
Ltmp2704:
	.quad	Leh_func_begin116-Ltmp2704
Lset682 = Leh_func_end116-Leh_func_begin116
	.quad	Lset682
	.byte	0
	.byte	4
Lset683 = Ltmp2215-Leh_func_begin116
	.long	Lset683
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset684 = Ltmp2216-Ltmp2215
	.long	Lset684
	.byte	13
	.byte	6
	.byte	4
Lset685 = Ltmp2217-Ltmp2216
	.long	Lset685
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end116:

	.globl	_atomic_add_16.eh
_atomic_add_16.eh:
Lset686 = Leh_frame_end117-Leh_frame_begin117
	.long	Lset686
Leh_frame_begin117:
Lset687 = Leh_frame_begin117-Leh_frame_common
	.long	Lset687
Ltmp2705:
	.quad	Leh_func_begin117-Ltmp2705
Lset688 = Leh_func_end117-Leh_func_begin117
	.quad	Lset688
	.byte	0
	.byte	4
Lset689 = Ltmp2232-Leh_func_begin117
	.long	Lset689
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset690 = Ltmp2233-Ltmp2232
	.long	Lset690
	.byte	13
	.byte	6
	.byte	4
Lset691 = Ltmp2234-Ltmp2233
	.long	Lset691
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end117:

	.globl	_atomic_add_char.eh
_atomic_add_char.eh:
Lset692 = Leh_frame_end118-Leh_frame_begin118
	.long	Lset692
Leh_frame_begin118:
Lset693 = Leh_frame_begin118-Leh_frame_common
	.long	Lset693
Ltmp2706:
	.quad	Leh_func_begin118-Ltmp2706
Lset694 = Leh_func_end118-Leh_func_begin118
	.quad	Lset694
	.byte	0
	.byte	4
Lset695 = Ltmp2249-Leh_func_begin118
	.long	Lset695
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset696 = Ltmp2250-Ltmp2249
	.long	Lset696
	.byte	13
	.byte	6
	.byte	4
Lset697 = Ltmp2251-Ltmp2250
	.long	Lset697
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end118:

	.globl	_atomic_add_8.eh
_atomic_add_8.eh:
Lset698 = Leh_frame_end119-Leh_frame_begin119
	.long	Lset698
Leh_frame_begin119:
Lset699 = Leh_frame_begin119-Leh_frame_common
	.long	Lset699
Ltmp2707:
	.quad	Leh_func_begin119-Ltmp2707
Lset700 = Leh_func_end119-Leh_func_begin119
	.quad	Lset700
	.byte	0
	.byte	4
Lset701 = Ltmp2266-Leh_func_begin119
	.long	Lset701
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset702 = Ltmp2267-Ltmp2266
	.long	Lset702
	.byte	13
	.byte	6
	.byte	4
Lset703 = Ltmp2268-Ltmp2267
	.long	Lset703
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	3
Leh_frame_end119:

	.globl	_atomic_dec_64.eh
_atomic_dec_64.eh:
Lset704 = Leh_frame_end120-Leh_frame_begin120
	.long	Lset704
Leh_frame_begin120:
Lset705 = Leh_frame_begin120-Leh_frame_common
	.long	Lset705
Ltmp2708:
	.quad	Leh_func_begin120-Ltmp2708
Lset706 = Leh_func_end120-Leh_func_begin120
	.quad	Lset706
	.byte	0
	.byte	4
Lset707 = Ltmp2283-Leh_func_begin120
	.long	Lset707
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset708 = Ltmp2284-Ltmp2283
	.long	Lset708
	.byte	13
	.byte	6
	.byte	4
Lset709 = Ltmp2285-Ltmp2284
	.long	Lset709
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end120:

	.globl	_atomic_dec_ulong.eh
_atomic_dec_ulong.eh:
Lset710 = Leh_frame_end121-Leh_frame_begin121
	.long	Lset710
Leh_frame_begin121:
Lset711 = Leh_frame_begin121-Leh_frame_common
	.long	Lset711
Ltmp2709:
	.quad	Leh_func_begin121-Ltmp2709
Lset712 = Leh_func_end121-Leh_func_begin121
	.quad	Lset712
	.byte	0
	.byte	4
Lset713 = Ltmp2300-Leh_func_begin121
	.long	Lset713
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset714 = Ltmp2301-Ltmp2300
	.long	Lset714
	.byte	13
	.byte	6
	.byte	4
Lset715 = Ltmp2302-Ltmp2301
	.long	Lset715
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end121:

	.globl	_atomic_dec_uint.eh
_atomic_dec_uint.eh:
Lset716 = Leh_frame_end122-Leh_frame_begin122
	.long	Lset716
Leh_frame_begin122:
Lset717 = Leh_frame_begin122-Leh_frame_common
	.long	Lset717
Ltmp2710:
	.quad	Leh_func_begin122-Ltmp2710
Lset718 = Leh_func_end122-Leh_func_begin122
	.quad	Lset718
	.byte	0
	.byte	4
Lset719 = Ltmp2317-Leh_func_begin122
	.long	Lset719
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset720 = Ltmp2318-Ltmp2317
	.long	Lset720
	.byte	13
	.byte	6
	.byte	4
Lset721 = Ltmp2319-Ltmp2318
	.long	Lset721
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end122:

	.globl	_atomic_dec_32.eh
_atomic_dec_32.eh:
Lset722 = Leh_frame_end123-Leh_frame_begin123
	.long	Lset722
Leh_frame_begin123:
Lset723 = Leh_frame_begin123-Leh_frame_common
	.long	Lset723
Ltmp2711:
	.quad	Leh_func_begin123-Ltmp2711
Lset724 = Leh_func_end123-Leh_func_begin123
	.quad	Lset724
	.byte	0
	.byte	4
Lset725 = Ltmp2334-Leh_func_begin123
	.long	Lset725
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset726 = Ltmp2335-Ltmp2334
	.long	Lset726
	.byte	13
	.byte	6
	.byte	4
Lset727 = Ltmp2336-Ltmp2335
	.long	Lset727
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end123:

	.globl	_atomic_dec_ushort.eh
_atomic_dec_ushort.eh:
Lset728 = Leh_frame_end124-Leh_frame_begin124
	.long	Lset728
Leh_frame_begin124:
Lset729 = Leh_frame_begin124-Leh_frame_common
	.long	Lset729
Ltmp2712:
	.quad	Leh_func_begin124-Ltmp2712
Lset730 = Leh_func_end124-Leh_func_begin124
	.quad	Lset730
	.byte	0
	.byte	4
Lset731 = Ltmp2351-Leh_func_begin124
	.long	Lset731
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset732 = Ltmp2352-Ltmp2351
	.long	Lset732
	.byte	13
	.byte	6
	.byte	4
Lset733 = Ltmp2353-Ltmp2352
	.long	Lset733
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end124:

	.globl	_atomic_dec_16.eh
_atomic_dec_16.eh:
Lset734 = Leh_frame_end125-Leh_frame_begin125
	.long	Lset734
Leh_frame_begin125:
Lset735 = Leh_frame_begin125-Leh_frame_common
	.long	Lset735
Ltmp2713:
	.quad	Leh_func_begin125-Ltmp2713
Lset736 = Leh_func_end125-Leh_func_begin125
	.quad	Lset736
	.byte	0
	.byte	4
Lset737 = Ltmp2368-Leh_func_begin125
	.long	Lset737
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset738 = Ltmp2369-Ltmp2368
	.long	Lset738
	.byte	13
	.byte	6
	.byte	4
Lset739 = Ltmp2370-Ltmp2369
	.long	Lset739
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end125:

	.globl	_atomic_dec_uchar.eh
_atomic_dec_uchar.eh:
Lset740 = Leh_frame_end126-Leh_frame_begin126
	.long	Lset740
Leh_frame_begin126:
Lset741 = Leh_frame_begin126-Leh_frame_common
	.long	Lset741
Ltmp2714:
	.quad	Leh_func_begin126-Ltmp2714
Lset742 = Leh_func_end126-Leh_func_begin126
	.quad	Lset742
	.byte	0
	.byte	4
Lset743 = Ltmp2385-Leh_func_begin126
	.long	Lset743
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset744 = Ltmp2386-Ltmp2385
	.long	Lset744
	.byte	13
	.byte	6
	.byte	4
Lset745 = Ltmp2387-Ltmp2386
	.long	Lset745
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end126:

	.globl	_atomic_dec_8.eh
_atomic_dec_8.eh:
Lset746 = Leh_frame_end127-Leh_frame_begin127
	.long	Lset746
Leh_frame_begin127:
Lset747 = Leh_frame_begin127-Leh_frame_common
	.long	Lset747
Ltmp2715:
	.quad	Leh_func_begin127-Ltmp2715
Lset748 = Leh_func_end127-Leh_func_begin127
	.quad	Lset748
	.byte	0
	.byte	4
Lset749 = Ltmp2402-Leh_func_begin127
	.long	Lset749
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset750 = Ltmp2403-Ltmp2402
	.long	Lset750
	.byte	13
	.byte	6
	.byte	4
Lset751 = Ltmp2404-Ltmp2403
	.long	Lset751
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end127:

	.globl	_atomic_dec_long.eh
_atomic_dec_long.eh:
Lset752 = Leh_frame_end128-Leh_frame_begin128
	.long	Lset752
Leh_frame_begin128:
Lset753 = Leh_frame_begin128-Leh_frame_common
	.long	Lset753
Ltmp2716:
	.quad	Leh_func_begin128-Ltmp2716
Lset754 = Leh_func_end128-Leh_func_begin128
	.quad	Lset754
	.byte	0
	.byte	4
Lset755 = Ltmp2419-Leh_func_begin128
	.long	Lset755
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset756 = Ltmp2420-Ltmp2419
	.long	Lset756
	.byte	13
	.byte	6
	.byte	4
Lset757 = Ltmp2421-Ltmp2420
	.long	Lset757
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end128:

	.globl	_atomic_inc_64.eh
_atomic_inc_64.eh:
Lset758 = Leh_frame_end129-Leh_frame_begin129
	.long	Lset758
Leh_frame_begin129:
Lset759 = Leh_frame_begin129-Leh_frame_common
	.long	Lset759
Ltmp2717:
	.quad	Leh_func_begin129-Ltmp2717
Lset760 = Leh_func_end129-Leh_func_begin129
	.quad	Lset760
	.byte	0
	.byte	4
Lset761 = Ltmp2436-Leh_func_begin129
	.long	Lset761
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset762 = Ltmp2437-Ltmp2436
	.long	Lset762
	.byte	13
	.byte	6
	.byte	4
Lset763 = Ltmp2438-Ltmp2437
	.long	Lset763
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end129:

	.globl	_atomic_inc_ulong.eh
_atomic_inc_ulong.eh:
Lset764 = Leh_frame_end130-Leh_frame_begin130
	.long	Lset764
Leh_frame_begin130:
Lset765 = Leh_frame_begin130-Leh_frame_common
	.long	Lset765
Ltmp2718:
	.quad	Leh_func_begin130-Ltmp2718
Lset766 = Leh_func_end130-Leh_func_begin130
	.quad	Lset766
	.byte	0
	.byte	4
Lset767 = Ltmp2453-Leh_func_begin130
	.long	Lset767
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset768 = Ltmp2454-Ltmp2453
	.long	Lset768
	.byte	13
	.byte	6
	.byte	4
Lset769 = Ltmp2455-Ltmp2454
	.long	Lset769
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end130:

	.globl	_atomic_inc_uint.eh
_atomic_inc_uint.eh:
Lset770 = Leh_frame_end131-Leh_frame_begin131
	.long	Lset770
Leh_frame_begin131:
Lset771 = Leh_frame_begin131-Leh_frame_common
	.long	Lset771
Ltmp2719:
	.quad	Leh_func_begin131-Ltmp2719
Lset772 = Leh_func_end131-Leh_func_begin131
	.quad	Lset772
	.byte	0
	.byte	4
Lset773 = Ltmp2470-Leh_func_begin131
	.long	Lset773
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset774 = Ltmp2471-Ltmp2470
	.long	Lset774
	.byte	13
	.byte	6
	.byte	4
Lset775 = Ltmp2472-Ltmp2471
	.long	Lset775
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end131:

	.globl	_atomic_inc_32.eh
_atomic_inc_32.eh:
Lset776 = Leh_frame_end132-Leh_frame_begin132
	.long	Lset776
Leh_frame_begin132:
Lset777 = Leh_frame_begin132-Leh_frame_common
	.long	Lset777
Ltmp2720:
	.quad	Leh_func_begin132-Ltmp2720
Lset778 = Leh_func_end132-Leh_func_begin132
	.quad	Lset778
	.byte	0
	.byte	4
Lset779 = Ltmp2487-Leh_func_begin132
	.long	Lset779
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset780 = Ltmp2488-Ltmp2487
	.long	Lset780
	.byte	13
	.byte	6
	.byte	4
Lset781 = Ltmp2489-Ltmp2488
	.long	Lset781
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end132:

	.globl	_atomic_inc_ushort.eh
_atomic_inc_ushort.eh:
Lset782 = Leh_frame_end133-Leh_frame_begin133
	.long	Lset782
Leh_frame_begin133:
Lset783 = Leh_frame_begin133-Leh_frame_common
	.long	Lset783
Ltmp2721:
	.quad	Leh_func_begin133-Ltmp2721
Lset784 = Leh_func_end133-Leh_func_begin133
	.quad	Lset784
	.byte	0
	.byte	4
Lset785 = Ltmp2504-Leh_func_begin133
	.long	Lset785
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset786 = Ltmp2505-Ltmp2504
	.long	Lset786
	.byte	13
	.byte	6
	.byte	4
Lset787 = Ltmp2506-Ltmp2505
	.long	Lset787
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end133:

	.globl	_atomic_inc_16.eh
_atomic_inc_16.eh:
Lset788 = Leh_frame_end134-Leh_frame_begin134
	.long	Lset788
Leh_frame_begin134:
Lset789 = Leh_frame_begin134-Leh_frame_common
	.long	Lset789
Ltmp2722:
	.quad	Leh_func_begin134-Ltmp2722
Lset790 = Leh_func_end134-Leh_func_begin134
	.quad	Lset790
	.byte	0
	.byte	4
Lset791 = Ltmp2521-Leh_func_begin134
	.long	Lset791
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset792 = Ltmp2522-Ltmp2521
	.long	Lset792
	.byte	13
	.byte	6
	.byte	4
Lset793 = Ltmp2523-Ltmp2522
	.long	Lset793
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end134:

	.globl	_atomic_inc_uchar.eh
_atomic_inc_uchar.eh:
Lset794 = Leh_frame_end135-Leh_frame_begin135
	.long	Lset794
Leh_frame_begin135:
Lset795 = Leh_frame_begin135-Leh_frame_common
	.long	Lset795
Ltmp2723:
	.quad	Leh_func_begin135-Ltmp2723
Lset796 = Leh_func_end135-Leh_func_begin135
	.quad	Lset796
	.byte	0
	.byte	4
Lset797 = Ltmp2538-Leh_func_begin135
	.long	Lset797
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset798 = Ltmp2539-Ltmp2538
	.long	Lset798
	.byte	13
	.byte	6
	.byte	4
Lset799 = Ltmp2540-Ltmp2539
	.long	Lset799
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end135:

	.globl	_atomic_inc_8.eh
_atomic_inc_8.eh:
Lset800 = Leh_frame_end136-Leh_frame_begin136
	.long	Lset800
Leh_frame_begin136:
Lset801 = Leh_frame_begin136-Leh_frame_common
	.long	Lset801
Ltmp2724:
	.quad	Leh_func_begin136-Ltmp2724
Lset802 = Leh_func_end136-Leh_func_begin136
	.quad	Lset802
	.byte	0
	.byte	4
Lset803 = Ltmp2555-Leh_func_begin136
	.long	Lset803
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset804 = Ltmp2556-Ltmp2555
	.long	Lset804
	.byte	13
	.byte	6
	.byte	4
Lset805 = Ltmp2557-Ltmp2556
	.long	Lset805
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end136:

	.globl	_atomic_inc_long.eh
_atomic_inc_long.eh:
Lset806 = Leh_frame_end137-Leh_frame_begin137
	.long	Lset806
Leh_frame_begin137:
Lset807 = Leh_frame_begin137-Leh_frame_common
	.long	Lset807
Ltmp2725:
	.quad	Leh_func_begin137-Ltmp2725
Lset808 = Leh_func_end137-Leh_func_begin137
	.quad	Lset808
	.byte	0
	.byte	4
Lset809 = Ltmp2572-Leh_func_begin137
	.long	Lset809
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset810 = Ltmp2573-Ltmp2572
	.long	Lset810
	.byte	13
	.byte	6
	.byte	4
Lset811 = Ltmp2574-Ltmp2573
	.long	Lset811
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	3
Leh_frame_end137:

	.section	__TEXT,__text,regular,pure_instructions
Ltext_end:
	.section	__DATA,__data
Ldata_end:
	.section	__TEXT,__text,regular,pure_instructions
Lsection_end1:
	.section	__DWARF,__debug_frame,regular,debug
Ldebug_frame_common:
Lset812 = Ldebug_frame_common_end-Ldebug_frame_common_begin
	.long	Lset812
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
Lset813 = Ldebug_frame_end1-Ldebug_frame_begin1
	.long	Lset813
Ldebug_frame_begin1:
Lset814 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset814
	.quad	Lfunc_begin1
Lset815 = Lfunc_end1-Lfunc_begin1
	.quad	Lset815
	.byte	4
Lset816 = Ltmp0-Lfunc_begin1
	.long	Lset816
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset817 = Ltmp1-Ltmp0
	.long	Lset817
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end1:
Lset818 = Ldebug_frame_end2-Ldebug_frame_begin2
	.long	Lset818
Ldebug_frame_begin2:
Lset819 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset819
	.quad	Lfunc_begin2
Lset820 = Lfunc_end2-Lfunc_begin2
	.quad	Lset820
	.byte	4
Lset821 = Ltmp5-Lfunc_begin2
	.long	Lset821
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset822 = Ltmp6-Ltmp5
	.long	Lset822
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end2:
Lset823 = Ldebug_frame_end3-Ldebug_frame_begin3
	.long	Lset823
Ldebug_frame_begin3:
Lset824 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset824
	.quad	Lfunc_begin3
Lset825 = Lfunc_end3-Lfunc_begin3
	.quad	Lset825
	.byte	4
Lset826 = Ltmp10-Lfunc_begin3
	.long	Lset826
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset827 = Ltmp11-Ltmp10
	.long	Lset827
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end3:
Lset828 = Ldebug_frame_end4-Ldebug_frame_begin4
	.long	Lset828
Ldebug_frame_begin4:
Lset829 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset829
	.quad	Lfunc_begin4
Lset830 = Lfunc_end4-Lfunc_begin4
	.quad	Lset830
	.byte	4
Lset831 = Ltmp15-Lfunc_begin4
	.long	Lset831
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset832 = Ltmp16-Ltmp15
	.long	Lset832
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end4:
Lset833 = Ldebug_frame_end5-Ldebug_frame_begin5
	.long	Lset833
Ldebug_frame_begin5:
Lset834 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset834
	.quad	Lfunc_begin5
Lset835 = Lfunc_end5-Lfunc_begin5
	.quad	Lset835
	.byte	4
Lset836 = Ltmp20-Lfunc_begin5
	.long	Lset836
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset837 = Ltmp21-Ltmp20
	.long	Lset837
	.byte	13
	.byte	6
	.byte	4
Lset838 = Ltmp22-Ltmp21
	.long	Lset838
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end5:
Lset839 = Ldebug_frame_end6-Ldebug_frame_begin6
	.long	Lset839
Ldebug_frame_begin6:
Lset840 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset840
	.quad	Lfunc_begin6
Lset841 = Lfunc_end6-Lfunc_begin6
	.quad	Lset841
	.byte	4
Lset842 = Ltmp52-Lfunc_begin6
	.long	Lset842
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset843 = Ltmp53-Ltmp52
	.long	Lset843
	.byte	13
	.byte	6
	.byte	4
Lset844 = Ltmp54-Ltmp53
	.long	Lset844
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end6:
Lset845 = Ldebug_frame_end7-Ldebug_frame_begin7
	.long	Lset845
Ldebug_frame_begin7:
Lset846 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset846
	.quad	Lfunc_begin7
Lset847 = Lfunc_end7-Lfunc_begin7
	.quad	Lset847
	.byte	4
Lset848 = Ltmp84-Lfunc_begin7
	.long	Lset848
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset849 = Ltmp85-Ltmp84
	.long	Lset849
	.byte	13
	.byte	6
	.byte	4
Lset850 = Ltmp86-Ltmp85
	.long	Lset850
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end7:
Lset851 = Ldebug_frame_end8-Ldebug_frame_begin8
	.long	Lset851
Ldebug_frame_begin8:
Lset852 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset852
	.quad	Lfunc_begin8
Lset853 = Lfunc_end8-Lfunc_begin8
	.quad	Lset853
	.byte	4
Lset854 = Ltmp109-Lfunc_begin8
	.long	Lset854
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset855 = Ltmp110-Ltmp109
	.long	Lset855
	.byte	13
	.byte	6
	.byte	4
Lset856 = Ltmp111-Ltmp110
	.long	Lset856
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end8:
Lset857 = Ldebug_frame_end9-Ldebug_frame_begin9
	.long	Lset857
Ldebug_frame_begin9:
Lset858 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset858
	.quad	Lfunc_begin9
Lset859 = Lfunc_end9-Lfunc_begin9
	.quad	Lset859
	.byte	4
Lset860 = Ltmp130-Lfunc_begin9
	.long	Lset860
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset861 = Ltmp131-Ltmp130
	.long	Lset861
	.byte	13
	.byte	6
	.byte	4
Lset862 = Ltmp132-Ltmp131
	.long	Lset862
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end9:
Lset863 = Ldebug_frame_end10-Ldebug_frame_begin10
	.long	Lset863
Ldebug_frame_begin10:
Lset864 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset864
	.quad	Lfunc_begin10
Lset865 = Lfunc_end10-Lfunc_begin10
	.quad	Lset865
	.byte	4
Lset866 = Ltmp151-Lfunc_begin10
	.long	Lset866
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset867 = Ltmp152-Ltmp151
	.long	Lset867
	.byte	13
	.byte	6
	.byte	4
Lset868 = Ltmp153-Ltmp152
	.long	Lset868
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end10:
Lset869 = Ldebug_frame_end11-Ldebug_frame_begin11
	.long	Lset869
Ldebug_frame_begin11:
Lset870 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset870
	.quad	Lfunc_begin11
Lset871 = Lfunc_end11-Lfunc_begin11
	.quad	Lset871
	.byte	4
Lset872 = Ltmp172-Lfunc_begin11
	.long	Lset872
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset873 = Ltmp173-Ltmp172
	.long	Lset873
	.byte	13
	.byte	6
	.byte	4
Lset874 = Ltmp174-Ltmp173
	.long	Lset874
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end11:
Lset875 = Ldebug_frame_end12-Ldebug_frame_begin12
	.long	Lset875
Ldebug_frame_begin12:
Lset876 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset876
	.quad	Lfunc_begin12
Lset877 = Lfunc_end12-Lfunc_begin12
	.quad	Lset877
	.byte	4
Lset878 = Ltmp193-Lfunc_begin12
	.long	Lset878
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset879 = Ltmp194-Ltmp193
	.long	Lset879
	.byte	13
	.byte	6
	.byte	4
Lset880 = Ltmp195-Ltmp194
	.long	Lset880
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end12:
Lset881 = Ldebug_frame_end13-Ldebug_frame_begin13
	.long	Lset881
Ldebug_frame_begin13:
Lset882 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset882
	.quad	Lfunc_begin13
Lset883 = Lfunc_end13-Lfunc_begin13
	.quad	Lset883
	.byte	4
Lset884 = Ltmp212-Lfunc_begin13
	.long	Lset884
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset885 = Ltmp213-Ltmp212
	.long	Lset885
	.byte	13
	.byte	6
	.byte	4
Lset886 = Ltmp214-Ltmp213
	.long	Lset886
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end13:
Lset887 = Ldebug_frame_end14-Ldebug_frame_begin14
	.long	Lset887
Ldebug_frame_begin14:
Lset888 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset888
	.quad	Lfunc_begin14
Lset889 = Lfunc_end14-Lfunc_begin14
	.quad	Lset889
	.byte	4
Lset890 = Ltmp231-Lfunc_begin14
	.long	Lset890
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset891 = Ltmp232-Ltmp231
	.long	Lset891
	.byte	13
	.byte	6
	.byte	4
Lset892 = Ltmp233-Ltmp232
	.long	Lset892
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end14:
Lset893 = Ldebug_frame_end15-Ldebug_frame_begin15
	.long	Lset893
Ldebug_frame_begin15:
Lset894 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset894
	.quad	Lfunc_begin15
Lset895 = Lfunc_end15-Lfunc_begin15
	.quad	Lset895
	.byte	4
Lset896 = Ltmp250-Lfunc_begin15
	.long	Lset896
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset897 = Ltmp251-Ltmp250
	.long	Lset897
	.byte	13
	.byte	6
	.byte	4
Lset898 = Ltmp252-Ltmp251
	.long	Lset898
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end15:
Lset899 = Ldebug_frame_end16-Ldebug_frame_begin16
	.long	Lset899
Ldebug_frame_begin16:
Lset900 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset900
	.quad	Lfunc_begin16
Lset901 = Lfunc_end16-Lfunc_begin16
	.quad	Lset901
	.byte	4
Lset902 = Ltmp269-Lfunc_begin16
	.long	Lset902
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset903 = Ltmp270-Ltmp269
	.long	Lset903
	.byte	13
	.byte	6
	.byte	4
Lset904 = Ltmp271-Ltmp270
	.long	Lset904
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end16:
Lset905 = Ldebug_frame_end17-Ldebug_frame_begin17
	.long	Lset905
Ldebug_frame_begin17:
Lset906 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset906
	.quad	Lfunc_begin17
Lset907 = Lfunc_end17-Lfunc_begin17
	.quad	Lset907
	.byte	4
Lset908 = Ltmp296-Lfunc_begin17
	.long	Lset908
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset909 = Ltmp297-Ltmp296
	.long	Lset909
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end17:
Lset910 = Ldebug_frame_end18-Ldebug_frame_begin18
	.long	Lset910
Ldebug_frame_begin18:
Lset911 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset911
	.quad	Lfunc_begin18
Lset912 = Lfunc_end18-Lfunc_begin18
	.quad	Lset912
	.byte	4
Lset913 = Ltmp307-Lfunc_begin18
	.long	Lset913
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset914 = Ltmp308-Ltmp307
	.long	Lset914
	.byte	13
	.byte	6
	.byte	4
Lset915 = Ltmp309-Ltmp308
	.long	Lset915
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end18:
Lset916 = Ldebug_frame_end19-Ldebug_frame_begin19
	.long	Lset916
Ldebug_frame_begin19:
Lset917 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset917
	.quad	Lfunc_begin19
Lset918 = Lfunc_end19-Lfunc_begin19
	.quad	Lset918
	.byte	4
Lset919 = Ltmp331-Lfunc_begin19
	.long	Lset919
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset920 = Ltmp332-Ltmp331
	.long	Lset920
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end19:
Lset921 = Ldebug_frame_end20-Ldebug_frame_begin20
	.long	Lset921
Ldebug_frame_begin20:
Lset922 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset922
	.quad	Lfunc_begin20
Lset923 = Lfunc_end20-Lfunc_begin20
	.quad	Lset923
	.byte	4
Lset924 = Ltmp342-Lfunc_begin20
	.long	Lset924
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset925 = Ltmp343-Ltmp342
	.long	Lset925
	.byte	13
	.byte	6
	.byte	4
Lset926 = Ltmp344-Ltmp343
	.long	Lset926
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end20:
Lset927 = Ldebug_frame_end21-Ldebug_frame_begin21
	.long	Lset927
Ldebug_frame_begin21:
Lset928 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset928
	.quad	Lfunc_begin21
Lset929 = Lfunc_end21-Lfunc_begin21
	.quad	Lset929
	.byte	4
Lset930 = Ltmp366-Lfunc_begin21
	.long	Lset930
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset931 = Ltmp367-Ltmp366
	.long	Lset931
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end21:
Lset932 = Ldebug_frame_end22-Ldebug_frame_begin22
	.long	Lset932
Ldebug_frame_begin22:
Lset933 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset933
	.quad	Lfunc_begin22
Lset934 = Lfunc_end22-Lfunc_begin22
	.quad	Lset934
	.byte	4
Lset935 = Ltmp377-Lfunc_begin22
	.long	Lset935
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset936 = Ltmp378-Ltmp377
	.long	Lset936
	.byte	13
	.byte	6
	.byte	4
Lset937 = Ltmp379-Ltmp378
	.long	Lset937
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end22:
Lset938 = Ldebug_frame_end23-Ldebug_frame_begin23
	.long	Lset938
Ldebug_frame_begin23:
Lset939 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset939
	.quad	Lfunc_begin23
Lset940 = Lfunc_end23-Lfunc_begin23
	.quad	Lset940
	.byte	4
Lset941 = Ltmp401-Lfunc_begin23
	.long	Lset941
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset942 = Ltmp402-Ltmp401
	.long	Lset942
	.byte	13
	.byte	6
	.byte	4
Lset943 = Ltmp403-Ltmp402
	.long	Lset943
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end23:
Lset944 = Ldebug_frame_end24-Ldebug_frame_begin24
	.long	Lset944
Ldebug_frame_begin24:
Lset945 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset945
	.quad	Lfunc_begin24
Lset946 = Lfunc_end24-Lfunc_begin24
	.quad	Lset946
	.byte	4
Lset947 = Ltmp425-Lfunc_begin24
	.long	Lset947
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset948 = Ltmp426-Ltmp425
	.long	Lset948
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end24:
Lset949 = Ldebug_frame_end25-Ldebug_frame_begin25
	.long	Lset949
Ldebug_frame_begin25:
Lset950 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset950
	.quad	Lfunc_begin25
Lset951 = Lfunc_end25-Lfunc_begin25
	.quad	Lset951
	.byte	4
Lset952 = Ltmp436-Lfunc_begin25
	.long	Lset952
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset953 = Ltmp437-Ltmp436
	.long	Lset953
	.byte	13
	.byte	6
	.byte	4
Lset954 = Ltmp438-Ltmp437
	.long	Lset954
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end25:
Lset955 = Ldebug_frame_end26-Ldebug_frame_begin26
	.long	Lset955
Ldebug_frame_begin26:
Lset956 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset956
	.quad	Lfunc_begin26
Lset957 = Lfunc_end26-Lfunc_begin26
	.quad	Lset957
	.byte	4
Lset958 = Ltmp456-Lfunc_begin26
	.long	Lset958
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset959 = Ltmp457-Ltmp456
	.long	Lset959
	.byte	13
	.byte	6
	.byte	4
Lset960 = Ltmp458-Ltmp457
	.long	Lset960
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end26:
Lset961 = Ldebug_frame_end27-Ldebug_frame_begin27
	.long	Lset961
Ldebug_frame_begin27:
Lset962 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset962
	.quad	Lfunc_begin27
Lset963 = Lfunc_end27-Lfunc_begin27
	.quad	Lset963
	.byte	4
Lset964 = Ltmp476-Lfunc_begin27
	.long	Lset964
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset965 = Ltmp477-Ltmp476
	.long	Lset965
	.byte	13
	.byte	6
	.byte	4
Lset966 = Ltmp478-Ltmp477
	.long	Lset966
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end27:
Lset967 = Ldebug_frame_end28-Ldebug_frame_begin28
	.long	Lset967
Ldebug_frame_begin28:
Lset968 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset968
	.quad	Lfunc_begin28
Lset969 = Lfunc_end28-Lfunc_begin28
	.quad	Lset969
	.byte	4
Lset970 = Ltmp496-Lfunc_begin28
	.long	Lset970
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset971 = Ltmp497-Ltmp496
	.long	Lset971
	.byte	13
	.byte	6
	.byte	4
Lset972 = Ltmp498-Ltmp497
	.long	Lset972
	.byte	131
	.byte	6
	.byte	140
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end28:
Lset973 = Ldebug_frame_end29-Ldebug_frame_begin29
	.long	Lset973
Ldebug_frame_begin29:
Lset974 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset974
	.quad	Lfunc_begin29
Lset975 = Lfunc_end29-Lfunc_begin29
	.quad	Lset975
	.byte	4
Lset976 = Ltmp516-Lfunc_begin29
	.long	Lset976
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset977 = Ltmp517-Ltmp516
	.long	Lset977
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end29:
Lset978 = Ldebug_frame_end30-Ldebug_frame_begin30
	.long	Lset978
Ldebug_frame_begin30:
Lset979 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset979
	.quad	Lfunc_begin30
Lset980 = Lfunc_end30-Lfunc_begin30
	.quad	Lset980
	.byte	4
Lset981 = Ltmp523-Lfunc_begin30
	.long	Lset981
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset982 = Ltmp524-Ltmp523
	.long	Lset982
	.byte	13
	.byte	6
	.byte	4
Lset983 = Ltmp525-Ltmp524
	.long	Lset983
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end30:
Lset984 = Ldebug_frame_end31-Ldebug_frame_begin31
	.long	Lset984
Ldebug_frame_begin31:
Lset985 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset985
	.quad	Lfunc_begin31
Lset986 = Lfunc_end31-Lfunc_begin31
	.quad	Lset986
	.byte	4
Lset987 = Ltmp545-Lfunc_begin31
	.long	Lset987
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset988 = Ltmp546-Ltmp545
	.long	Lset988
	.byte	13
	.byte	6
	.byte	4
Lset989 = Ltmp547-Ltmp546
	.long	Lset989
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end31:
Lset990 = Ldebug_frame_end32-Ldebug_frame_begin32
	.long	Lset990
Ldebug_frame_begin32:
Lset991 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset991
	.quad	Lfunc_begin32
Lset992 = Lfunc_end32-Lfunc_begin32
	.quad	Lset992
	.byte	4
Lset993 = Ltmp567-Lfunc_begin32
	.long	Lset993
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset994 = Ltmp568-Ltmp567
	.long	Lset994
	.byte	13
	.byte	6
	.byte	4
Lset995 = Ltmp569-Ltmp568
	.long	Lset995
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end32:
Lset996 = Ldebug_frame_end33-Ldebug_frame_begin33
	.long	Lset996
Ldebug_frame_begin33:
Lset997 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset997
	.quad	Lfunc_begin33
Lset998 = Lfunc_end33-Lfunc_begin33
	.quad	Lset998
	.byte	4
Lset999 = Ltmp589-Lfunc_begin33
	.long	Lset999
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1000 = Ltmp590-Ltmp589
	.long	Lset1000
	.byte	13
	.byte	6
	.byte	4
Lset1001 = Ltmp591-Ltmp590
	.long	Lset1001
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end33:
Lset1002 = Ldebug_frame_end34-Ldebug_frame_begin34
	.long	Lset1002
Ldebug_frame_begin34:
Lset1003 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1003
	.quad	Lfunc_begin34
Lset1004 = Lfunc_end34-Lfunc_begin34
	.quad	Lset1004
	.byte	4
Lset1005 = Ltmp611-Lfunc_begin34
	.long	Lset1005
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1006 = Ltmp612-Ltmp611
	.long	Lset1006
	.byte	13
	.byte	6
	.byte	4
Lset1007 = Ltmp613-Ltmp612
	.long	Lset1007
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end34:
Lset1008 = Ldebug_frame_end35-Ldebug_frame_begin35
	.long	Lset1008
Ldebug_frame_begin35:
Lset1009 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1009
	.quad	Lfunc_begin35
Lset1010 = Lfunc_end35-Lfunc_begin35
	.quad	Lset1010
	.byte	4
Lset1011 = Ltmp631-Lfunc_begin35
	.long	Lset1011
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1012 = Ltmp632-Ltmp631
	.long	Lset1012
	.byte	13
	.byte	6
	.byte	4
Lset1013 = Ltmp633-Ltmp632
	.long	Lset1013
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end35:
Lset1014 = Ldebug_frame_end36-Ldebug_frame_begin36
	.long	Lset1014
Ldebug_frame_begin36:
Lset1015 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1015
	.quad	Lfunc_begin36
Lset1016 = Lfunc_end36-Lfunc_begin36
	.quad	Lset1016
	.byte	4
Lset1017 = Ltmp651-Lfunc_begin36
	.long	Lset1017
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1018 = Ltmp652-Ltmp651
	.long	Lset1018
	.byte	13
	.byte	6
	.byte	4
Lset1019 = Ltmp653-Ltmp652
	.long	Lset1019
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end36:
Lset1020 = Ldebug_frame_end37-Ldebug_frame_begin37
	.long	Lset1020
Ldebug_frame_begin37:
Lset1021 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1021
	.quad	Lfunc_begin37
Lset1022 = Lfunc_end37-Lfunc_begin37
	.quad	Lset1022
	.byte	4
Lset1023 = Ltmp671-Lfunc_begin37
	.long	Lset1023
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1024 = Ltmp672-Ltmp671
	.long	Lset1024
	.byte	13
	.byte	6
	.byte	4
Lset1025 = Ltmp673-Ltmp672
	.long	Lset1025
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end37:
Lset1026 = Ldebug_frame_end38-Ldebug_frame_begin38
	.long	Lset1026
Ldebug_frame_begin38:
Lset1027 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1027
	.quad	Lfunc_begin38
Lset1028 = Lfunc_end38-Lfunc_begin38
	.quad	Lset1028
	.byte	4
Lset1029 = Ltmp691-Lfunc_begin38
	.long	Lset1029
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1030 = Ltmp692-Ltmp691
	.long	Lset1030
	.byte	13
	.byte	6
	.byte	4
Lset1031 = Ltmp693-Ltmp692
	.long	Lset1031
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end38:
Lset1032 = Ldebug_frame_end39-Ldebug_frame_begin39
	.long	Lset1032
Ldebug_frame_begin39:
Lset1033 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1033
	.quad	Lfunc_begin39
Lset1034 = Lfunc_end39-Lfunc_begin39
	.quad	Lset1034
	.byte	4
Lset1035 = Ltmp713-Lfunc_begin39
	.long	Lset1035
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1036 = Ltmp714-Ltmp713
	.long	Lset1036
	.byte	13
	.byte	6
	.byte	4
Lset1037 = Ltmp715-Ltmp714
	.long	Lset1037
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end39:
Lset1038 = Ldebug_frame_end40-Ldebug_frame_begin40
	.long	Lset1038
Ldebug_frame_begin40:
Lset1039 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1039
	.quad	Lfunc_begin40
Lset1040 = Lfunc_end40-Lfunc_begin40
	.quad	Lset1040
	.byte	4
Lset1041 = Ltmp735-Lfunc_begin40
	.long	Lset1041
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1042 = Ltmp736-Ltmp735
	.long	Lset1042
	.byte	13
	.byte	6
	.byte	4
Lset1043 = Ltmp737-Ltmp736
	.long	Lset1043
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end40:
Lset1044 = Ldebug_frame_end41-Ldebug_frame_begin41
	.long	Lset1044
Ldebug_frame_begin41:
Lset1045 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1045
	.quad	Lfunc_begin41
Lset1046 = Lfunc_end41-Lfunc_begin41
	.quad	Lset1046
	.byte	4
Lset1047 = Ltmp757-Lfunc_begin41
	.long	Lset1047
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1048 = Ltmp758-Ltmp757
	.long	Lset1048
	.byte	13
	.byte	6
	.byte	4
Lset1049 = Ltmp759-Ltmp758
	.long	Lset1049
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end41:
Lset1050 = Ldebug_frame_end42-Ldebug_frame_begin42
	.long	Lset1050
Ldebug_frame_begin42:
Lset1051 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1051
	.quad	Lfunc_begin42
Lset1052 = Lfunc_end42-Lfunc_begin42
	.quad	Lset1052
	.byte	4
Lset1053 = Ltmp779-Lfunc_begin42
	.long	Lset1053
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1054 = Ltmp780-Ltmp779
	.long	Lset1054
	.byte	13
	.byte	6
	.byte	4
Lset1055 = Ltmp781-Ltmp780
	.long	Lset1055
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end42:
Lset1056 = Ldebug_frame_end43-Ldebug_frame_begin43
	.long	Lset1056
Ldebug_frame_begin43:
Lset1057 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1057
	.quad	Lfunc_begin43
Lset1058 = Lfunc_end43-Lfunc_begin43
	.quad	Lset1058
	.byte	4
Lset1059 = Ltmp801-Lfunc_begin43
	.long	Lset1059
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1060 = Ltmp802-Ltmp801
	.long	Lset1060
	.byte	13
	.byte	6
	.byte	4
Lset1061 = Ltmp803-Ltmp802
	.long	Lset1061
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end43:
Lset1062 = Ldebug_frame_end44-Ldebug_frame_begin44
	.long	Lset1062
Ldebug_frame_begin44:
Lset1063 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1063
	.quad	Lfunc_begin44
Lset1064 = Lfunc_end44-Lfunc_begin44
	.quad	Lset1064
	.byte	4
Lset1065 = Ltmp821-Lfunc_begin44
	.long	Lset1065
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1066 = Ltmp822-Ltmp821
	.long	Lset1066
	.byte	13
	.byte	6
	.byte	4
Lset1067 = Ltmp823-Ltmp822
	.long	Lset1067
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end44:
Lset1068 = Ldebug_frame_end45-Ldebug_frame_begin45
	.long	Lset1068
Ldebug_frame_begin45:
Lset1069 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1069
	.quad	Lfunc_begin45
Lset1070 = Lfunc_end45-Lfunc_begin45
	.quad	Lset1070
	.byte	4
Lset1071 = Ltmp841-Lfunc_begin45
	.long	Lset1071
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1072 = Ltmp842-Ltmp841
	.long	Lset1072
	.byte	13
	.byte	6
	.byte	4
Lset1073 = Ltmp843-Ltmp842
	.long	Lset1073
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end45:
Lset1074 = Ldebug_frame_end46-Ldebug_frame_begin46
	.long	Lset1074
Ldebug_frame_begin46:
Lset1075 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1075
	.quad	Lfunc_begin46
Lset1076 = Lfunc_end46-Lfunc_begin46
	.quad	Lset1076
	.byte	4
Lset1077 = Ltmp861-Lfunc_begin46
	.long	Lset1077
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1078 = Ltmp862-Ltmp861
	.long	Lset1078
	.byte	13
	.byte	6
	.byte	4
Lset1079 = Ltmp863-Ltmp862
	.long	Lset1079
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end46:
Lset1080 = Ldebug_frame_end47-Ldebug_frame_begin47
	.long	Lset1080
Ldebug_frame_begin47:
Lset1081 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1081
	.quad	Lfunc_begin47
Lset1082 = Lfunc_end47-Lfunc_begin47
	.quad	Lset1082
	.byte	4
Lset1083 = Ltmp881-Lfunc_begin47
	.long	Lset1083
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1084 = Ltmp882-Ltmp881
	.long	Lset1084
	.byte	13
	.byte	6
	.byte	4
Lset1085 = Ltmp883-Ltmp882
	.long	Lset1085
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end47:
Lset1086 = Ldebug_frame_end48-Ldebug_frame_begin48
	.long	Lset1086
Ldebug_frame_begin48:
Lset1087 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1087
	.quad	Lfunc_begin48
Lset1088 = Lfunc_end48-Lfunc_begin48
	.quad	Lset1088
	.byte	4
Lset1089 = Ltmp903-Lfunc_begin48
	.long	Lset1089
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1090 = Ltmp904-Ltmp903
	.long	Lset1090
	.byte	13
	.byte	6
	.byte	4
Lset1091 = Ltmp905-Ltmp904
	.long	Lset1091
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end48:
Lset1092 = Ldebug_frame_end49-Ldebug_frame_begin49
	.long	Lset1092
Ldebug_frame_begin49:
Lset1093 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1093
	.quad	Lfunc_begin49
Lset1094 = Lfunc_end49-Lfunc_begin49
	.quad	Lset1094
	.byte	4
Lset1095 = Ltmp926-Lfunc_begin49
	.long	Lset1095
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1096 = Ltmp927-Ltmp926
	.long	Lset1096
	.byte	13
	.byte	6
	.byte	4
Lset1097 = Ltmp928-Ltmp927
	.long	Lset1097
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end49:
Lset1098 = Ldebug_frame_end50-Ldebug_frame_begin50
	.long	Lset1098
Ldebug_frame_begin50:
Lset1099 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1099
	.quad	Lfunc_begin50
Lset1100 = Lfunc_end50-Lfunc_begin50
	.quad	Lset1100
	.byte	4
Lset1101 = Ltmp948-Lfunc_begin50
	.long	Lset1101
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1102 = Ltmp949-Ltmp948
	.long	Lset1102
	.byte	13
	.byte	6
	.byte	4
Lset1103 = Ltmp950-Ltmp949
	.long	Lset1103
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end50:
Lset1104 = Ldebug_frame_end51-Ldebug_frame_begin51
	.long	Lset1104
Ldebug_frame_begin51:
Lset1105 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1105
	.quad	Lfunc_begin51
Lset1106 = Lfunc_end51-Lfunc_begin51
	.quad	Lset1106
	.byte	4
Lset1107 = Ltmp970-Lfunc_begin51
	.long	Lset1107
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1108 = Ltmp971-Ltmp970
	.long	Lset1108
	.byte	13
	.byte	6
	.byte	4
Lset1109 = Ltmp972-Ltmp971
	.long	Lset1109
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end51:
Lset1110 = Ldebug_frame_end52-Ldebug_frame_begin52
	.long	Lset1110
Ldebug_frame_begin52:
Lset1111 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1111
	.quad	Lfunc_begin52
Lset1112 = Lfunc_end52-Lfunc_begin52
	.quad	Lset1112
	.byte	4
Lset1113 = Ltmp992-Lfunc_begin52
	.long	Lset1113
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1114 = Ltmp993-Ltmp992
	.long	Lset1114
	.byte	13
	.byte	6
	.byte	4
Lset1115 = Ltmp994-Ltmp993
	.long	Lset1115
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end52:
Lset1116 = Ldebug_frame_end53-Ldebug_frame_begin53
	.long	Lset1116
Ldebug_frame_begin53:
Lset1117 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1117
	.quad	Lfunc_begin53
Lset1118 = Lfunc_end53-Lfunc_begin53
	.quad	Lset1118
	.byte	4
Lset1119 = Ltmp1014-Lfunc_begin53
	.long	Lset1119
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1120 = Ltmp1015-Ltmp1014
	.long	Lset1120
	.byte	13
	.byte	6
	.byte	4
Lset1121 = Ltmp1016-Ltmp1015
	.long	Lset1121
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end53:
Lset1122 = Ldebug_frame_end54-Ldebug_frame_begin54
	.long	Lset1122
Ldebug_frame_begin54:
Lset1123 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1123
	.quad	Lfunc_begin54
Lset1124 = Lfunc_end54-Lfunc_begin54
	.quad	Lset1124
	.byte	4
Lset1125 = Ltmp1034-Lfunc_begin54
	.long	Lset1125
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1126 = Ltmp1035-Ltmp1034
	.long	Lset1126
	.byte	13
	.byte	6
	.byte	4
Lset1127 = Ltmp1036-Ltmp1035
	.long	Lset1127
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end54:
Lset1128 = Ldebug_frame_end55-Ldebug_frame_begin55
	.long	Lset1128
Ldebug_frame_begin55:
Lset1129 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1129
	.quad	Lfunc_begin55
Lset1130 = Lfunc_end55-Lfunc_begin55
	.quad	Lset1130
	.byte	4
Lset1131 = Ltmp1054-Lfunc_begin55
	.long	Lset1131
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1132 = Ltmp1055-Ltmp1054
	.long	Lset1132
	.byte	13
	.byte	6
	.byte	4
Lset1133 = Ltmp1056-Ltmp1055
	.long	Lset1133
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end55:
Lset1134 = Ldebug_frame_end56-Ldebug_frame_begin56
	.long	Lset1134
Ldebug_frame_begin56:
Lset1135 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1135
	.quad	Lfunc_begin56
Lset1136 = Lfunc_end56-Lfunc_begin56
	.quad	Lset1136
	.byte	4
Lset1137 = Ltmp1074-Lfunc_begin56
	.long	Lset1137
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1138 = Ltmp1075-Ltmp1074
	.long	Lset1138
	.byte	13
	.byte	6
	.byte	4
Lset1139 = Ltmp1076-Ltmp1075
	.long	Lset1139
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end56:
Lset1140 = Ldebug_frame_end57-Ldebug_frame_begin57
	.long	Lset1140
Ldebug_frame_begin57:
Lset1141 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1141
	.quad	Lfunc_begin57
Lset1142 = Lfunc_end57-Lfunc_begin57
	.quad	Lset1142
	.byte	4
Lset1143 = Ltmp1094-Lfunc_begin57
	.long	Lset1143
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1144 = Ltmp1095-Ltmp1094
	.long	Lset1144
	.byte	13
	.byte	6
	.byte	4
Lset1145 = Ltmp1096-Ltmp1095
	.long	Lset1145
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end57:
Lset1146 = Ldebug_frame_end58-Ldebug_frame_begin58
	.long	Lset1146
Ldebug_frame_begin58:
Lset1147 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1147
	.quad	Lfunc_begin58
Lset1148 = Lfunc_end58-Lfunc_begin58
	.quad	Lset1148
	.byte	4
Lset1149 = Ltmp1117-Lfunc_begin58
	.long	Lset1149
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1150 = Ltmp1118-Ltmp1117
	.long	Lset1150
	.byte	13
	.byte	6
	.byte	4
Lset1151 = Ltmp1119-Ltmp1118
	.long	Lset1151
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end58:
Lset1152 = Ldebug_frame_end59-Ldebug_frame_begin59
	.long	Lset1152
Ldebug_frame_begin59:
Lset1153 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1153
	.quad	Lfunc_begin59
Lset1154 = Lfunc_end59-Lfunc_begin59
	.quad	Lset1154
	.byte	4
Lset1155 = Ltmp1139-Lfunc_begin59
	.long	Lset1155
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1156 = Ltmp1140-Ltmp1139
	.long	Lset1156
	.byte	13
	.byte	6
	.byte	4
Lset1157 = Ltmp1141-Ltmp1140
	.long	Lset1157
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end59:
Lset1158 = Ldebug_frame_end60-Ldebug_frame_begin60
	.long	Lset1158
Ldebug_frame_begin60:
Lset1159 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1159
	.quad	Lfunc_begin60
Lset1160 = Lfunc_end60-Lfunc_begin60
	.quad	Lset1160
	.byte	4
Lset1161 = Ltmp1161-Lfunc_begin60
	.long	Lset1161
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1162 = Ltmp1162-Ltmp1161
	.long	Lset1162
	.byte	13
	.byte	6
	.byte	4
Lset1163 = Ltmp1163-Ltmp1162
	.long	Lset1163
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end60:
Lset1164 = Ldebug_frame_end61-Ldebug_frame_begin61
	.long	Lset1164
Ldebug_frame_begin61:
Lset1165 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1165
	.quad	Lfunc_begin61
Lset1166 = Lfunc_end61-Lfunc_begin61
	.quad	Lset1166
	.byte	4
Lset1167 = Ltmp1183-Lfunc_begin61
	.long	Lset1167
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1168 = Ltmp1184-Ltmp1183
	.long	Lset1168
	.byte	13
	.byte	6
	.byte	4
Lset1169 = Ltmp1185-Ltmp1184
	.long	Lset1169
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end61:
Lset1170 = Ldebug_frame_end62-Ldebug_frame_begin62
	.long	Lset1170
Ldebug_frame_begin62:
Lset1171 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1171
	.quad	Lfunc_begin62
Lset1172 = Lfunc_end62-Lfunc_begin62
	.quad	Lset1172
	.byte	4
Lset1173 = Ltmp1205-Lfunc_begin62
	.long	Lset1173
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1174 = Ltmp1206-Ltmp1205
	.long	Lset1174
	.byte	13
	.byte	6
	.byte	4
Lset1175 = Ltmp1207-Ltmp1206
	.long	Lset1175
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end62:
Lset1176 = Ldebug_frame_end63-Ldebug_frame_begin63
	.long	Lset1176
Ldebug_frame_begin63:
Lset1177 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1177
	.quad	Lfunc_begin63
Lset1178 = Lfunc_end63-Lfunc_begin63
	.quad	Lset1178
	.byte	4
Lset1179 = Ltmp1225-Lfunc_begin63
	.long	Lset1179
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1180 = Ltmp1226-Ltmp1225
	.long	Lset1180
	.byte	13
	.byte	6
	.byte	4
Lset1181 = Ltmp1227-Ltmp1226
	.long	Lset1181
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end63:
Lset1182 = Ldebug_frame_end64-Ldebug_frame_begin64
	.long	Lset1182
Ldebug_frame_begin64:
Lset1183 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1183
	.quad	Lfunc_begin64
Lset1184 = Lfunc_end64-Lfunc_begin64
	.quad	Lset1184
	.byte	4
Lset1185 = Ltmp1245-Lfunc_begin64
	.long	Lset1185
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1186 = Ltmp1246-Ltmp1245
	.long	Lset1186
	.byte	13
	.byte	6
	.byte	4
Lset1187 = Ltmp1247-Ltmp1246
	.long	Lset1187
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end64:
Lset1188 = Ldebug_frame_end65-Ldebug_frame_begin65
	.long	Lset1188
Ldebug_frame_begin65:
Lset1189 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1189
	.quad	Lfunc_begin65
Lset1190 = Lfunc_end65-Lfunc_begin65
	.quad	Lset1190
	.byte	4
Lset1191 = Ltmp1265-Lfunc_begin65
	.long	Lset1191
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1192 = Ltmp1266-Ltmp1265
	.long	Lset1192
	.byte	13
	.byte	6
	.byte	4
Lset1193 = Ltmp1267-Ltmp1266
	.long	Lset1193
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end65:
Lset1194 = Ldebug_frame_end66-Ldebug_frame_begin66
	.long	Lset1194
Ldebug_frame_begin66:
Lset1195 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1195
	.quad	Lfunc_begin66
Lset1196 = Lfunc_end66-Lfunc_begin66
	.quad	Lset1196
	.byte	4
Lset1197 = Ltmp1285-Lfunc_begin66
	.long	Lset1197
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1198 = Ltmp1286-Ltmp1285
	.long	Lset1198
	.byte	13
	.byte	6
	.byte	4
Lset1199 = Ltmp1287-Ltmp1286
	.long	Lset1199
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end66:
Lset1200 = Ldebug_frame_end67-Ldebug_frame_begin67
	.long	Lset1200
Ldebug_frame_begin67:
Lset1201 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1201
	.quad	Lfunc_begin67
Lset1202 = Lfunc_end67-Lfunc_begin67
	.quad	Lset1202
	.byte	4
Lset1203 = Ltmp1305-Lfunc_begin67
	.long	Lset1203
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1204 = Ltmp1306-Ltmp1305
	.long	Lset1204
	.byte	13
	.byte	6
	.byte	4
Lset1205 = Ltmp1307-Ltmp1306
	.long	Lset1205
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end67:
Lset1206 = Ldebug_frame_end68-Ldebug_frame_begin68
	.long	Lset1206
Ldebug_frame_begin68:
Lset1207 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1207
	.quad	Lfunc_begin68
Lset1208 = Lfunc_end68-Lfunc_begin68
	.quad	Lset1208
	.byte	4
Lset1209 = Ltmp1325-Lfunc_begin68
	.long	Lset1209
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1210 = Ltmp1326-Ltmp1325
	.long	Lset1210
	.byte	13
	.byte	6
	.byte	4
Lset1211 = Ltmp1327-Ltmp1326
	.long	Lset1211
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end68:
Lset1212 = Ldebug_frame_end69-Ldebug_frame_begin69
	.long	Lset1212
Ldebug_frame_begin69:
Lset1213 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1213
	.quad	Lfunc_begin69
Lset1214 = Lfunc_end69-Lfunc_begin69
	.quad	Lset1214
	.byte	4
Lset1215 = Ltmp1345-Lfunc_begin69
	.long	Lset1215
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1216 = Ltmp1346-Ltmp1345
	.long	Lset1216
	.byte	13
	.byte	6
	.byte	4
Lset1217 = Ltmp1347-Ltmp1346
	.long	Lset1217
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end69:
Lset1218 = Ldebug_frame_end70-Ldebug_frame_begin70
	.long	Lset1218
Ldebug_frame_begin70:
Lset1219 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1219
	.quad	Lfunc_begin70
Lset1220 = Lfunc_end70-Lfunc_begin70
	.quad	Lset1220
	.byte	4
Lset1221 = Ltmp1365-Lfunc_begin70
	.long	Lset1221
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1222 = Ltmp1366-Ltmp1365
	.long	Lset1222
	.byte	13
	.byte	6
	.byte	4
Lset1223 = Ltmp1367-Ltmp1366
	.long	Lset1223
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end70:
Lset1224 = Ldebug_frame_end71-Ldebug_frame_begin71
	.long	Lset1224
Ldebug_frame_begin71:
Lset1225 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1225
	.quad	Lfunc_begin71
Lset1226 = Lfunc_end71-Lfunc_begin71
	.quad	Lset1226
	.byte	4
Lset1227 = Ltmp1385-Lfunc_begin71
	.long	Lset1227
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1228 = Ltmp1386-Ltmp1385
	.long	Lset1228
	.byte	13
	.byte	6
	.byte	4
Lset1229 = Ltmp1387-Ltmp1386
	.long	Lset1229
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end71:
Lset1230 = Ldebug_frame_end72-Ldebug_frame_begin72
	.long	Lset1230
Ldebug_frame_begin72:
Lset1231 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1231
	.quad	Lfunc_begin72
Lset1232 = Lfunc_end72-Lfunc_begin72
	.quad	Lset1232
	.byte	4
Lset1233 = Ltmp1405-Lfunc_begin72
	.long	Lset1233
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1234 = Ltmp1406-Ltmp1405
	.long	Lset1234
	.byte	13
	.byte	6
	.byte	4
Lset1235 = Ltmp1407-Ltmp1406
	.long	Lset1235
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end72:
Lset1236 = Ldebug_frame_end73-Ldebug_frame_begin73
	.long	Lset1236
Ldebug_frame_begin73:
Lset1237 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1237
	.quad	Lfunc_begin73
Lset1238 = Lfunc_end73-Lfunc_begin73
	.quad	Lset1238
	.byte	4
Lset1239 = Ltmp1425-Lfunc_begin73
	.long	Lset1239
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1240 = Ltmp1426-Ltmp1425
	.long	Lset1240
	.byte	13
	.byte	6
	.byte	4
Lset1241 = Ltmp1427-Ltmp1426
	.long	Lset1241
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end73:
Lset1242 = Ldebug_frame_end74-Ldebug_frame_begin74
	.long	Lset1242
Ldebug_frame_begin74:
Lset1243 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1243
	.quad	Lfunc_begin74
Lset1244 = Lfunc_end74-Lfunc_begin74
	.quad	Lset1244
	.byte	4
Lset1245 = Ltmp1445-Lfunc_begin74
	.long	Lset1245
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1246 = Ltmp1446-Ltmp1445
	.long	Lset1246
	.byte	13
	.byte	6
	.byte	4
Lset1247 = Ltmp1447-Ltmp1446
	.long	Lset1247
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end74:
Lset1248 = Ldebug_frame_end75-Ldebug_frame_begin75
	.long	Lset1248
Ldebug_frame_begin75:
Lset1249 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1249
	.quad	Lfunc_begin75
Lset1250 = Lfunc_end75-Lfunc_begin75
	.quad	Lset1250
	.byte	4
Lset1251 = Ltmp1465-Lfunc_begin75
	.long	Lset1251
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1252 = Ltmp1466-Ltmp1465
	.long	Lset1252
	.byte	13
	.byte	6
	.byte	4
Lset1253 = Ltmp1467-Ltmp1466
	.long	Lset1253
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end75:
Lset1254 = Ldebug_frame_end76-Ldebug_frame_begin76
	.long	Lset1254
Ldebug_frame_begin76:
Lset1255 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1255
	.quad	Lfunc_begin76
Lset1256 = Lfunc_end76-Lfunc_begin76
	.quad	Lset1256
	.byte	4
Lset1257 = Ltmp1485-Lfunc_begin76
	.long	Lset1257
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1258 = Ltmp1486-Ltmp1485
	.long	Lset1258
	.byte	13
	.byte	6
	.byte	4
Lset1259 = Ltmp1487-Ltmp1486
	.long	Lset1259
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end76:
Lset1260 = Ldebug_frame_end77-Ldebug_frame_begin77
	.long	Lset1260
Ldebug_frame_begin77:
Lset1261 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1261
	.quad	Lfunc_begin77
Lset1262 = Lfunc_end77-Lfunc_begin77
	.quad	Lset1262
	.byte	4
Lset1263 = Ltmp1505-Lfunc_begin77
	.long	Lset1263
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1264 = Ltmp1506-Ltmp1505
	.long	Lset1264
	.byte	13
	.byte	6
	.byte	4
Lset1265 = Ltmp1507-Ltmp1506
	.long	Lset1265
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end77:
Lset1266 = Ldebug_frame_end78-Ldebug_frame_begin78
	.long	Lset1266
Ldebug_frame_begin78:
Lset1267 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1267
	.quad	Lfunc_begin78
Lset1268 = Lfunc_end78-Lfunc_begin78
	.quad	Lset1268
	.byte	4
Lset1269 = Ltmp1525-Lfunc_begin78
	.long	Lset1269
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1270 = Ltmp1526-Ltmp1525
	.long	Lset1270
	.byte	13
	.byte	6
	.byte	4
Lset1271 = Ltmp1527-Ltmp1526
	.long	Lset1271
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end78:
Lset1272 = Ldebug_frame_end79-Ldebug_frame_begin79
	.long	Lset1272
Ldebug_frame_begin79:
Lset1273 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1273
	.quad	Lfunc_begin79
Lset1274 = Lfunc_end79-Lfunc_begin79
	.quad	Lset1274
	.byte	4
Lset1275 = Ltmp1545-Lfunc_begin79
	.long	Lset1275
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1276 = Ltmp1546-Ltmp1545
	.long	Lset1276
	.byte	13
	.byte	6
	.byte	4
Lset1277 = Ltmp1547-Ltmp1546
	.long	Lset1277
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end79:
Lset1278 = Ldebug_frame_end80-Ldebug_frame_begin80
	.long	Lset1278
Ldebug_frame_begin80:
Lset1279 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1279
	.quad	Lfunc_begin80
Lset1280 = Lfunc_end80-Lfunc_begin80
	.quad	Lset1280
	.byte	4
Lset1281 = Ltmp1565-Lfunc_begin80
	.long	Lset1281
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1282 = Ltmp1566-Ltmp1565
	.long	Lset1282
	.byte	13
	.byte	6
	.byte	4
Lset1283 = Ltmp1567-Ltmp1566
	.long	Lset1283
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end80:
Lset1284 = Ldebug_frame_end81-Ldebug_frame_begin81
	.long	Lset1284
Ldebug_frame_begin81:
Lset1285 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1285
	.quad	Lfunc_begin81
Lset1286 = Lfunc_end81-Lfunc_begin81
	.quad	Lset1286
	.byte	4
Lset1287 = Ltmp1585-Lfunc_begin81
	.long	Lset1287
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1288 = Ltmp1586-Ltmp1585
	.long	Lset1288
	.byte	13
	.byte	6
	.byte	4
Lset1289 = Ltmp1587-Ltmp1586
	.long	Lset1289
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end81:
Lset1290 = Ldebug_frame_end82-Ldebug_frame_begin82
	.long	Lset1290
Ldebug_frame_begin82:
Lset1291 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1291
	.quad	Lfunc_begin82
Lset1292 = Lfunc_end82-Lfunc_begin82
	.quad	Lset1292
	.byte	4
Lset1293 = Ltmp1605-Lfunc_begin82
	.long	Lset1293
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1294 = Ltmp1606-Ltmp1605
	.long	Lset1294
	.byte	13
	.byte	6
	.byte	4
Lset1295 = Ltmp1607-Ltmp1606
	.long	Lset1295
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end82:
Lset1296 = Ldebug_frame_end83-Ldebug_frame_begin83
	.long	Lset1296
Ldebug_frame_begin83:
Lset1297 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1297
	.quad	Lfunc_begin83
Lset1298 = Lfunc_end83-Lfunc_begin83
	.quad	Lset1298
	.byte	4
Lset1299 = Ltmp1625-Lfunc_begin83
	.long	Lset1299
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1300 = Ltmp1626-Ltmp1625
	.long	Lset1300
	.byte	13
	.byte	6
	.byte	4
Lset1301 = Ltmp1627-Ltmp1626
	.long	Lset1301
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end83:
Lset1302 = Ldebug_frame_end84-Ldebug_frame_begin84
	.long	Lset1302
Ldebug_frame_begin84:
Lset1303 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1303
	.quad	Lfunc_begin84
Lset1304 = Lfunc_end84-Lfunc_begin84
	.quad	Lset1304
	.byte	4
Lset1305 = Ltmp1645-Lfunc_begin84
	.long	Lset1305
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1306 = Ltmp1646-Ltmp1645
	.long	Lset1306
	.byte	13
	.byte	6
	.byte	4
Lset1307 = Ltmp1647-Ltmp1646
	.long	Lset1307
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end84:
Lset1308 = Ldebug_frame_end85-Ldebug_frame_begin85
	.long	Lset1308
Ldebug_frame_begin85:
Lset1309 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1309
	.quad	Lfunc_begin85
Lset1310 = Lfunc_end85-Lfunc_begin85
	.quad	Lset1310
	.byte	4
Lset1311 = Ltmp1664-Lfunc_begin85
	.long	Lset1311
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1312 = Ltmp1665-Ltmp1664
	.long	Lset1312
	.byte	13
	.byte	6
	.byte	4
Lset1313 = Ltmp1666-Ltmp1665
	.long	Lset1313
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end85:
Lset1314 = Ldebug_frame_end86-Ldebug_frame_begin86
	.long	Lset1314
Ldebug_frame_begin86:
Lset1315 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1315
	.quad	Lfunc_begin86
Lset1316 = Lfunc_end86-Lfunc_begin86
	.quad	Lset1316
	.byte	4
Lset1317 = Ltmp1683-Lfunc_begin86
	.long	Lset1317
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1318 = Ltmp1684-Ltmp1683
	.long	Lset1318
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end86:
Lset1319 = Ldebug_frame_end87-Ldebug_frame_begin87
	.long	Lset1319
Ldebug_frame_begin87:
Lset1320 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1320
	.quad	Lfunc_begin87
Lset1321 = Lfunc_end87-Lfunc_begin87
	.quad	Lset1321
	.byte	4
Lset1322 = Ltmp1692-Lfunc_begin87
	.long	Lset1322
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1323 = Ltmp1693-Ltmp1692
	.long	Lset1323
	.byte	13
	.byte	6
	.byte	4
Lset1324 = Ltmp1694-Ltmp1693
	.long	Lset1324
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end87:
Lset1325 = Ldebug_frame_end88-Ldebug_frame_begin88
	.long	Lset1325
Ldebug_frame_begin88:
Lset1326 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1326
	.quad	Lfunc_begin88
Lset1327 = Lfunc_end88-Lfunc_begin88
	.quad	Lset1327
	.byte	4
Lset1328 = Ltmp1711-Lfunc_begin88
	.long	Lset1328
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1329 = Ltmp1712-Ltmp1711
	.long	Lset1329
	.byte	13
	.byte	6
	.byte	4
Lset1330 = Ltmp1713-Ltmp1712
	.long	Lset1330
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end88:
Lset1331 = Ldebug_frame_end89-Ldebug_frame_begin89
	.long	Lset1331
Ldebug_frame_begin89:
Lset1332 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1332
	.quad	Lfunc_begin89
Lset1333 = Lfunc_end89-Lfunc_begin89
	.quad	Lset1333
	.byte	4
Lset1334 = Ltmp1730-Lfunc_begin89
	.long	Lset1334
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1335 = Ltmp1731-Ltmp1730
	.long	Lset1335
	.byte	13
	.byte	6
	.byte	4
Lset1336 = Ltmp1732-Ltmp1731
	.long	Lset1336
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end89:
Lset1337 = Ldebug_frame_end90-Ldebug_frame_begin90
	.long	Lset1337
Ldebug_frame_begin90:
Lset1338 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1338
	.quad	Lfunc_begin90
Lset1339 = Lfunc_end90-Lfunc_begin90
	.quad	Lset1339
	.byte	4
Lset1340 = Ltmp1747-Lfunc_begin90
	.long	Lset1340
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1341 = Ltmp1748-Ltmp1747
	.long	Lset1341
	.byte	13
	.byte	6
	.byte	4
Lset1342 = Ltmp1749-Ltmp1748
	.long	Lset1342
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end90:
Lset1343 = Ldebug_frame_end91-Ldebug_frame_begin91
	.long	Lset1343
Ldebug_frame_begin91:
Lset1344 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1344
	.quad	Lfunc_begin91
Lset1345 = Lfunc_end91-Lfunc_begin91
	.quad	Lset1345
	.byte	4
Lset1346 = Ltmp1764-Lfunc_begin91
	.long	Lset1346
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1347 = Ltmp1765-Ltmp1764
	.long	Lset1347
	.byte	13
	.byte	6
	.byte	4
Lset1348 = Ltmp1766-Ltmp1765
	.long	Lset1348
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end91:
Lset1349 = Ldebug_frame_end92-Ldebug_frame_begin92
	.long	Lset1349
Ldebug_frame_begin92:
Lset1350 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1350
	.quad	Lfunc_begin92
Lset1351 = Lfunc_end92-Lfunc_begin92
	.quad	Lset1351
	.byte	4
Lset1352 = Ltmp1781-Lfunc_begin92
	.long	Lset1352
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1353 = Ltmp1782-Ltmp1781
	.long	Lset1353
	.byte	13
	.byte	6
	.byte	4
Lset1354 = Ltmp1783-Ltmp1782
	.long	Lset1354
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end92:
Lset1355 = Ldebug_frame_end93-Ldebug_frame_begin93
	.long	Lset1355
Ldebug_frame_begin93:
Lset1356 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1356
	.quad	Lfunc_begin93
Lset1357 = Lfunc_end93-Lfunc_begin93
	.quad	Lset1357
	.byte	4
Lset1358 = Ltmp1798-Lfunc_begin93
	.long	Lset1358
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1359 = Ltmp1799-Ltmp1798
	.long	Lset1359
	.byte	13
	.byte	6
	.byte	4
Lset1360 = Ltmp1800-Ltmp1799
	.long	Lset1360
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end93:
Lset1361 = Ldebug_frame_end94-Ldebug_frame_begin94
	.long	Lset1361
Ldebug_frame_begin94:
Lset1362 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1362
	.quad	Lfunc_begin94
Lset1363 = Lfunc_end94-Lfunc_begin94
	.quad	Lset1363
	.byte	4
Lset1364 = Ltmp1817-Lfunc_begin94
	.long	Lset1364
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1365 = Ltmp1818-Ltmp1817
	.long	Lset1365
	.byte	13
	.byte	6
	.byte	4
Lset1366 = Ltmp1819-Ltmp1818
	.long	Lset1366
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end94:
Lset1367 = Ldebug_frame_end95-Ldebug_frame_begin95
	.long	Lset1367
Ldebug_frame_begin95:
Lset1368 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1368
	.quad	Lfunc_begin95
Lset1369 = Lfunc_end95-Lfunc_begin95
	.quad	Lset1369
	.byte	4
Lset1370 = Ltmp1836-Lfunc_begin95
	.long	Lset1370
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1371 = Ltmp1837-Ltmp1836
	.long	Lset1371
	.byte	13
	.byte	6
	.align	2
Ldebug_frame_end95:
Lset1372 = Ldebug_frame_end96-Ldebug_frame_begin96
	.long	Lset1372
Ldebug_frame_begin96:
Lset1373 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1373
	.quad	Lfunc_begin96
Lset1374 = Lfunc_end96-Lfunc_begin96
	.quad	Lset1374
	.byte	4
Lset1375 = Ltmp1845-Lfunc_begin96
	.long	Lset1375
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1376 = Ltmp1846-Ltmp1845
	.long	Lset1376
	.byte	13
	.byte	6
	.byte	4
Lset1377 = Ltmp1847-Ltmp1846
	.long	Lset1377
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end96:
Lset1378 = Ldebug_frame_end97-Ldebug_frame_begin97
	.long	Lset1378
Ldebug_frame_begin97:
Lset1379 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1379
	.quad	Lfunc_begin97
Lset1380 = Lfunc_end97-Lfunc_begin97
	.quad	Lset1380
	.byte	4
Lset1381 = Ltmp1864-Lfunc_begin97
	.long	Lset1381
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1382 = Ltmp1865-Ltmp1864
	.long	Lset1382
	.byte	13
	.byte	6
	.byte	4
Lset1383 = Ltmp1866-Ltmp1865
	.long	Lset1383
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end97:
Lset1384 = Ldebug_frame_end98-Ldebug_frame_begin98
	.long	Lset1384
Ldebug_frame_begin98:
Lset1385 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1385
	.quad	Lfunc_begin98
Lset1386 = Lfunc_end98-Lfunc_begin98
	.quad	Lset1386
	.byte	4
Lset1387 = Ltmp1883-Lfunc_begin98
	.long	Lset1387
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1388 = Ltmp1884-Ltmp1883
	.long	Lset1388
	.byte	13
	.byte	6
	.byte	4
Lset1389 = Ltmp1885-Ltmp1884
	.long	Lset1389
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end98:
Lset1390 = Ldebug_frame_end99-Ldebug_frame_begin99
	.long	Lset1390
Ldebug_frame_begin99:
Lset1391 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1391
	.quad	Lfunc_begin99
Lset1392 = Lfunc_end99-Lfunc_begin99
	.quad	Lset1392
	.byte	4
Lset1393 = Ltmp1900-Lfunc_begin99
	.long	Lset1393
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1394 = Ltmp1901-Ltmp1900
	.long	Lset1394
	.byte	13
	.byte	6
	.byte	4
Lset1395 = Ltmp1902-Ltmp1901
	.long	Lset1395
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end99:
Lset1396 = Ldebug_frame_end100-Ldebug_frame_begin100
	.long	Lset1396
Ldebug_frame_begin100:
Lset1397 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1397
	.quad	Lfunc_begin100
Lset1398 = Lfunc_end100-Lfunc_begin100
	.quad	Lset1398
	.byte	4
Lset1399 = Ltmp1917-Lfunc_begin100
	.long	Lset1399
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1400 = Ltmp1918-Ltmp1917
	.long	Lset1400
	.byte	13
	.byte	6
	.byte	4
Lset1401 = Ltmp1919-Ltmp1918
	.long	Lset1401
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end100:
Lset1402 = Ldebug_frame_end101-Ldebug_frame_begin101
	.long	Lset1402
Ldebug_frame_begin101:
Lset1403 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1403
	.quad	Lfunc_begin101
Lset1404 = Lfunc_end101-Lfunc_begin101
	.quad	Lset1404
	.byte	4
Lset1405 = Ltmp1934-Lfunc_begin101
	.long	Lset1405
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1406 = Ltmp1935-Ltmp1934
	.long	Lset1406
	.byte	13
	.byte	6
	.byte	4
Lset1407 = Ltmp1936-Ltmp1935
	.long	Lset1407
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end101:
Lset1408 = Ldebug_frame_end102-Ldebug_frame_begin102
	.long	Lset1408
Ldebug_frame_begin102:
Lset1409 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1409
	.quad	Lfunc_begin102
Lset1410 = Lfunc_end102-Lfunc_begin102
	.quad	Lset1410
	.byte	4
Lset1411 = Ltmp1951-Lfunc_begin102
	.long	Lset1411
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1412 = Ltmp1952-Ltmp1951
	.long	Lset1412
	.byte	13
	.byte	6
	.byte	4
Lset1413 = Ltmp1953-Ltmp1952
	.long	Lset1413
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end102:
Lset1414 = Ldebug_frame_end103-Ldebug_frame_begin103
	.long	Lset1414
Ldebug_frame_begin103:
Lset1415 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1415
	.quad	Lfunc_begin103
Lset1416 = Lfunc_end103-Lfunc_begin103
	.quad	Lset1416
	.byte	4
Lset1417 = Ltmp1973-Lfunc_begin103
	.long	Lset1417
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1418 = Ltmp1974-Ltmp1973
	.long	Lset1418
	.byte	13
	.byte	6
	.byte	4
Lset1419 = Ltmp1975-Ltmp1974
	.long	Lset1419
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end103:
Lset1420 = Ldebug_frame_end104-Ldebug_frame_begin104
	.long	Lset1420
Ldebug_frame_begin104:
Lset1421 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1421
	.quad	Lfunc_begin104
Lset1422 = Lfunc_end104-Lfunc_begin104
	.quad	Lset1422
	.byte	4
Lset1423 = Ltmp1992-Lfunc_begin104
	.long	Lset1423
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1424 = Ltmp1993-Ltmp1992
	.long	Lset1424
	.byte	13
	.byte	6
	.byte	4
Lset1425 = Ltmp1994-Ltmp1993
	.long	Lset1425
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end104:
Lset1426 = Ldebug_frame_end105-Ldebug_frame_begin105
	.long	Lset1426
Ldebug_frame_begin105:
Lset1427 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1427
	.quad	Lfunc_begin105
Lset1428 = Lfunc_end105-Lfunc_begin105
	.quad	Lset1428
	.byte	4
Lset1429 = Ltmp2011-Lfunc_begin105
	.long	Lset1429
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1430 = Ltmp2012-Ltmp2011
	.long	Lset1430
	.byte	13
	.byte	6
	.byte	4
Lset1431 = Ltmp2013-Ltmp2012
	.long	Lset1431
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end105:
Lset1432 = Ldebug_frame_end106-Ldebug_frame_begin106
	.long	Lset1432
Ldebug_frame_begin106:
Lset1433 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1433
	.quad	Lfunc_begin106
Lset1434 = Lfunc_end106-Lfunc_begin106
	.quad	Lset1434
	.byte	4
Lset1435 = Ltmp2030-Lfunc_begin106
	.long	Lset1435
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1436 = Ltmp2031-Ltmp2030
	.long	Lset1436
	.byte	13
	.byte	6
	.byte	4
Lset1437 = Ltmp2032-Ltmp2031
	.long	Lset1437
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end106:
Lset1438 = Ldebug_frame_end107-Ldebug_frame_begin107
	.long	Lset1438
Ldebug_frame_begin107:
Lset1439 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1439
	.quad	Lfunc_begin107
Lset1440 = Lfunc_end107-Lfunc_begin107
	.quad	Lset1440
	.byte	4
Lset1441 = Ltmp2049-Lfunc_begin107
	.long	Lset1441
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1442 = Ltmp2050-Ltmp2049
	.long	Lset1442
	.byte	13
	.byte	6
	.byte	4
Lset1443 = Ltmp2051-Ltmp2050
	.long	Lset1443
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end107:
Lset1444 = Ldebug_frame_end108-Ldebug_frame_begin108
	.long	Lset1444
Ldebug_frame_begin108:
Lset1445 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1445
	.quad	Lfunc_begin108
Lset1446 = Lfunc_end108-Lfunc_begin108
	.quad	Lset1446
	.byte	4
Lset1447 = Ltmp2066-Lfunc_begin108
	.long	Lset1447
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1448 = Ltmp2067-Ltmp2066
	.long	Lset1448
	.byte	13
	.byte	6
	.byte	4
Lset1449 = Ltmp2068-Ltmp2067
	.long	Lset1449
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end108:
Lset1450 = Ldebug_frame_end109-Ldebug_frame_begin109
	.long	Lset1450
Ldebug_frame_begin109:
Lset1451 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1451
	.quad	Lfunc_begin109
Lset1452 = Lfunc_end109-Lfunc_begin109
	.quad	Lset1452
	.byte	4
Lset1453 = Ltmp2083-Lfunc_begin109
	.long	Lset1453
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1454 = Ltmp2084-Ltmp2083
	.long	Lset1454
	.byte	13
	.byte	6
	.byte	4
Lset1455 = Ltmp2085-Ltmp2084
	.long	Lset1455
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end109:
Lset1456 = Ldebug_frame_end110-Ldebug_frame_begin110
	.long	Lset1456
Ldebug_frame_begin110:
Lset1457 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1457
	.quad	Lfunc_begin110
Lset1458 = Lfunc_end110-Lfunc_begin110
	.quad	Lset1458
	.byte	4
Lset1459 = Ltmp2100-Lfunc_begin110
	.long	Lset1459
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1460 = Ltmp2101-Ltmp2100
	.long	Lset1460
	.byte	13
	.byte	6
	.byte	4
Lset1461 = Ltmp2102-Ltmp2101
	.long	Lset1461
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end110:
Lset1462 = Ldebug_frame_end111-Ldebug_frame_begin111
	.long	Lset1462
Ldebug_frame_begin111:
Lset1463 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1463
	.quad	Lfunc_begin111
Lset1464 = Lfunc_end111-Lfunc_begin111
	.quad	Lset1464
	.byte	4
Lset1465 = Ltmp2117-Lfunc_begin111
	.long	Lset1465
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1466 = Ltmp2118-Ltmp2117
	.long	Lset1466
	.byte	13
	.byte	6
	.byte	4
Lset1467 = Ltmp2119-Ltmp2118
	.long	Lset1467
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end111:
Lset1468 = Ldebug_frame_end112-Ldebug_frame_begin112
	.long	Lset1468
Ldebug_frame_begin112:
Lset1469 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1469
	.quad	Lfunc_begin112
Lset1470 = Lfunc_end112-Lfunc_begin112
	.quad	Lset1470
	.byte	4
Lset1471 = Ltmp2139-Lfunc_begin112
	.long	Lset1471
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1472 = Ltmp2140-Ltmp2139
	.long	Lset1472
	.byte	13
	.byte	6
	.byte	4
Lset1473 = Ltmp2141-Ltmp2140
	.long	Lset1473
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end112:
Lset1474 = Ldebug_frame_end113-Ldebug_frame_begin113
	.long	Lset1474
Ldebug_frame_begin113:
Lset1475 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1475
	.quad	Lfunc_begin113
Lset1476 = Lfunc_end113-Lfunc_begin113
	.quad	Lset1476
	.byte	4
Lset1477 = Ltmp2158-Lfunc_begin113
	.long	Lset1477
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1478 = Ltmp2159-Ltmp2158
	.long	Lset1478
	.byte	13
	.byte	6
	.byte	4
Lset1479 = Ltmp2160-Ltmp2159
	.long	Lset1479
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end113:
Lset1480 = Ldebug_frame_end114-Ldebug_frame_begin114
	.long	Lset1480
Ldebug_frame_begin114:
Lset1481 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1481
	.quad	Lfunc_begin114
Lset1482 = Lfunc_end114-Lfunc_begin114
	.quad	Lset1482
	.byte	4
Lset1483 = Ltmp2177-Lfunc_begin114
	.long	Lset1483
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1484 = Ltmp2178-Ltmp2177
	.long	Lset1484
	.byte	13
	.byte	6
	.byte	4
Lset1485 = Ltmp2179-Ltmp2178
	.long	Lset1485
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end114:
Lset1486 = Ldebug_frame_end115-Ldebug_frame_begin115
	.long	Lset1486
Ldebug_frame_begin115:
Lset1487 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1487
	.quad	Lfunc_begin115
Lset1488 = Lfunc_end115-Lfunc_begin115
	.quad	Lset1488
	.byte	4
Lset1489 = Ltmp2196-Lfunc_begin115
	.long	Lset1489
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1490 = Ltmp2197-Ltmp2196
	.long	Lset1490
	.byte	13
	.byte	6
	.byte	4
Lset1491 = Ltmp2198-Ltmp2197
	.long	Lset1491
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end115:
Lset1492 = Ldebug_frame_end116-Ldebug_frame_begin116
	.long	Lset1492
Ldebug_frame_begin116:
Lset1493 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1493
	.quad	Lfunc_begin116
Lset1494 = Lfunc_end116-Lfunc_begin116
	.quad	Lset1494
	.byte	4
Lset1495 = Ltmp2215-Lfunc_begin116
	.long	Lset1495
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1496 = Ltmp2216-Ltmp2215
	.long	Lset1496
	.byte	13
	.byte	6
	.byte	4
Lset1497 = Ltmp2217-Ltmp2216
	.long	Lset1497
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end116:
Lset1498 = Ldebug_frame_end117-Ldebug_frame_begin117
	.long	Lset1498
Ldebug_frame_begin117:
Lset1499 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1499
	.quad	Lfunc_begin117
Lset1500 = Lfunc_end117-Lfunc_begin117
	.quad	Lset1500
	.byte	4
Lset1501 = Ltmp2232-Lfunc_begin117
	.long	Lset1501
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1502 = Ltmp2233-Ltmp2232
	.long	Lset1502
	.byte	13
	.byte	6
	.byte	4
Lset1503 = Ltmp2234-Ltmp2233
	.long	Lset1503
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end117:
Lset1504 = Ldebug_frame_end118-Ldebug_frame_begin118
	.long	Lset1504
Ldebug_frame_begin118:
Lset1505 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1505
	.quad	Lfunc_begin118
Lset1506 = Lfunc_end118-Lfunc_begin118
	.quad	Lset1506
	.byte	4
Lset1507 = Ltmp2249-Lfunc_begin118
	.long	Lset1507
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1508 = Ltmp2250-Ltmp2249
	.long	Lset1508
	.byte	13
	.byte	6
	.byte	4
Lset1509 = Ltmp2251-Ltmp2250
	.long	Lset1509
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end118:
Lset1510 = Ldebug_frame_end119-Ldebug_frame_begin119
	.long	Lset1510
Ldebug_frame_begin119:
Lset1511 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1511
	.quad	Lfunc_begin119
Lset1512 = Lfunc_end119-Lfunc_begin119
	.quad	Lset1512
	.byte	4
Lset1513 = Ltmp2266-Lfunc_begin119
	.long	Lset1513
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1514 = Ltmp2267-Ltmp2266
	.long	Lset1514
	.byte	13
	.byte	6
	.byte	4
Lset1515 = Ltmp2268-Ltmp2267
	.long	Lset1515
	.byte	131
	.byte	5
	.byte	142
	.byte	4
	.byte	143
	.byte	3
	.align	2
Ldebug_frame_end119:
Lset1516 = Ldebug_frame_end120-Ldebug_frame_begin120
	.long	Lset1516
Ldebug_frame_begin120:
Lset1517 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1517
	.quad	Lfunc_begin120
Lset1518 = Lfunc_end120-Lfunc_begin120
	.quad	Lset1518
	.byte	4
Lset1519 = Ltmp2283-Lfunc_begin120
	.long	Lset1519
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1520 = Ltmp2284-Ltmp2283
	.long	Lset1520
	.byte	13
	.byte	6
	.byte	4
Lset1521 = Ltmp2285-Ltmp2284
	.long	Lset1521
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end120:
Lset1522 = Ldebug_frame_end121-Ldebug_frame_begin121
	.long	Lset1522
Ldebug_frame_begin121:
Lset1523 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1523
	.quad	Lfunc_begin121
Lset1524 = Lfunc_end121-Lfunc_begin121
	.quad	Lset1524
	.byte	4
Lset1525 = Ltmp2300-Lfunc_begin121
	.long	Lset1525
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1526 = Ltmp2301-Ltmp2300
	.long	Lset1526
	.byte	13
	.byte	6
	.byte	4
Lset1527 = Ltmp2302-Ltmp2301
	.long	Lset1527
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end121:
Lset1528 = Ldebug_frame_end122-Ldebug_frame_begin122
	.long	Lset1528
Ldebug_frame_begin122:
Lset1529 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1529
	.quad	Lfunc_begin122
Lset1530 = Lfunc_end122-Lfunc_begin122
	.quad	Lset1530
	.byte	4
Lset1531 = Ltmp2317-Lfunc_begin122
	.long	Lset1531
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1532 = Ltmp2318-Ltmp2317
	.long	Lset1532
	.byte	13
	.byte	6
	.byte	4
Lset1533 = Ltmp2319-Ltmp2318
	.long	Lset1533
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end122:
Lset1534 = Ldebug_frame_end123-Ldebug_frame_begin123
	.long	Lset1534
Ldebug_frame_begin123:
Lset1535 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1535
	.quad	Lfunc_begin123
Lset1536 = Lfunc_end123-Lfunc_begin123
	.quad	Lset1536
	.byte	4
Lset1537 = Ltmp2334-Lfunc_begin123
	.long	Lset1537
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1538 = Ltmp2335-Ltmp2334
	.long	Lset1538
	.byte	13
	.byte	6
	.byte	4
Lset1539 = Ltmp2336-Ltmp2335
	.long	Lset1539
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end123:
Lset1540 = Ldebug_frame_end124-Ldebug_frame_begin124
	.long	Lset1540
Ldebug_frame_begin124:
Lset1541 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1541
	.quad	Lfunc_begin124
Lset1542 = Lfunc_end124-Lfunc_begin124
	.quad	Lset1542
	.byte	4
Lset1543 = Ltmp2351-Lfunc_begin124
	.long	Lset1543
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1544 = Ltmp2352-Ltmp2351
	.long	Lset1544
	.byte	13
	.byte	6
	.byte	4
Lset1545 = Ltmp2353-Ltmp2352
	.long	Lset1545
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end124:
Lset1546 = Ldebug_frame_end125-Ldebug_frame_begin125
	.long	Lset1546
Ldebug_frame_begin125:
Lset1547 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1547
	.quad	Lfunc_begin125
Lset1548 = Lfunc_end125-Lfunc_begin125
	.quad	Lset1548
	.byte	4
Lset1549 = Ltmp2368-Lfunc_begin125
	.long	Lset1549
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1550 = Ltmp2369-Ltmp2368
	.long	Lset1550
	.byte	13
	.byte	6
	.byte	4
Lset1551 = Ltmp2370-Ltmp2369
	.long	Lset1551
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end125:
Lset1552 = Ldebug_frame_end126-Ldebug_frame_begin126
	.long	Lset1552
Ldebug_frame_begin126:
Lset1553 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1553
	.quad	Lfunc_begin126
Lset1554 = Lfunc_end126-Lfunc_begin126
	.quad	Lset1554
	.byte	4
Lset1555 = Ltmp2385-Lfunc_begin126
	.long	Lset1555
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1556 = Ltmp2386-Ltmp2385
	.long	Lset1556
	.byte	13
	.byte	6
	.byte	4
Lset1557 = Ltmp2387-Ltmp2386
	.long	Lset1557
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end126:
Lset1558 = Ldebug_frame_end127-Ldebug_frame_begin127
	.long	Lset1558
Ldebug_frame_begin127:
Lset1559 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1559
	.quad	Lfunc_begin127
Lset1560 = Lfunc_end127-Lfunc_begin127
	.quad	Lset1560
	.byte	4
Lset1561 = Ltmp2402-Lfunc_begin127
	.long	Lset1561
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1562 = Ltmp2403-Ltmp2402
	.long	Lset1562
	.byte	13
	.byte	6
	.byte	4
Lset1563 = Ltmp2404-Ltmp2403
	.long	Lset1563
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end127:
Lset1564 = Ldebug_frame_end128-Ldebug_frame_begin128
	.long	Lset1564
Ldebug_frame_begin128:
Lset1565 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1565
	.quad	Lfunc_begin128
Lset1566 = Lfunc_end128-Lfunc_begin128
	.quad	Lset1566
	.byte	4
Lset1567 = Ltmp2419-Lfunc_begin128
	.long	Lset1567
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1568 = Ltmp2420-Ltmp2419
	.long	Lset1568
	.byte	13
	.byte	6
	.byte	4
Lset1569 = Ltmp2421-Ltmp2420
	.long	Lset1569
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end128:
Lset1570 = Ldebug_frame_end129-Ldebug_frame_begin129
	.long	Lset1570
Ldebug_frame_begin129:
Lset1571 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1571
	.quad	Lfunc_begin129
Lset1572 = Lfunc_end129-Lfunc_begin129
	.quad	Lset1572
	.byte	4
Lset1573 = Ltmp2436-Lfunc_begin129
	.long	Lset1573
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1574 = Ltmp2437-Ltmp2436
	.long	Lset1574
	.byte	13
	.byte	6
	.byte	4
Lset1575 = Ltmp2438-Ltmp2437
	.long	Lset1575
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end129:
Lset1576 = Ldebug_frame_end130-Ldebug_frame_begin130
	.long	Lset1576
Ldebug_frame_begin130:
Lset1577 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1577
	.quad	Lfunc_begin130
Lset1578 = Lfunc_end130-Lfunc_begin130
	.quad	Lset1578
	.byte	4
Lset1579 = Ltmp2453-Lfunc_begin130
	.long	Lset1579
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1580 = Ltmp2454-Ltmp2453
	.long	Lset1580
	.byte	13
	.byte	6
	.byte	4
Lset1581 = Ltmp2455-Ltmp2454
	.long	Lset1581
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end130:
Lset1582 = Ldebug_frame_end131-Ldebug_frame_begin131
	.long	Lset1582
Ldebug_frame_begin131:
Lset1583 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1583
	.quad	Lfunc_begin131
Lset1584 = Lfunc_end131-Lfunc_begin131
	.quad	Lset1584
	.byte	4
Lset1585 = Ltmp2470-Lfunc_begin131
	.long	Lset1585
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1586 = Ltmp2471-Ltmp2470
	.long	Lset1586
	.byte	13
	.byte	6
	.byte	4
Lset1587 = Ltmp2472-Ltmp2471
	.long	Lset1587
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end131:
Lset1588 = Ldebug_frame_end132-Ldebug_frame_begin132
	.long	Lset1588
Ldebug_frame_begin132:
Lset1589 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1589
	.quad	Lfunc_begin132
Lset1590 = Lfunc_end132-Lfunc_begin132
	.quad	Lset1590
	.byte	4
Lset1591 = Ltmp2487-Lfunc_begin132
	.long	Lset1591
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1592 = Ltmp2488-Ltmp2487
	.long	Lset1592
	.byte	13
	.byte	6
	.byte	4
Lset1593 = Ltmp2489-Ltmp2488
	.long	Lset1593
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end132:
Lset1594 = Ldebug_frame_end133-Ldebug_frame_begin133
	.long	Lset1594
Ldebug_frame_begin133:
Lset1595 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1595
	.quad	Lfunc_begin133
Lset1596 = Lfunc_end133-Lfunc_begin133
	.quad	Lset1596
	.byte	4
Lset1597 = Ltmp2504-Lfunc_begin133
	.long	Lset1597
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1598 = Ltmp2505-Ltmp2504
	.long	Lset1598
	.byte	13
	.byte	6
	.byte	4
Lset1599 = Ltmp2506-Ltmp2505
	.long	Lset1599
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end133:
Lset1600 = Ldebug_frame_end134-Ldebug_frame_begin134
	.long	Lset1600
Ldebug_frame_begin134:
Lset1601 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1601
	.quad	Lfunc_begin134
Lset1602 = Lfunc_end134-Lfunc_begin134
	.quad	Lset1602
	.byte	4
Lset1603 = Ltmp2521-Lfunc_begin134
	.long	Lset1603
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1604 = Ltmp2522-Ltmp2521
	.long	Lset1604
	.byte	13
	.byte	6
	.byte	4
Lset1605 = Ltmp2523-Ltmp2522
	.long	Lset1605
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end134:
Lset1606 = Ldebug_frame_end135-Ldebug_frame_begin135
	.long	Lset1606
Ldebug_frame_begin135:
Lset1607 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1607
	.quad	Lfunc_begin135
Lset1608 = Lfunc_end135-Lfunc_begin135
	.quad	Lset1608
	.byte	4
Lset1609 = Ltmp2538-Lfunc_begin135
	.long	Lset1609
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1610 = Ltmp2539-Ltmp2538
	.long	Lset1610
	.byte	13
	.byte	6
	.byte	4
Lset1611 = Ltmp2540-Ltmp2539
	.long	Lset1611
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end135:
Lset1612 = Ldebug_frame_end136-Ldebug_frame_begin136
	.long	Lset1612
Ldebug_frame_begin136:
Lset1613 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1613
	.quad	Lfunc_begin136
Lset1614 = Lfunc_end136-Lfunc_begin136
	.quad	Lset1614
	.byte	4
Lset1615 = Ltmp2555-Lfunc_begin136
	.long	Lset1615
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1616 = Ltmp2556-Ltmp2555
	.long	Lset1616
	.byte	13
	.byte	6
	.byte	4
Lset1617 = Ltmp2557-Ltmp2556
	.long	Lset1617
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end136:
Lset1618 = Ldebug_frame_end137-Ldebug_frame_begin137
	.long	Lset1618
Ldebug_frame_begin137:
Lset1619 = Ldebug_frame_common-Lsection_debug_frame
	.long	Lset1619
	.quad	Lfunc_begin137
Lset1620 = Lfunc_end137-Lfunc_begin137
	.quad	Lset1620
	.byte	4
Lset1621 = Ltmp2572-Lfunc_begin137
	.long	Lset1621
	.byte	14
	.byte	16
	.byte	134
	.byte	2
	.byte	4
Lset1622 = Ltmp2573-Ltmp2572
	.long	Lset1622
	.byte	13
	.byte	6
	.byte	4
Lset1623 = Ltmp2574-Ltmp2573
	.long	Lset1623
	.byte	131
	.byte	4
	.byte	142
	.byte	3
	.align	2
Ldebug_frame_end137:
	.section	__DWARF,__debug_info,regular,debug
Linfo_begin1:
	.long	33518
	.short	2
Lset1624 = Labbrev_begin-Lsection_abbrev
	.long	Lset1624
	.byte	8
	.byte	1
	.ascii	 "4.2.1 (Based on Apple Inc. build 5658) (LLVM build 2336.11.00)"
	.byte	0
	.byte	1
	.ascii	 "atomic.c"
	.byte	0
	.quad	0
	.long	0
	.ascii	 "/Users/lundman/src/zfs/osx.zfs/x/zfs/lib/libspl/asm-generic/"
	.byte	0
	.byte	1
	.byte	2
	.long	231
	.ascii	 "membar_enter"
	.byte	0
	.ascii	 "membar_enter"
	.byte	0
	.byte	1
	.short	426
	.byte	1
	.byte	1
	.quad	Lfunc_begin1
	.quad	Lfunc_end1
	.byte	1
	.byte	86
	.byte	3
	.quad	Ltmp3
	.quad	Ltmp4
	.byte	0
	.byte	2
	.long	301
	.ascii	 "membar_exit"
	.byte	0
	.ascii	 "membar_exit"
	.byte	0
	.byte	1
	.short	431
	.byte	1
	.byte	1
	.quad	Lfunc_begin2
	.quad	Lfunc_end2
	.byte	1
	.byte	86
	.byte	3
	.quad	Ltmp8
	.quad	Ltmp9
	.byte	0
	.byte	2
	.long	379
	.ascii	 "membar_producer"
	.byte	0
	.ascii	 "membar_producer"
	.byte	0
	.byte	1
	.short	436
	.byte	1
	.byte	1
	.quad	Lfunc_begin3
	.quad	Lfunc_end3
	.byte	1
	.byte	86
	.byte	3
	.quad	Ltmp13
	.quad	Ltmp14
	.byte	0
	.byte	2
	.long	457
	.ascii	 "membar_consumer"
	.byte	0
	.ascii	 "membar_consumer"
	.byte	0
	.byte	1
	.short	441
	.byte	1
	.byte	1
	.quad	Lfunc_begin4
	.quad	Lfunc_end4
	.byte	1
	.byte	86
	.byte	3
	.quad	Ltmp18
	.quad	Ltmp19
	.byte	0
	.byte	4
	.byte	5
	.ascii	 "int"
	.byte	0
	.byte	4
	.byte	5
	.long	865
	.ascii	 "atomic_clear_long_excl"
	.byte	0
	.ascii	 "atomic_clear_long_excl"
	.byte	0
	.byte	1
	.short	410
	.byte	1
	.long	457
	.byte	1
	.quad	Lfunc_begin5
	.quad	Lfunc_end5
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	409
	.long	33310
Lset1625 = Ldebug_loc-Lsection_loc
	.long	Lset1625
	.byte	6
	.ascii	 "value"
	.byte	0
	.byte	1
	.short	409
	.long	2199
Lset1626 = Ldebug_loc4-Lsection_loc
	.long	Lset1626
	.byte	7
	.quad	Ltmp26
	.quad	Ltmp51
	.byte	8
	.ascii	 "bit"
	.byte	0
	.byte	1
	.short	411
	.long	1897
	.byte	1
	.byte	80
	.quad	Ltmp35
	.byte	9
	.long	701
	.quad	Ltmp26
	.quad	Ltmp33
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	413
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp29
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	413
	.long	33335
	.byte	12
	.long	0
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	413
	.long	33350
	.byte	0
	.byte	0
	.byte	9
	.long	784
	.quad	Ltmp37
	.quad	Ltmp42
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	416
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp38
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	416
	.long	33335
	.byte	12
	.long	48
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	416
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp44
	.quad	Ltmp49
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	420
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp45
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	420
	.long	33335
	.byte	12
	.long	96
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	420
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	1262
	.ascii	 "atomic_set_long_excl"
	.byte	0
	.ascii	 "atomic_set_long_excl"
	.byte	0
	.byte	1
	.short	394
	.byte	1
	.long	457
	.byte	1
	.quad	Lfunc_begin6
	.quad	Lfunc_end6
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	393
	.long	33310
Lset1627 = Ldebug_loc8-Lsection_loc
	.long	Lset1627
	.byte	6
	.ascii	 "value"
	.byte	0
	.byte	1
	.short	393
	.long	2199
Lset1628 = Ldebug_loc12-Lsection_loc
	.long	Lset1628
	.byte	7
	.quad	Ltmp58
	.quad	Ltmp83
	.byte	8
	.ascii	 "bit"
	.byte	0
	.byte	1
	.short	395
	.long	1897
	.byte	1
	.byte	80
	.quad	Ltmp67
	.byte	9
	.long	1098
	.quad	Ltmp58
	.quad	Ltmp65
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	397
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp61
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	397
	.long	33335
	.byte	12
	.long	144
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	397
	.long	33350
	.byte	0
	.byte	0
	.byte	9
	.long	1181
	.quad	Ltmp69
	.quad	Ltmp74
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	400
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp70
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	400
	.long	33335
	.byte	12
	.long	192
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	400
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp76
	.quad	Ltmp81
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	404
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp77
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	404
	.long	33335
	.byte	12
	.long	240
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	404
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	13
	.byte	8
	.byte	1
	.byte	0
	.byte	5
	.long	1569
	.ascii	 "atomic_swap_ptr"
	.byte	0
	.ascii	 "atomic_swap_ptr"
	.byte	0
	.byte	1
	.short	381
	.byte	1
	.long	1262
	.byte	1
	.quad	Lfunc_begin7
	.quad	Lfunc_end7
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	380
	.long	1262
Lset1629 = Ldebug_loc16-Lsection_loc
	.long	Lset1629
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	380
	.long	1262
Lset1630 = Ldebug_loc20-Lsection_loc
	.long	Lset1630
	.byte	7
	.quad	Ltmp90
	.quad	Ltmp108
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	382
	.long	1262
	.byte	1
	.byte	95
	.quad	Ltmp99
	.byte	9
	.long	1488
	.quad	Ltmp90
	.quad	Ltmp97
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	384
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp93
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	384
	.long	33335
	.byte	12
	.long	288
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	384
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp101
	.quad	Ltmp106
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	387
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp102
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	387
	.long	33335
	.byte	12
	.long	336
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	387
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	7
	.ascii	 "long long unsigned int"
	.byte	0
	.byte	8
	.byte	14
	.long	1569
	.ascii	 "uint64_t"
	.byte	0
	.byte	1
	.byte	59
	.byte	5
	.long	1876
	.ascii	 "atomic_swap_64"
	.byte	0
	.ascii	 "atomic_swap_64"
	.byte	0
	.byte	1
	.short	378
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin8
	.quad	Lfunc_end8
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	378
	.long	33358
Lset1631 = Ldebug_loc24-Lsection_loc
	.long	Lset1631
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	378
	.long	1595
Lset1632 = Ldebug_loc28-Lsection_loc
	.long	Lset1632
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	378
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp117
	.byte	12
	.long	384
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	378
	.long	1595
	.byte	1
	.byte	95
	.quad	Ltmp122
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	378
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp123
	.byte	15
	.long	1833
	.long	432
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	378
	.long	33335
	.byte	12
	.long	480
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	378
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	528
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	378
	.long	33335
	.byte	12
	.long	576
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	378
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	7
	.ascii	 "long unsigned int"
	.byte	0
	.byte	8
	.byte	14
	.long	1876
	.ascii	 "ulong_t"
	.byte	0
	.byte	1
	.byte	47
	.byte	5
	.long	2183
	.ascii	 "atomic_swap_ulong"
	.byte	0
	.ascii	 "atomic_swap_ulong"
	.byte	0
	.byte	1
	.short	377
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin9
	.quad	Lfunc_end9
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	377
	.long	33310
Lset1633 = Ldebug_loc32-Lsection_loc
	.long	Lset1633
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	377
	.long	1897
Lset1634 = Ldebug_loc36-Lsection_loc
	.long	Lset1634
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	377
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp138
	.byte	12
	.long	624
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	377
	.long	1897
	.byte	1
	.byte	95
	.quad	Ltmp143
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	377
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp144
	.byte	15
	.long	2140
	.long	672
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	377
	.long	33335
	.byte	12
	.long	720
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	377
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	768
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	377
	.long	33335
	.byte	12
	.long	816
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	377
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	7
	.ascii	 "unsigned int"
	.byte	0
	.byte	4
	.byte	14
	.long	2183
	.ascii	 "uint_t"
	.byte	0
	.byte	1
	.byte	45
	.byte	5
	.long	2482
	.ascii	 "atomic_swap_uint"
	.byte	0
	.ascii	 "atomic_swap_uint"
	.byte	0
	.byte	1
	.short	376
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin10
	.quad	Lfunc_end10
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	376
	.long	33366
Lset1635 = Ldebug_loc40-Lsection_loc
	.long	Lset1635
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	376
	.long	2199
Lset1636 = Ldebug_loc44-Lsection_loc
	.long	Lset1636
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	376
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp159
	.byte	12
	.long	864
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	376
	.long	2199
	.byte	1
	.byte	95
	.quad	Ltmp164
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	376
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp165
	.byte	15
	.long	2439
	.long	912
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	376
	.long	33335
	.byte	12
	.long	960
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	376
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	1008
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	376
	.long	33335
	.byte	12
	.long	1056
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	376
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	14
	.long	2183
	.ascii	 "uint32_t"
	.byte	0
	.byte	1
	.byte	55
	.byte	5
	.long	2763
	.ascii	 "atomic_swap_32"
	.byte	0
	.ascii	 "atomic_swap_32"
	.byte	0
	.byte	1
	.short	375
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin11
	.quad	Lfunc_end11
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	375
	.long	33374
Lset1637 = Ldebug_loc48-Lsection_loc
	.long	Lset1637
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	375
	.long	2482
Lset1638 = Ldebug_loc52-Lsection_loc
	.long	Lset1638
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	375
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp180
	.byte	12
	.long	1104
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	375
	.long	2482
	.byte	1
	.byte	95
	.quad	Ltmp185
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	375
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp186
	.byte	15
	.long	2720
	.long	1152
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	375
	.long	33335
	.byte	12
	.long	1200
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	375
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	1248
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	375
	.long	33335
	.byte	12
	.long	1296
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	375
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	7
	.ascii	 "short unsigned int"
	.byte	0
	.byte	2
	.byte	14
	.long	2763
	.ascii	 "ushort_t"
	.byte	0
	.byte	1
	.byte	44
	.byte	5
	.long	3072
	.ascii	 "atomic_swap_ushort"
	.byte	0
	.ascii	 "atomic_swap_ushort"
	.byte	0
	.byte	1
	.short	374
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin12
	.quad	Lfunc_end12
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	374
	.long	33382
Lset1639 = Ldebug_loc56-Lsection_loc
	.long	Lset1639
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	374
	.long	2785
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	374
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp199
	.byte	12
	.long	1344
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	374
	.long	2785
	.byte	1
	.byte	95
	.quad	Ltmp204
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	374
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp205
	.byte	15
	.long	3029
	.long	1392
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	374
	.long	33335
	.byte	12
	.long	1440
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	374
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	1488
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	374
	.long	33335
	.byte	12
	.long	1536
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	374
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	14
	.long	2763
	.ascii	 "uint16_t"
	.byte	0
	.byte	1
	.byte	50
	.byte	5
	.long	3351
	.ascii	 "atomic_swap_16"
	.byte	0
	.ascii	 "atomic_swap_16"
	.byte	0
	.byte	1
	.short	373
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin13
	.quad	Lfunc_end13
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	373
	.long	33390
Lset1640 = Ldebug_loc60-Lsection_loc
	.long	Lset1640
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	373
	.long	3072
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	373
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp218
	.byte	12
	.long	1584
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	373
	.long	3072
	.byte	1
	.byte	95
	.quad	Ltmp223
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	373
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp224
	.byte	15
	.long	3308
	.long	1632
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	373
	.long	33335
	.byte	12
	.long	1680
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	373
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	1728
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	373
	.long	33335
	.byte	12
	.long	1776
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	373
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	8
	.ascii	 "unsigned char"
	.byte	0
	.byte	1
	.byte	14
	.long	3351
	.ascii	 "uchar_t"
	.byte	0
	.byte	1
	.byte	43
	.byte	5
	.long	3652
	.ascii	 "atomic_swap_uchar"
	.byte	0
	.ascii	 "atomic_swap_uchar"
	.byte	0
	.byte	1
	.short	372
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin14
	.quad	Lfunc_end14
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	372
	.long	33398
Lset1641 = Ldebug_loc64-Lsection_loc
	.long	Lset1641
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	372
	.long	3368
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	372
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp237
	.byte	12
	.long	1824
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	372
	.long	3368
	.byte	1
	.byte	95
	.quad	Ltmp242
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	372
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp243
	.byte	15
	.long	3609
	.long	1872
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	372
	.long	33335
	.byte	12
	.long	1920
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	372
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	1968
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	372
	.long	33335
	.byte	12
	.long	2016
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	372
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	14
	.long	3351
	.ascii	 "uint8_t"
	.byte	0
	.byte	1
	.byte	45
	.byte	5
	.long	3928
	.ascii	 "atomic_swap_8"
	.byte	0
	.ascii	 "atomic_swap_8"
	.byte	0
	.byte	1
	.short	371
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin15
	.quad	Lfunc_end15
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	371
	.long	33406
Lset1642 = Ldebug_loc68-Lsection_loc
	.long	Lset1642
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	371
	.long	3652
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	371
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp256
	.byte	12
	.long	2064
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	371
	.long	3652
	.byte	1
	.byte	95
	.quad	Ltmp261
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	371
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp262
	.byte	15
	.long	3885
	.long	2112
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	371
	.long	33335
	.byte	12
	.long	2160
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	371
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	2208
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	371
	.long	33335
	.byte	12
	.long	2256
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	371
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	4246
	.ascii	 "atomic_cas_ptr"
	.byte	0
	.ascii	 "atomic_cas_ptr"
	.byte	0
	.byte	1
	.short	343
	.byte	1
	.long	1262
	.byte	1
	.quad	Lfunc_begin16
	.quad	Lfunc_end16
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	342
	.long	1262
Lset1643 = Ldebug_loc72-Lsection_loc
	.long	Lset1643
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	342
	.long	1262
Lset1644 = Ldebug_loc76-Lsection_loc
	.long	Lset1644
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	342
	.long	1262
Lset1645 = Ldebug_loc80-Lsection_loc
	.long	Lset1645
	.byte	7
	.quad	Ltmp276
	.quad	Ltmp295
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	344
	.long	1262
	.byte	1
	.byte	92
	.quad	Ltmp286
	.byte	9
	.long	4165
	.quad	Ltmp276
	.quad	Ltmp284
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	346
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp280
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	346
	.long	33335
	.byte	12
	.long	2304
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	346
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp288
	.quad	Ltmp293
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	350
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp289
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	350
	.long	33335
	.byte	12
	.long	2352
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	350
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	4363
	.ascii	 "casptr"
	.byte	0
	.ascii	 "casptr"
	.byte	0
	.byte	1
	.short	468
	.byte	1
	.long	1262
	.byte	1
	.quad	Lfunc_begin17
	.quad	Lfunc_end17
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	467
	.long	1262
Lset1646 = Ldebug_loc84-Lsection_loc
	.long	Lset1646
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	467
	.long	1262
Lset1647 = Ldebug_loc88-Lsection_loc
	.long	Lset1647
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	467
	.long	1262
Lset1648 = Ldebug_loc92-Lsection_loc
	.long	Lset1648
	.byte	3
	.quad	Ltmp305
	.quad	Ltmp306
	.byte	0
	.byte	5
	.long	4655
	.ascii	 "atomic_cas_64"
	.byte	0
	.ascii	 "atomic_cas_64"
	.byte	0
	.byte	1
	.short	340
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin18
	.quad	Lfunc_end18
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	340
	.long	33358
Lset1649 = Ldebug_loc96-Lsection_loc
	.long	Lset1649
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	340
	.long	1595
Lset1650 = Ldebug_loc100-Lsection_loc
	.long	Lset1650
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	340
	.long	1595
Lset1651 = Ldebug_loc104-Lsection_loc
	.long	Lset1651
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	340
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp317
	.byte	12
	.long	2400
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	340
	.long	1595
	.byte	1
	.byte	92
	.quad	Ltmp322
	.byte	15
	.long	4574
	.long	2448
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	340
	.long	33335
	.byte	12
	.long	2496
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	340
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp323
	.quad	Ltmp328
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	340
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp324
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	340
	.long	33335
	.byte	12
	.long	2544
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	340
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	4770
	.ascii	 "cas64"
	.byte	0
	.ascii	 "cas64"
	.byte	0
	.byte	1
	.short	458
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin19
	.quad	Lfunc_end19
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	457
	.long	33358
Lset1652 = Ldebug_loc108-Lsection_loc
	.long	Lset1652
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	457
	.long	1595
Lset1653 = Ldebug_loc112-Lsection_loc
	.long	Lset1653
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	457
	.long	1595
Lset1654 = Ldebug_loc116-Lsection_loc
	.long	Lset1654
	.byte	3
	.quad	Ltmp340
	.quad	Ltmp341
	.byte	0
	.byte	5
	.long	5068
	.ascii	 "atomic_cas_ulong"
	.byte	0
	.ascii	 "atomic_cas_ulong"
	.byte	0
	.byte	1
	.short	339
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin20
	.quad	Lfunc_end20
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	339
	.long	33310
Lset1655 = Ldebug_loc120-Lsection_loc
	.long	Lset1655
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	339
	.long	1897
Lset1656 = Ldebug_loc124-Lsection_loc
	.long	Lset1656
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	339
	.long	1897
Lset1657 = Ldebug_loc128-Lsection_loc
	.long	Lset1657
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	339
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp352
	.byte	12
	.long	2592
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	339
	.long	1897
	.byte	1
	.byte	92
	.quad	Ltmp357
	.byte	15
	.long	4987
	.long	2640
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	339
	.long	33335
	.byte	12
	.long	2688
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	339
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp358
	.quad	Ltmp363
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	339
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp359
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	339
	.long	33335
	.byte	12
	.long	2736
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	339
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	5187
	.ascii	 "caslong"
	.byte	0
	.ascii	 "caslong"
	.byte	0
	.byte	1
	.short	463
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin21
	.quad	Lfunc_end21
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	462
	.long	33310
Lset1658 = Ldebug_loc132-Lsection_loc
	.long	Lset1658
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	462
	.long	1897
Lset1659 = Ldebug_loc136-Lsection_loc
	.long	Lset1659
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	462
	.long	1897
Lset1660 = Ldebug_loc140-Lsection_loc
	.long	Lset1660
	.byte	3
	.quad	Ltmp375
	.quad	Ltmp376
	.byte	0
	.byte	5
	.long	5483
	.ascii	 "atomic_cas_uint"
	.byte	0
	.ascii	 "atomic_cas_uint"
	.byte	0
	.byte	1
	.short	338
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin22
	.quad	Lfunc_end22
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	338
	.long	33366
Lset1661 = Ldebug_loc144-Lsection_loc
	.long	Lset1661
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	338
	.long	2199
Lset1662 = Ldebug_loc148-Lsection_loc
	.long	Lset1662
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	338
	.long	2199
Lset1663 = Ldebug_loc152-Lsection_loc
	.long	Lset1663
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	338
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp387
	.byte	12
	.long	2784
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	338
	.long	2199
	.byte	1
	.byte	92
	.quad	Ltmp392
	.byte	15
	.long	5402
	.long	2832
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	338
	.long	33335
	.byte	12
	.long	2880
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	338
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp393
	.quad	Ltmp398
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	338
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp394
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	338
	.long	33335
	.byte	12
	.long	2928
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	338
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	5775
	.ascii	 "atomic_cas_32"
	.byte	0
	.ascii	 "atomic_cas_32"
	.byte	0
	.byte	1
	.short	337
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin23
	.quad	Lfunc_end23
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	337
	.long	33374
Lset1664 = Ldebug_loc156-Lsection_loc
	.long	Lset1664
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	337
	.long	2482
Lset1665 = Ldebug_loc160-Lsection_loc
	.long	Lset1665
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	337
	.long	2482
Lset1666 = Ldebug_loc164-Lsection_loc
	.long	Lset1666
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	337
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp411
	.byte	12
	.long	2976
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	337
	.long	2482
	.byte	1
	.byte	92
	.quad	Ltmp416
	.byte	15
	.long	5694
	.long	3024
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	337
	.long	33335
	.byte	12
	.long	3072
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	337
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp417
	.quad	Ltmp422
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	337
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp418
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	337
	.long	33335
	.byte	12
	.long	3120
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	337
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	5890
	.ascii	 "cas32"
	.byte	0
	.ascii	 "cas32"
	.byte	0
	.byte	1
	.short	453
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin24
	.quad	Lfunc_end24
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	452
	.long	33374
Lset1667 = Ldebug_loc168-Lsection_loc
	.long	Lset1667
	.byte	6
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	452
	.long	2482
Lset1668 = Ldebug_loc172-Lsection_loc
	.long	Lset1668
	.byte	6
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	452
	.long	2482
Lset1669 = Ldebug_loc176-Lsection_loc
	.long	Lset1669
	.byte	3
	.quad	Ltmp434
	.quad	Ltmp435
	.byte	0
	.byte	5
	.long	6186
	.ascii	 "atomic_cas_ushort"
	.byte	0
	.ascii	 "atomic_cas_ushort"
	.byte	0
	.byte	1
	.short	336
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin25
	.quad	Lfunc_end25
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	336
	.long	33382
Lset1670 = Ldebug_loc180-Lsection_loc
	.long	Lset1670
	.byte	16
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	336
	.long	2785
	.byte	1
	.byte	83
	.byte	16
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	336
	.long	2785
	.byte	1
	.byte	94
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	336
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp442
	.byte	12
	.long	3168
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	336
	.long	2785
	.byte	1
	.byte	92
	.quad	Ltmp447
	.byte	15
	.long	6105
	.long	3216
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	336
	.long	33335
	.byte	12
	.long	3264
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	336
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp448
	.quad	Ltmp453
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	336
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp449
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	336
	.long	33335
	.byte	12
	.long	3312
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	336
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	6474
	.ascii	 "atomic_cas_16"
	.byte	0
	.ascii	 "atomic_cas_16"
	.byte	0
	.byte	1
	.short	335
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin26
	.quad	Lfunc_end26
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	335
	.long	33390
Lset1671 = Ldebug_loc184-Lsection_loc
	.long	Lset1671
	.byte	16
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	335
	.long	3072
	.byte	1
	.byte	83
	.byte	16
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	335
	.long	3072
	.byte	1
	.byte	94
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	335
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp462
	.byte	12
	.long	3360
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	335
	.long	3072
	.byte	1
	.byte	92
	.quad	Ltmp467
	.byte	15
	.long	6393
	.long	3408
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	335
	.long	33335
	.byte	12
	.long	3456
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	335
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp468
	.quad	Ltmp473
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	335
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp469
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	335
	.long	33335
	.byte	12
	.long	3504
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	335
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	6768
	.ascii	 "atomic_cas_uchar"
	.byte	0
	.ascii	 "atomic_cas_uchar"
	.byte	0
	.byte	1
	.short	334
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin27
	.quad	Lfunc_end27
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	334
	.long	33398
Lset1672 = Ldebug_loc188-Lsection_loc
	.long	Lset1672
	.byte	16
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	334
	.long	3368
	.byte	1
	.byte	83
	.byte	16
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	334
	.long	3368
	.byte	1
	.byte	94
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	334
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp482
	.byte	12
	.long	3552
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	334
	.long	3368
	.byte	1
	.byte	92
	.quad	Ltmp487
	.byte	15
	.long	6687
	.long	3600
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	334
	.long	33335
	.byte	12
	.long	3648
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	334
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp488
	.quad	Ltmp493
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	334
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp489
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	334
	.long	33335
	.byte	12
	.long	3696
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	334
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	7054
	.ascii	 "atomic_cas_8"
	.byte	0
	.ascii	 "atomic_cas_8"
	.byte	0
	.byte	1
	.short	333
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin28
	.quad	Lfunc_end28
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	333
	.long	33406
Lset1673 = Ldebug_loc192-Lsection_loc
	.long	Lset1673
	.byte	16
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	333
	.long	3652
	.byte	1
	.byte	83
	.byte	16
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	333
	.long	3652
	.byte	1
	.byte	94
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	333
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp502
	.byte	12
	.long	3744
	.byte	8
	.ascii	 "old"
	.byte	0
	.byte	1
	.short	333
	.long	3652
	.byte	1
	.byte	92
	.quad	Ltmp507
	.byte	15
	.long	6973
	.long	3792
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	333
	.long	33335
	.byte	12
	.long	3840
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	333
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp508
	.quad	Ltmp513
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	333
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp509
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	333
	.long	33335
	.byte	12
	.long	3888
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	333
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	7159
	.ascii	 "cas8"
	.byte	0
	.ascii	 "cas8"
	.byte	0
	.byte	1
	.short	448
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin29
	.quad	Lfunc_end29
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	447
	.long	33406
Lset1674 = Ldebug_loc196-Lsection_loc
	.long	Lset1674
	.byte	17
	.ascii	 "arg1"
	.byte	0
	.byte	1
	.short	447
	.long	3652
	.byte	17
	.ascii	 "arg2"
	.byte	0
	.byte	1
	.short	447
	.long	3652
	.byte	3
	.quad	Ltmp521
	.quad	Ltmp522
	.byte	0
	.byte	5
	.long	7427
	.ascii	 "atomic_and_64_nv"
	.byte	0
	.ascii	 "atomic_and_64_nv"
	.byte	0
	.byte	1
	.short	314
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin30
	.quad	Lfunc_end30
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	314
	.long	33358
Lset1675 = Ldebug_loc200-Lsection_loc
	.long	Lset1675
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	314
	.long	1595
Lset1676 = Ldebug_loc204-Lsection_loc
	.long	Lset1676
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	314
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp531
	.byte	12
	.long	3936
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	314
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp537
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	314
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp538
	.byte	15
	.long	7384
	.long	3984
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	314
	.long	33335
	.byte	12
	.long	4032
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	314
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	4080
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	314
	.long	33335
	.byte	12
	.long	4128
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	314
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	7701
	.ascii	 "atomic_and_ulong_nv"
	.byte	0
	.ascii	 "atomic_and_ulong_nv"
	.byte	0
	.byte	1
	.short	313
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin31
	.quad	Lfunc_end31
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	313
	.long	33310
Lset1677 = Ldebug_loc208-Lsection_loc
	.long	Lset1677
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	313
	.long	1897
Lset1678 = Ldebug_loc212-Lsection_loc
	.long	Lset1678
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	313
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp553
	.byte	12
	.long	4176
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	313
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp559
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	313
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp560
	.byte	15
	.long	7658
	.long	4224
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	313
	.long	33335
	.byte	12
	.long	4272
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	313
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	4320
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	313
	.long	33335
	.byte	12
	.long	4368
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	313
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	7973
	.ascii	 "atomic_and_uint_nv"
	.byte	0
	.ascii	 "atomic_and_uint_nv"
	.byte	0
	.byte	1
	.short	312
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin32
	.quad	Lfunc_end32
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	312
	.long	33366
Lset1679 = Ldebug_loc216-Lsection_loc
	.long	Lset1679
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	312
	.long	2199
Lset1680 = Ldebug_loc220-Lsection_loc
	.long	Lset1680
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	312
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp575
	.byte	12
	.long	4416
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	312
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp581
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	312
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp582
	.byte	15
	.long	7930
	.long	4464
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	312
	.long	33335
	.byte	12
	.long	4512
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	312
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	4560
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	312
	.long	33335
	.byte	12
	.long	4608
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	312
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	8241
	.ascii	 "atomic_and_32_nv"
	.byte	0
	.ascii	 "atomic_and_32_nv"
	.byte	0
	.byte	1
	.short	311
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin33
	.quad	Lfunc_end33
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	311
	.long	33374
Lset1681 = Ldebug_loc224-Lsection_loc
	.long	Lset1681
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	311
	.long	2482
Lset1682 = Ldebug_loc228-Lsection_loc
	.long	Lset1682
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	311
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp597
	.byte	12
	.long	4656
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	311
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp603
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	311
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp604
	.byte	15
	.long	8198
	.long	4704
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	311
	.long	33335
	.byte	12
	.long	4752
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	311
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	4800
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	311
	.long	33335
	.byte	12
	.long	4848
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	311
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	8515
	.ascii	 "atomic_and_ushort_nv"
	.byte	0
	.ascii	 "atomic_and_ushort_nv"
	.byte	0
	.byte	1
	.short	310
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin34
	.quad	Lfunc_end34
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	310
	.long	33382
Lset1683 = Ldebug_loc232-Lsection_loc
	.long	Lset1683
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	310
	.long	2785
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	310
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp617
	.byte	12
	.long	4896
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	310
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp623
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	310
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp624
	.byte	15
	.long	8472
	.long	4944
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	310
	.long	33335
	.byte	12
	.long	4992
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	310
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	5040
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	310
	.long	33335
	.byte	12
	.long	5088
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	310
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	8781
	.ascii	 "atomic_and_16_nv"
	.byte	0
	.ascii	 "atomic_and_16_nv"
	.byte	0
	.byte	1
	.short	309
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin35
	.quad	Lfunc_end35
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	309
	.long	33390
Lset1684 = Ldebug_loc236-Lsection_loc
	.long	Lset1684
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	309
	.long	3072
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	309
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp637
	.byte	12
	.long	5136
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	309
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp643
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	309
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp644
	.byte	15
	.long	8738
	.long	5184
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	309
	.long	33335
	.byte	12
	.long	5232
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	309
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	5280
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	309
	.long	33335
	.byte	12
	.long	5328
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	309
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	9053
	.ascii	 "atomic_and_uchar_nv"
	.byte	0
	.ascii	 "atomic_and_uchar_nv"
	.byte	0
	.byte	1
	.short	308
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin36
	.quad	Lfunc_end36
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	308
	.long	33398
Lset1685 = Ldebug_loc240-Lsection_loc
	.long	Lset1685
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	308
	.long	3368
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	308
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp657
	.byte	12
	.long	5376
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	308
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp663
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	308
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp664
	.byte	15
	.long	9010
	.long	5424
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	308
	.long	33335
	.byte	12
	.long	5472
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	308
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	5520
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	308
	.long	33335
	.byte	12
	.long	5568
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	308
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	9317
	.ascii	 "atomic_and_8_nv"
	.byte	0
	.ascii	 "atomic_and_8_nv"
	.byte	0
	.byte	1
	.short	307
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin37
	.quad	Lfunc_end37
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	307
	.long	33406
Lset1686 = Ldebug_loc244-Lsection_loc
	.long	Lset1686
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	307
	.long	3652
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	307
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp677
	.byte	12
	.long	5616
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	307
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp683
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	307
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp684
	.byte	15
	.long	9274
	.long	5664
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	307
	.long	33335
	.byte	12
	.long	5712
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	307
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	5760
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	307
	.long	33335
	.byte	12
	.long	5808
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	307
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	9589
	.ascii	 "atomic_and_long_nv"
	.byte	0
	.ascii	 "atomic_and_long_nv"
	.byte	0
	.byte	1
	.short	306
	.byte	1
	.long	1876
	.byte	1
	.quad	Lfunc_begin38
	.quad	Lfunc_end38
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	306
	.long	33422
Lset1687 = Ldebug_loc248-Lsection_loc
	.long	Lset1687
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	306
	.long	1876
Lset1688 = Ldebug_loc252-Lsection_loc
	.long	Lset1688
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	306
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp699
	.byte	12
	.long	5856
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	306
	.long	1876
	.byte	1
	.byte	83
	.quad	Ltmp705
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	306
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp706
	.byte	15
	.long	9546
	.long	5904
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	306
	.long	33335
	.byte	12
	.long	5952
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	306
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	6000
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	306
	.long	33335
	.byte	12
	.long	6048
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	306
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	9855
	.ascii	 "atomic_or_64_nv"
	.byte	0
	.ascii	 "atomic_or_64_nv"
	.byte	0
	.byte	1
	.short	293
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin39
	.quad	Lfunc_end39
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	293
	.long	33358
Lset1689 = Ldebug_loc256-Lsection_loc
	.long	Lset1689
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	293
	.long	1595
Lset1690 = Ldebug_loc260-Lsection_loc
	.long	Lset1690
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	293
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp721
	.byte	12
	.long	6096
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	293
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp727
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	293
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp728
	.byte	15
	.long	9812
	.long	6144
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	293
	.long	33335
	.byte	12
	.long	6192
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	293
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	6240
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	293
	.long	33335
	.byte	12
	.long	6288
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	293
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	10127
	.ascii	 "atomic_or_ulong_nv"
	.byte	0
	.ascii	 "atomic_or_ulong_nv"
	.byte	0
	.byte	1
	.short	292
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin40
	.quad	Lfunc_end40
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	292
	.long	33310
Lset1691 = Ldebug_loc264-Lsection_loc
	.long	Lset1691
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	292
	.long	1897
Lset1692 = Ldebug_loc268-Lsection_loc
	.long	Lset1692
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	292
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp743
	.byte	12
	.long	6336
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	292
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp749
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	292
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp750
	.byte	15
	.long	10084
	.long	6384
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	292
	.long	33335
	.byte	12
	.long	6432
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	292
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	6480
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	292
	.long	33335
	.byte	12
	.long	6528
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	292
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	10397
	.ascii	 "atomic_or_uint_nv"
	.byte	0
	.ascii	 "atomic_or_uint_nv"
	.byte	0
	.byte	1
	.short	291
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin41
	.quad	Lfunc_end41
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	291
	.long	33366
Lset1693 = Ldebug_loc272-Lsection_loc
	.long	Lset1693
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	291
	.long	2199
Lset1694 = Ldebug_loc276-Lsection_loc
	.long	Lset1694
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	291
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp765
	.byte	12
	.long	6576
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	291
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp771
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	291
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp772
	.byte	15
	.long	10354
	.long	6624
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	291
	.long	33335
	.byte	12
	.long	6672
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	291
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	6720
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	291
	.long	33335
	.byte	12
	.long	6768
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	291
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	10663
	.ascii	 "atomic_or_32_nv"
	.byte	0
	.ascii	 "atomic_or_32_nv"
	.byte	0
	.byte	1
	.short	290
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin42
	.quad	Lfunc_end42
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	290
	.long	33374
Lset1695 = Ldebug_loc280-Lsection_loc
	.long	Lset1695
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	290
	.long	2482
Lset1696 = Ldebug_loc284-Lsection_loc
	.long	Lset1696
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	290
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp787
	.byte	12
	.long	6816
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	290
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp793
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	290
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp794
	.byte	15
	.long	10620
	.long	6864
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	290
	.long	33335
	.byte	12
	.long	6912
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	290
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	6960
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	290
	.long	33335
	.byte	12
	.long	7008
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	290
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	10935
	.ascii	 "atomic_or_ushort_nv"
	.byte	0
	.ascii	 "atomic_or_ushort_nv"
	.byte	0
	.byte	1
	.short	289
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin43
	.quad	Lfunc_end43
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	289
	.long	33382
Lset1697 = Ldebug_loc288-Lsection_loc
	.long	Lset1697
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	289
	.long	2785
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	289
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp807
	.byte	12
	.long	7056
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	289
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp813
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	289
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp814
	.byte	15
	.long	10892
	.long	7104
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	289
	.long	33335
	.byte	12
	.long	7152
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	289
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	7200
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	289
	.long	33335
	.byte	12
	.long	7248
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	289
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	11199
	.ascii	 "atomic_or_16_nv"
	.byte	0
	.ascii	 "atomic_or_16_nv"
	.byte	0
	.byte	1
	.short	288
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin44
	.quad	Lfunc_end44
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	288
	.long	33390
Lset1698 = Ldebug_loc292-Lsection_loc
	.long	Lset1698
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	288
	.long	3072
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	288
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp827
	.byte	12
	.long	7296
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	288
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp833
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	288
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp834
	.byte	15
	.long	11156
	.long	7344
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	288
	.long	33335
	.byte	12
	.long	7392
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	288
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	7440
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	288
	.long	33335
	.byte	12
	.long	7488
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	288
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	11469
	.ascii	 "atomic_or_uchar_nv"
	.byte	0
	.ascii	 "atomic_or_uchar_nv"
	.byte	0
	.byte	1
	.short	287
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin45
	.quad	Lfunc_end45
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	287
	.long	33398
Lset1699 = Ldebug_loc296-Lsection_loc
	.long	Lset1699
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	287
	.long	3368
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	287
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp847
	.byte	12
	.long	7536
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	287
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp853
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	287
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp854
	.byte	15
	.long	11426
	.long	7584
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	287
	.long	33335
	.byte	12
	.long	7632
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	287
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	7680
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	287
	.long	33335
	.byte	12
	.long	7728
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	287
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	11731
	.ascii	 "atomic_or_8_nv"
	.byte	0
	.ascii	 "atomic_or_8_nv"
	.byte	0
	.byte	1
	.short	286
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin46
	.quad	Lfunc_end46
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	286
	.long	33406
Lset1700 = Ldebug_loc300-Lsection_loc
	.long	Lset1700
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	286
	.long	3652
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	286
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp867
	.byte	12
	.long	7776
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	286
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp873
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	286
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp874
	.byte	15
	.long	11688
	.long	7824
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	286
	.long	33335
	.byte	12
	.long	7872
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	286
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	7920
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	286
	.long	33335
	.byte	12
	.long	7968
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	286
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	12001
	.ascii	 "atomic_or_long_nv"
	.byte	0
	.ascii	 "atomic_or_long_nv"
	.byte	0
	.byte	1
	.short	285
	.byte	1
	.long	1876
	.byte	1
	.quad	Lfunc_begin47
	.quad	Lfunc_end47
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	285
	.long	33422
Lset1701 = Ldebug_loc304-Lsection_loc
	.long	Lset1701
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	285
	.long	1876
Lset1702 = Ldebug_loc308-Lsection_loc
	.long	Lset1702
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	285
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp889
	.byte	12
	.long	8016
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	285
	.long	1876
	.byte	1
	.byte	83
	.quad	Ltmp895
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	285
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp896
	.byte	15
	.long	11958
	.long	8064
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	285
	.long	33335
	.byte	12
	.long	8112
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	285
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	8160
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	285
	.long	33335
	.byte	12
	.long	8208
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	285
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	12298
	.ascii	 "atomic_sub_ptr_nv"
	.byte	0
	.ascii	 "atomic_sub_ptr_nv"
	.byte	0
	.byte	1
	.short	264
	.byte	1
	.long	1262
	.byte	1
	.quad	Lfunc_begin48
	.quad	Lfunc_end48
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	263
	.long	1262
Lset1703 = Ldebug_loc312-Lsection_loc
	.long	Lset1703
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	263
	.long	33430
Lset1704 = Ldebug_loc316-Lsection_loc
	.long	Lset1704
	.byte	7
	.quad	Ltmp909
	.quad	Ltmp925
	.byte	11
	.ascii	 "ptr"
	.byte	0
	.byte	1
	.short	265
	.long	1262
	.byte	9
	.long	12217
	.quad	Ltmp909
	.quad	Ltmp916
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	267
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp912
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	267
	.long	33335
	.byte	12
	.long	8256
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	267
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp918
	.quad	Ltmp923
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	269
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp919
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	269
	.long	33335
	.byte	12
	.long	8304
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	269
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	12566
	.ascii	 "atomic_sub_64_nv"
	.byte	0
	.ascii	 "atomic_sub_64_nv"
	.byte	0
	.byte	1
	.short	261
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin49
	.quad	Lfunc_end49
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	261
	.long	33358
Lset1705 = Ldebug_loc320-Lsection_loc
	.long	Lset1705
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	261
	.long	33335
Lset1706 = Ldebug_loc324-Lsection_loc
	.long	Lset1706
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	261
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp934
	.byte	12
	.long	8352
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	261
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp940
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	261
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp941
	.byte	15
	.long	12523
	.long	8400
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	261
	.long	33335
	.byte	12
	.long	8448
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	261
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	8496
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	261
	.long	33335
	.byte	12
	.long	8544
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	261
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	12838
	.ascii	 "atomic_sub_long_nv"
	.byte	0
	.ascii	 "atomic_sub_long_nv"
	.byte	0
	.byte	1
	.short	260
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin50
	.quad	Lfunc_end50
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	260
	.long	33310
Lset1707 = Ldebug_loc328-Lsection_loc
	.long	Lset1707
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	260
	.long	33149
Lset1708 = Ldebug_loc332-Lsection_loc
	.long	Lset1708
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	260
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp956
	.byte	12
	.long	8592
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	260
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp962
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	260
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp963
	.byte	15
	.long	12795
	.long	8640
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	260
	.long	33335
	.byte	12
	.long	8688
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	260
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	8736
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	260
	.long	33335
	.byte	12
	.long	8784
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	260
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	13108
	.ascii	 "atomic_sub_int_nv"
	.byte	0
	.ascii	 "atomic_sub_int_nv"
	.byte	0
	.byte	1
	.short	259
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin51
	.quad	Lfunc_end51
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	259
	.long	33366
Lset1709 = Ldebug_loc336-Lsection_loc
	.long	Lset1709
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	259
	.long	457
Lset1710 = Ldebug_loc340-Lsection_loc
	.long	Lset1710
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	259
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp978
	.byte	12
	.long	8832
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	259
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp984
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	259
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp985
	.byte	15
	.long	13065
	.long	8880
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	259
	.long	33335
	.byte	12
	.long	8928
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	259
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	8976
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	259
	.long	33335
	.byte	12
	.long	9024
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	259
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	13376
	.ascii	 "atomic_sub_32_nv"
	.byte	0
	.ascii	 "atomic_sub_32_nv"
	.byte	0
	.byte	1
	.short	258
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin52
	.quad	Lfunc_end52
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	258
	.long	33374
Lset1711 = Ldebug_loc344-Lsection_loc
	.long	Lset1711
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	258
	.long	33445
Lset1712 = Ldebug_loc348-Lsection_loc
	.long	Lset1712
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	258
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1000
	.byte	12
	.long	9072
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	258
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp1006
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	258
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1007
	.byte	15
	.long	13333
	.long	9120
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	258
	.long	33335
	.byte	12
	.long	9168
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	258
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	9216
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	258
	.long	33335
	.byte	12
	.long	9264
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	258
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	13648
	.ascii	 "atomic_sub_short_nv"
	.byte	0
	.ascii	 "atomic_sub_short_nv"
	.byte	0
	.byte	1
	.short	257
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin53
	.quad	Lfunc_end53
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	257
	.long	33382
Lset1713 = Ldebug_loc352-Lsection_loc
	.long	Lset1713
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	257
	.long	33460
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	257
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1020
	.byte	12
	.long	9312
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	257
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp1026
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	257
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1027
	.byte	15
	.long	13605
	.long	9360
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	257
	.long	33335
	.byte	12
	.long	9408
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	257
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	9456
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	257
	.long	33335
	.byte	12
	.long	9504
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	257
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	5
	.long	13914
	.ascii	 "atomic_sub_16_nv"
	.byte	0
	.ascii	 "atomic_sub_16_nv"
	.byte	0
	.byte	1
	.short	256
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin54
	.quad	Lfunc_end54
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	256
	.long	33390
Lset1714 = Ldebug_loc356-Lsection_loc
	.long	Lset1714
	.byte	16
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	256
	.long	33473
	.byte	1
	.byte	83
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	256
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1040
	.byte	12
	.long	9552
	.byte	8
	.ascii	 "rc"
	.byte	0
	.byte	1
	.short	256
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp1046
	.byte	10
	.ascii	 "__right"
	.byte	0
	.byte	1
	.short	256
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1047
	.byte	15
	.long	13871
	.long	9600
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	256
	.long	33335
	.byte	12
	.long	9648
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	256
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	9696
	.byte	11
	.ascii	 "__left"
	.byte	0
	.byte	1
	.short	256
	.long	33335
	.byte	12
	.long	9744
	.byte	11
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.short	256
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	14174
	.ascii	 "atomic_sub_char_nv"
	.byte	0
	.ascii	 "atomic_sub_char_nv"
	.byte	0
	.byte	1
	.byte	255
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin55
	.quad	Lfunc_end55
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	255
	.long	33398
Lset1715 = Ldebug_loc360-Lsection_loc
	.long	Lset1715
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	255
	.long	33488
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	255
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1060
	.byte	12
	.long	9792
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	255
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp1066
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	255
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1067
	.byte	15
	.long	14133
	.long	9840
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	255
	.long	33335
	.byte	12
	.long	9888
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	255
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	9936
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	255
	.long	33335
	.byte	12
	.long	9984
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	255
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	14428
	.ascii	 "atomic_sub_8_nv"
	.byte	0
	.ascii	 "atomic_sub_8_nv"
	.byte	0
	.byte	1
	.byte	254
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin56
	.quad	Lfunc_end56
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	254
	.long	33406
Lset1716 = Ldebug_loc364-Lsection_loc
	.long	Lset1716
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	254
	.long	33503
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	254
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1080
	.byte	12
	.long	10032
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	254
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp1086
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	254
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1087
	.byte	15
	.long	14387
	.long	10080
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	254
	.long	33335
	.byte	12
	.long	10128
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	254
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	10176
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	254
	.long	33335
	.byte	12
	.long	10224
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	254
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	14725
	.ascii	 "atomic_add_ptr_nv"
	.byte	0
	.ascii	 "atomic_add_ptr_nv"
	.byte	0
	.byte	1
	.byte	233
	.byte	1
	.long	1262
	.byte	1
	.quad	Lfunc_begin57
	.quad	Lfunc_end57
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	232
	.long	1262
Lset1717 = Ldebug_loc368-Lsection_loc
	.long	Lset1717
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	232
	.long	33430
Lset1718 = Ldebug_loc372-Lsection_loc
	.long	Lset1718
	.byte	7
	.quad	Ltmp1100
	.quad	Ltmp1116
	.byte	22
	.ascii	 "ptr"
	.byte	0
	.byte	1
	.byte	234
	.long	1262
	.byte	1
	.byte	83
	.quad	Ltmp1108
	.byte	9
	.long	14647
	.quad	Ltmp1100
	.quad	Ltmp1107
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	236
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1103
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	236
	.long	33335
	.byte	12
	.long	10272
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	236
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp1109
	.quad	Ltmp1114
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	238
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1110
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	238
	.long	33335
	.byte	12
	.long	10320
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	238
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	14983
	.ascii	 "atomic_add_64_nv"
	.byte	0
	.ascii	 "atomic_add_64_nv"
	.byte	0
	.byte	1
	.byte	230
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin58
	.quad	Lfunc_end58
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	230
	.long	33358
Lset1719 = Ldebug_loc376-Lsection_loc
	.long	Lset1719
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	230
	.long	33335
Lset1720 = Ldebug_loc380-Lsection_loc
	.long	Lset1720
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	230
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1125
	.byte	12
	.long	10368
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	230
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp1131
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	230
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1132
	.byte	15
	.long	14942
	.long	10416
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	230
	.long	33335
	.byte	12
	.long	10464
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	230
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	10512
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	230
	.long	33335
	.byte	12
	.long	10560
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	230
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	15245
	.ascii	 "atomic_add_long_nv"
	.byte	0
	.ascii	 "atomic_add_long_nv"
	.byte	0
	.byte	1
	.byte	229
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin59
	.quad	Lfunc_end59
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	229
	.long	33310
Lset1721 = Ldebug_loc384-Lsection_loc
	.long	Lset1721
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	229
	.long	33149
Lset1722 = Ldebug_loc388-Lsection_loc
	.long	Lset1722
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	229
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1147
	.byte	12
	.long	10608
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	229
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp1153
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	229
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1154
	.byte	15
	.long	15204
	.long	10656
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	229
	.long	33335
	.byte	12
	.long	10704
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	229
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	10752
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	229
	.long	33335
	.byte	12
	.long	10800
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	229
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	15505
	.ascii	 "atomic_add_int_nv"
	.byte	0
	.ascii	 "atomic_add_int_nv"
	.byte	0
	.byte	1
	.byte	228
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin60
	.quad	Lfunc_end60
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	228
	.long	33366
Lset1723 = Ldebug_loc392-Lsection_loc
	.long	Lset1723
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	228
	.long	457
Lset1724 = Ldebug_loc396-Lsection_loc
	.long	Lset1724
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	228
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1169
	.byte	12
	.long	10848
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	228
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp1175
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	228
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1176
	.byte	15
	.long	15464
	.long	10896
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	228
	.long	33335
	.byte	12
	.long	10944
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	228
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	10992
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	228
	.long	33335
	.byte	12
	.long	11040
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	228
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	15763
	.ascii	 "atomic_add_32_nv"
	.byte	0
	.ascii	 "atomic_add_32_nv"
	.byte	0
	.byte	1
	.byte	227
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin61
	.quad	Lfunc_end61
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	227
	.long	33374
Lset1725 = Ldebug_loc400-Lsection_loc
	.long	Lset1725
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	227
	.long	33445
Lset1726 = Ldebug_loc404-Lsection_loc
	.long	Lset1726
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	227
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1191
	.byte	12
	.long	11088
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	227
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp1197
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	227
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1198
	.byte	15
	.long	15722
	.long	11136
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	227
	.long	33335
	.byte	12
	.long	11184
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	227
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	11232
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	227
	.long	33335
	.byte	12
	.long	11280
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	227
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	16025
	.ascii	 "atomic_add_short_nv"
	.byte	0
	.ascii	 "atomic_add_short_nv"
	.byte	0
	.byte	1
	.byte	226
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin62
	.quad	Lfunc_end62
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	226
	.long	33382
Lset1727 = Ldebug_loc408-Lsection_loc
	.long	Lset1727
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	226
	.long	33460
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	226
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1211
	.byte	12
	.long	11328
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	226
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp1217
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	226
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1218
	.byte	15
	.long	15984
	.long	11376
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	226
	.long	33335
	.byte	12
	.long	11424
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	226
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	11472
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	226
	.long	33335
	.byte	12
	.long	11520
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	226
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	16281
	.ascii	 "atomic_add_16_nv"
	.byte	0
	.ascii	 "atomic_add_16_nv"
	.byte	0
	.byte	1
	.byte	225
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin63
	.quad	Lfunc_end63
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	225
	.long	33390
Lset1728 = Ldebug_loc412-Lsection_loc
	.long	Lset1728
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	225
	.long	33473
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	225
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1231
	.byte	12
	.long	11568
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	225
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp1237
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	225
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1238
	.byte	15
	.long	16240
	.long	11616
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	225
	.long	33335
	.byte	12
	.long	11664
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	225
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	11712
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	225
	.long	33335
	.byte	12
	.long	11760
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	225
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	16541
	.ascii	 "atomic_add_char_nv"
	.byte	0
	.ascii	 "atomic_add_char_nv"
	.byte	0
	.byte	1
	.byte	224
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin64
	.quad	Lfunc_end64
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	224
	.long	33398
Lset1729 = Ldebug_loc416-Lsection_loc
	.long	Lset1729
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	224
	.long	33488
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	224
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1251
	.byte	12
	.long	11808
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	224
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp1257
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	224
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1258
	.byte	15
	.long	16500
	.long	11856
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	224
	.long	33335
	.byte	12
	.long	11904
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	224
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	11952
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	224
	.long	33335
	.byte	12
	.long	12000
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	224
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	16795
	.ascii	 "atomic_add_8_nv"
	.byte	0
	.ascii	 "atomic_add_8_nv"
	.byte	0
	.byte	1
	.byte	223
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin65
	.quad	Lfunc_end65
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	223
	.long	33406
Lset1730 = Ldebug_loc420-Lsection_loc
	.long	Lset1730
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	223
	.long	33503
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	223
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1271
	.byte	12
	.long	12048
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	223
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp1277
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	223
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1278
	.byte	15
	.long	16754
	.long	12096
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	223
	.long	33335
	.byte	12
	.long	12144
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	223
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	12192
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	223
	.long	33335
	.byte	12
	.long	12240
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	223
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	17037
	.ascii	 "atomic_dec_64_nv"
	.byte	0
	.ascii	 "atomic_dec_64_nv"
	.byte	0
	.byte	1
	.byte	210
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin66
	.quad	Lfunc_end66
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	210
	.long	33358
Lset1731 = Ldebug_loc424-Lsection_loc
	.long	Lset1731
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	210
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1291
	.byte	12
	.long	12288
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	210
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp1297
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	210
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1298
	.byte	15
	.long	16996
	.long	12336
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	210
	.long	33335
	.byte	12
	.long	12384
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	210
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	12432
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	210
	.long	33335
	.byte	12
	.long	12480
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	210
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	17285
	.ascii	 "atomic_dec_ulong_nv"
	.byte	0
	.ascii	 "atomic_dec_ulong_nv"
	.byte	0
	.byte	1
	.byte	209
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin67
	.quad	Lfunc_end67
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	209
	.long	33310
Lset1732 = Ldebug_loc428-Lsection_loc
	.long	Lset1732
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	209
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1311
	.byte	12
	.long	12528
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	209
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp1317
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	209
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1318
	.byte	15
	.long	17244
	.long	12576
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	209
	.long	33335
	.byte	12
	.long	12624
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	209
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	12672
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	209
	.long	33335
	.byte	12
	.long	12720
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	209
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	17531
	.ascii	 "atomic_dec_uint_nv"
	.byte	0
	.ascii	 "atomic_dec_uint_nv"
	.byte	0
	.byte	1
	.byte	208
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin68
	.quad	Lfunc_end68
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	208
	.long	33366
Lset1733 = Ldebug_loc432-Lsection_loc
	.long	Lset1733
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	208
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1331
	.byte	12
	.long	12768
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	208
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp1337
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	208
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1338
	.byte	15
	.long	17490
	.long	12816
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	208
	.long	33335
	.byte	12
	.long	12864
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	208
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	12912
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	208
	.long	33335
	.byte	12
	.long	12960
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	208
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	17773
	.ascii	 "atomic_dec_32_nv"
	.byte	0
	.ascii	 "atomic_dec_32_nv"
	.byte	0
	.byte	1
	.byte	207
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin69
	.quad	Lfunc_end69
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	207
	.long	33374
Lset1734 = Ldebug_loc436-Lsection_loc
	.long	Lset1734
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	207
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1351
	.byte	12
	.long	13008
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	207
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp1357
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	207
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1358
	.byte	15
	.long	17732
	.long	13056
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	207
	.long	33335
	.byte	12
	.long	13104
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	207
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	13152
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	207
	.long	33335
	.byte	12
	.long	13200
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	207
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	18023
	.ascii	 "atomic_dec_ushort_nv"
	.byte	0
	.ascii	 "atomic_dec_ushort_nv"
	.byte	0
	.byte	1
	.byte	206
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin70
	.quad	Lfunc_end70
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	206
	.long	33382
Lset1735 = Ldebug_loc440-Lsection_loc
	.long	Lset1735
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	206
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1371
	.byte	12
	.long	13248
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	206
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp1377
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	206
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1378
	.byte	15
	.long	17982
	.long	13296
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	206
	.long	33335
	.byte	12
	.long	13344
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	206
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	13392
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	206
	.long	33335
	.byte	12
	.long	13440
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	206
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	18265
	.ascii	 "atomic_dec_16_nv"
	.byte	0
	.ascii	 "atomic_dec_16_nv"
	.byte	0
	.byte	1
	.byte	205
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin71
	.quad	Lfunc_end71
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	205
	.long	33390
Lset1736 = Ldebug_loc444-Lsection_loc
	.long	Lset1736
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	205
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1391
	.byte	12
	.long	13488
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	205
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp1397
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	205
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1398
	.byte	15
	.long	18224
	.long	13536
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	205
	.long	33335
	.byte	12
	.long	13584
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	205
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	13632
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	205
	.long	33335
	.byte	12
	.long	13680
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	205
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	18513
	.ascii	 "atomic_dec_uchar_nv"
	.byte	0
	.ascii	 "atomic_dec_uchar_nv"
	.byte	0
	.byte	1
	.byte	204
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin72
	.quad	Lfunc_end72
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	204
	.long	33398
Lset1737 = Ldebug_loc448-Lsection_loc
	.long	Lset1737
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	204
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1411
	.byte	12
	.long	13728
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	204
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp1417
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	204
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1418
	.byte	15
	.long	18472
	.long	13776
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	204
	.long	33335
	.byte	12
	.long	13824
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	204
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	13872
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	204
	.long	33335
	.byte	12
	.long	13920
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	204
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	18753
	.ascii	 "atomic_dec_8_nv"
	.byte	0
	.ascii	 "atomic_dec_8_nv"
	.byte	0
	.byte	1
	.byte	203
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin73
	.quad	Lfunc_end73
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	203
	.long	33406
Lset1738 = Ldebug_loc452-Lsection_loc
	.long	Lset1738
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	203
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1431
	.byte	12
	.long	13968
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	203
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp1437
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	203
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1438
	.byte	15
	.long	18712
	.long	14016
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	203
	.long	33335
	.byte	12
	.long	14064
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	203
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	14112
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	203
	.long	33335
	.byte	12
	.long	14160
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	203
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	18999
	.ascii	 "atomic_dec_long_nv"
	.byte	0
	.ascii	 "atomic_dec_long_nv"
	.byte	0
	.byte	1
	.byte	202
	.byte	1
	.long	1876
	.byte	1
	.quad	Lfunc_begin74
	.quad	Lfunc_end74
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	202
	.long	33422
Lset1739 = Ldebug_loc456-Lsection_loc
	.long	Lset1739
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	202
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1451
	.byte	12
	.long	14208
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	202
	.long	1876
	.byte	1
	.byte	83
	.quad	Ltmp1457
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	202
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1458
	.byte	15
	.long	18958
	.long	14256
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	202
	.long	33335
	.byte	12
	.long	14304
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	202
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	14352
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	202
	.long	33335
	.byte	12
	.long	14400
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	202
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	19241
	.ascii	 "atomic_inc_64_nv"
	.byte	0
	.ascii	 "atomic_inc_64_nv"
	.byte	0
	.byte	1
	.byte	189
	.byte	1
	.long	1595
	.byte	1
	.quad	Lfunc_begin75
	.quad	Lfunc_end75
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	189
	.long	33358
Lset1740 = Ldebug_loc460-Lsection_loc
	.long	Lset1740
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	189
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1471
	.byte	12
	.long	14448
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	189
	.long	1595
	.byte	1
	.byte	83
	.quad	Ltmp1477
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	189
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1478
	.byte	15
	.long	19200
	.long	14496
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	189
	.long	33335
	.byte	12
	.long	14544
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	189
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	14592
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	189
	.long	33335
	.byte	12
	.long	14640
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	189
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	19489
	.ascii	 "atomic_inc_ulong_nv"
	.byte	0
	.ascii	 "atomic_inc_ulong_nv"
	.byte	0
	.byte	1
	.byte	188
	.byte	1
	.long	1897
	.byte	1
	.quad	Lfunc_begin76
	.quad	Lfunc_end76
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	188
	.long	33310
Lset1741 = Ldebug_loc464-Lsection_loc
	.long	Lset1741
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	188
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1491
	.byte	12
	.long	14688
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	188
	.long	1897
	.byte	1
	.byte	83
	.quad	Ltmp1497
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	188
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1498
	.byte	15
	.long	19448
	.long	14736
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	188
	.long	33335
	.byte	12
	.long	14784
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	188
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	14832
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	188
	.long	33335
	.byte	12
	.long	14880
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	188
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	19735
	.ascii	 "atomic_inc_uint_nv"
	.byte	0
	.ascii	 "atomic_inc_uint_nv"
	.byte	0
	.byte	1
	.byte	187
	.byte	1
	.long	2199
	.byte	1
	.quad	Lfunc_begin77
	.quad	Lfunc_end77
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	187
	.long	33366
Lset1742 = Ldebug_loc468-Lsection_loc
	.long	Lset1742
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	187
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1511
	.byte	12
	.long	14928
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	187
	.long	2199
	.byte	1
	.byte	83
	.quad	Ltmp1517
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	187
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1518
	.byte	15
	.long	19694
	.long	14976
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	187
	.long	33335
	.byte	12
	.long	15024
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	187
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	15072
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	187
	.long	33335
	.byte	12
	.long	15120
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	187
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	19977
	.ascii	 "atomic_inc_32_nv"
	.byte	0
	.ascii	 "atomic_inc_32_nv"
	.byte	0
	.byte	1
	.byte	186
	.byte	1
	.long	2482
	.byte	1
	.quad	Lfunc_begin78
	.quad	Lfunc_end78
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	186
	.long	33374
Lset1743 = Ldebug_loc472-Lsection_loc
	.long	Lset1743
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	186
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1531
	.byte	12
	.long	15168
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	186
	.long	2482
	.byte	1
	.byte	83
	.quad	Ltmp1537
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	186
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1538
	.byte	15
	.long	19936
	.long	15216
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	186
	.long	33335
	.byte	12
	.long	15264
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	186
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	15312
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	186
	.long	33335
	.byte	12
	.long	15360
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	186
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	20227
	.ascii	 "atomic_inc_ushort_nv"
	.byte	0
	.ascii	 "atomic_inc_ushort_nv"
	.byte	0
	.byte	1
	.byte	185
	.byte	1
	.long	2785
	.byte	1
	.quad	Lfunc_begin79
	.quad	Lfunc_end79
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	185
	.long	33382
Lset1744 = Ldebug_loc476-Lsection_loc
	.long	Lset1744
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	185
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1551
	.byte	12
	.long	15408
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	185
	.long	2785
	.byte	1
	.byte	83
	.quad	Ltmp1557
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	185
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1558
	.byte	15
	.long	20186
	.long	15456
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	185
	.long	33335
	.byte	12
	.long	15504
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	185
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	15552
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	185
	.long	33335
	.byte	12
	.long	15600
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	185
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	20469
	.ascii	 "atomic_inc_16_nv"
	.byte	0
	.ascii	 "atomic_inc_16_nv"
	.byte	0
	.byte	1
	.byte	184
	.byte	1
	.long	3072
	.byte	1
	.quad	Lfunc_begin80
	.quad	Lfunc_end80
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	184
	.long	33390
Lset1745 = Ldebug_loc480-Lsection_loc
	.long	Lset1745
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	184
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1571
	.byte	12
	.long	15648
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	184
	.long	3072
	.byte	1
	.byte	83
	.quad	Ltmp1577
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	184
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1578
	.byte	15
	.long	20428
	.long	15696
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	184
	.long	33335
	.byte	12
	.long	15744
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	184
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	15792
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	184
	.long	33335
	.byte	12
	.long	15840
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	184
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	20717
	.ascii	 "atomic_inc_uchar_nv"
	.byte	0
	.ascii	 "atomic_inc_uchar_nv"
	.byte	0
	.byte	1
	.byte	183
	.byte	1
	.long	3368
	.byte	1
	.quad	Lfunc_begin81
	.quad	Lfunc_end81
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	183
	.long	33398
Lset1746 = Ldebug_loc484-Lsection_loc
	.long	Lset1746
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	183
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1591
	.byte	12
	.long	15888
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	183
	.long	3368
	.byte	1
	.byte	83
	.quad	Ltmp1597
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	183
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1598
	.byte	15
	.long	20676
	.long	15936
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	183
	.long	33335
	.byte	12
	.long	15984
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	183
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	16032
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	183
	.long	33335
	.byte	12
	.long	16080
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	183
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	20957
	.ascii	 "atomic_inc_8_nv"
	.byte	0
	.ascii	 "atomic_inc_8_nv"
	.byte	0
	.byte	1
	.byte	182
	.byte	1
	.long	3652
	.byte	1
	.quad	Lfunc_begin82
	.quad	Lfunc_end82
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	182
	.long	33406
Lset1747 = Ldebug_loc488-Lsection_loc
	.long	Lset1747
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	182
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1611
	.byte	12
	.long	16128
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	182
	.long	3652
	.byte	1
	.byte	83
	.quad	Ltmp1617
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	182
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1618
	.byte	15
	.long	20916
	.long	16176
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	182
	.long	33335
	.byte	12
	.long	16224
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	182
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	16272
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	182
	.long	33335
	.byte	12
	.long	16320
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	182
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	18
	.long	21203
	.ascii	 "atomic_inc_long_nv"
	.byte	0
	.ascii	 "atomic_inc_long_nv"
	.byte	0
	.byte	1
	.byte	181
	.byte	1
	.long	1876
	.byte	1
	.quad	Lfunc_begin83
	.quad	Lfunc_end83
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	181
	.long	33422
Lset1748 = Ldebug_loc492-Lsection_loc
	.long	Lset1748
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	181
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1631
	.byte	12
	.long	16368
	.byte	22
	.ascii	 "rc"
	.byte	0
	.byte	1
	.byte	181
	.long	1876
	.byte	1
	.byte	83
	.quad	Ltmp1637
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	181
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1638
	.byte	15
	.long	21162
	.long	16416
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	181
	.long	33335
	.byte	12
	.long	16464
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	181
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	16512
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	181
	.long	33335
	.byte	12
	.long	16560
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	181
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	21431
	.ascii	 "atomic_and_64"
	.byte	0
	.ascii	 "atomic_and_64"
	.byte	0
	.byte	1
	.byte	164
	.byte	1
	.byte	1
	.quad	Lfunc_begin84
	.quad	Lfunc_end84
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	164
	.long	33358
Lset1749 = Ldebug_loc496-Lsection_loc
	.long	Lset1749
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	164
	.long	1595
Lset1750 = Ldebug_loc500-Lsection_loc
	.long	Lset1750
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	164
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1653
	.byte	12
	.long	16608
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	164
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1659
	.byte	15
	.long	21390
	.long	16656
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	164
	.long	33335
	.byte	12
	.long	16704
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	164
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	16752
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	164
	.long	33335
	.byte	12
	.long	16800
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	164
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	21665
	.ascii	 "atomic_and_ulong"
	.byte	0
	.ascii	 "atomic_and_ulong"
	.byte	0
	.byte	1
	.byte	163
	.byte	1
	.byte	1
	.quad	Lfunc_begin85
	.quad	Lfunc_end85
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	163
	.long	33310
Lset1751 = Ldebug_loc504-Lsection_loc
	.long	Lset1751
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	163
	.long	1897
Lset1752 = Ldebug_loc508-Lsection_loc
	.long	Lset1752
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	163
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1672
	.byte	12
	.long	16848
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	163
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1678
	.byte	15
	.long	21624
	.long	16896
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	163
	.long	33335
	.byte	12
	.long	16944
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	163
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	16992
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	163
	.long	33335
	.byte	12
	.long	17040
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	163
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	21779
	.ascii	 "atomic_and_long"
	.byte	0
	.ascii	 "atomic_and_long"
	.byte	0
	.byte	1
	.short	473
	.byte	1
	.byte	1
	.quad	Lfunc_begin86
	.quad	Lfunc_end86
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	472
	.long	33310
Lset1753 = Ldebug_loc512-Lsection_loc
	.long	Lset1753
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	472
	.long	1897
Lset1754 = Ldebug_loc516-Lsection_loc
	.long	Lset1754
	.byte	3
	.quad	Ltmp1690
	.quad	Ltmp1691
	.byte	0
	.byte	24
	.long	22011
	.ascii	 "atomic_and_uint"
	.byte	0
	.ascii	 "atomic_and_uint"
	.byte	0
	.byte	1
	.byte	162
	.byte	1
	.byte	1
	.quad	Lfunc_begin87
	.quad	Lfunc_end87
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	162
	.long	33366
Lset1755 = Ldebug_loc520-Lsection_loc
	.long	Lset1755
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	162
	.long	2199
Lset1756 = Ldebug_loc524-Lsection_loc
	.long	Lset1756
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	162
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1700
	.byte	12
	.long	17088
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	162
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1706
	.byte	15
	.long	21970
	.long	17136
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	162
	.long	33335
	.byte	12
	.long	17184
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	162
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	17232
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	162
	.long	33335
	.byte	12
	.long	17280
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	162
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	22239
	.ascii	 "atomic_and_32"
	.byte	0
	.ascii	 "atomic_and_32"
	.byte	0
	.byte	1
	.byte	161
	.byte	1
	.byte	1
	.quad	Lfunc_begin88
	.quad	Lfunc_end88
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	161
	.long	33374
Lset1757 = Ldebug_loc528-Lsection_loc
	.long	Lset1757
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	161
	.long	2482
Lset1758 = Ldebug_loc532-Lsection_loc
	.long	Lset1758
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	161
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1719
	.byte	12
	.long	17328
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	161
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1725
	.byte	15
	.long	22198
	.long	17376
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	161
	.long	33335
	.byte	12
	.long	17424
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	161
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	17472
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	161
	.long	33335
	.byte	12
	.long	17520
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	161
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	22473
	.ascii	 "atomic_and_ushort"
	.byte	0
	.ascii	 "atomic_and_ushort"
	.byte	0
	.byte	1
	.byte	160
	.byte	1
	.byte	1
	.quad	Lfunc_begin89
	.quad	Lfunc_end89
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	160
	.long	33382
Lset1759 = Ldebug_loc536-Lsection_loc
	.long	Lset1759
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	160
	.long	2785
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	160
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1736
	.byte	12
	.long	17568
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	160
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1742
	.byte	15
	.long	22432
	.long	17616
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	160
	.long	33335
	.byte	12
	.long	17664
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	160
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	17712
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	160
	.long	33335
	.byte	12
	.long	17760
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	160
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	22699
	.ascii	 "atomic_and_16"
	.byte	0
	.ascii	 "atomic_and_16"
	.byte	0
	.byte	1
	.byte	159
	.byte	1
	.byte	1
	.quad	Lfunc_begin90
	.quad	Lfunc_end90
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	159
	.long	33390
Lset1760 = Ldebug_loc540-Lsection_loc
	.long	Lset1760
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	159
	.long	3072
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	159
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1753
	.byte	12
	.long	17808
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	159
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1759
	.byte	15
	.long	22658
	.long	17856
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	159
	.long	33335
	.byte	12
	.long	17904
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	159
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	17952
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	159
	.long	33335
	.byte	12
	.long	18000
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	159
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	22931
	.ascii	 "atomic_and_uchar"
	.byte	0
	.ascii	 "atomic_and_uchar"
	.byte	0
	.byte	1
	.byte	158
	.byte	1
	.byte	1
	.quad	Lfunc_begin91
	.quad	Lfunc_end91
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	158
	.long	33398
Lset1761 = Ldebug_loc544-Lsection_loc
	.long	Lset1761
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	158
	.long	3368
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	158
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1770
	.byte	12
	.long	18048
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	158
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1776
	.byte	15
	.long	22890
	.long	18096
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	158
	.long	33335
	.byte	12
	.long	18144
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	158
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	18192
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	158
	.long	33335
	.byte	12
	.long	18240
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	158
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	23155
	.ascii	 "atomic_and_8"
	.byte	0
	.ascii	 "atomic_and_8"
	.byte	0
	.byte	1
	.byte	157
	.byte	1
	.byte	1
	.quad	Lfunc_begin92
	.quad	Lfunc_end92
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	157
	.long	33406
Lset1762 = Ldebug_loc548-Lsection_loc
	.long	Lset1762
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	157
	.long	3652
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	157
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1787
	.byte	12
	.long	18288
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	157
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1793
	.byte	15
	.long	23114
	.long	18336
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	157
	.long	33335
	.byte	12
	.long	18384
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	157
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	18432
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	157
	.long	33335
	.byte	12
	.long	18480
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	157
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	23381
	.ascii	 "atomic_or_64"
	.byte	0
	.ascii	 "atomic_or_64"
	.byte	0
	.byte	1
	.byte	146
	.byte	1
	.byte	1
	.quad	Lfunc_begin93
	.quad	Lfunc_end93
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	146
	.long	33358
Lset1763 = Ldebug_loc552-Lsection_loc
	.long	Lset1763
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	146
	.long	1595
Lset1764 = Ldebug_loc556-Lsection_loc
	.long	Lset1764
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	146
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1806
	.byte	12
	.long	18528
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	146
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1812
	.byte	15
	.long	23340
	.long	18576
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	146
	.long	33335
	.byte	12
	.long	18624
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	146
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	18672
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	146
	.long	33335
	.byte	12
	.long	18720
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	146
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	23613
	.ascii	 "atomic_or_ulong"
	.byte	0
	.ascii	 "atomic_or_ulong"
	.byte	0
	.byte	1
	.byte	145
	.byte	1
	.byte	1
	.quad	Lfunc_begin94
	.quad	Lfunc_end94
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	145
	.long	33310
Lset1765 = Ldebug_loc560-Lsection_loc
	.long	Lset1765
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	145
	.long	1897
Lset1766 = Ldebug_loc564-Lsection_loc
	.long	Lset1766
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	145
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1825
	.byte	12
	.long	18768
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	145
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1831
	.byte	15
	.long	23572
	.long	18816
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	145
	.long	33335
	.byte	12
	.long	18864
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	145
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	18912
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	145
	.long	33335
	.byte	12
	.long	18960
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	145
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	2
	.long	23725
	.ascii	 "atomic_or_long"
	.byte	0
	.ascii	 "atomic_or_long"
	.byte	0
	.byte	1
	.short	478
	.byte	1
	.byte	1
	.quad	Lfunc_begin95
	.quad	Lfunc_end95
	.byte	1
	.byte	86
	.byte	6
	.ascii	 "target"
	.byte	0
	.byte	1
	.short	477
	.long	33310
Lset1767 = Ldebug_loc568-Lsection_loc
	.long	Lset1767
	.byte	6
	.ascii	 "bits"
	.byte	0
	.byte	1
	.short	477
	.long	1897
Lset1768 = Ldebug_loc572-Lsection_loc
	.long	Lset1768
	.byte	3
	.quad	Ltmp1843
	.quad	Ltmp1844
	.byte	0
	.byte	24
	.long	23955
	.ascii	 "atomic_or_uint"
	.byte	0
	.ascii	 "atomic_or_uint"
	.byte	0
	.byte	1
	.byte	144
	.byte	1
	.byte	1
	.quad	Lfunc_begin96
	.quad	Lfunc_end96
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	144
	.long	33366
Lset1769 = Ldebug_loc576-Lsection_loc
	.long	Lset1769
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	144
	.long	2199
Lset1770 = Ldebug_loc580-Lsection_loc
	.long	Lset1770
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	144
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1853
	.byte	12
	.long	19008
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	144
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1859
	.byte	15
	.long	23914
	.long	19056
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	144
	.long	33335
	.byte	12
	.long	19104
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	144
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	19152
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	144
	.long	33335
	.byte	12
	.long	19200
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	144
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	24181
	.ascii	 "atomic_or_32"
	.byte	0
	.ascii	 "atomic_or_32"
	.byte	0
	.byte	1
	.byte	143
	.byte	1
	.byte	1
	.quad	Lfunc_begin97
	.quad	Lfunc_end97
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	143
	.long	33374
Lset1771 = Ldebug_loc584-Lsection_loc
	.long	Lset1771
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	143
	.long	2482
Lset1772 = Ldebug_loc588-Lsection_loc
	.long	Lset1772
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	143
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1872
	.byte	12
	.long	19248
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	143
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1878
	.byte	15
	.long	24140
	.long	19296
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	143
	.long	33335
	.byte	12
	.long	19344
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	143
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	19392
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	143
	.long	33335
	.byte	12
	.long	19440
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	143
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	24413
	.ascii	 "atomic_or_ushort"
	.byte	0
	.ascii	 "atomic_or_ushort"
	.byte	0
	.byte	1
	.byte	142
	.byte	1
	.byte	1
	.quad	Lfunc_begin98
	.quad	Lfunc_end98
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	142
	.long	33382
Lset1773 = Ldebug_loc592-Lsection_loc
	.long	Lset1773
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	142
	.long	2785
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	142
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1889
	.byte	12
	.long	19488
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	142
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1895
	.byte	15
	.long	24372
	.long	19536
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	142
	.long	33335
	.byte	12
	.long	19584
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	142
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	19632
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	142
	.long	33335
	.byte	12
	.long	19680
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	142
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	24637
	.ascii	 "atomic_or_16"
	.byte	0
	.ascii	 "atomic_or_16"
	.byte	0
	.byte	1
	.byte	141
	.byte	1
	.byte	1
	.quad	Lfunc_begin99
	.quad	Lfunc_end99
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	141
	.long	33390
Lset1774 = Ldebug_loc596-Lsection_loc
	.long	Lset1774
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	141
	.long	3072
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	141
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1906
	.byte	12
	.long	19728
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	141
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1912
	.byte	15
	.long	24596
	.long	19776
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	141
	.long	33335
	.byte	12
	.long	19824
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	141
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	19872
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	141
	.long	33335
	.byte	12
	.long	19920
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	141
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	24867
	.ascii	 "atomic_or_uchar"
	.byte	0
	.ascii	 "atomic_or_uchar"
	.byte	0
	.byte	1
	.byte	140
	.byte	1
	.byte	1
	.quad	Lfunc_begin100
	.quad	Lfunc_end100
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	140
	.long	33398
Lset1775 = Ldebug_loc600-Lsection_loc
	.long	Lset1775
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	140
	.long	3368
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	140
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1923
	.byte	12
	.long	19968
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	140
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1929
	.byte	15
	.long	24826
	.long	20016
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	140
	.long	33335
	.byte	12
	.long	20064
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	140
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	20112
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	140
	.long	33335
	.byte	12
	.long	20160
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	140
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	25089
	.ascii	 "atomic_or_8"
	.byte	0
	.ascii	 "atomic_or_8"
	.byte	0
	.byte	1
	.byte	139
	.byte	1
	.byte	1
	.quad	Lfunc_begin101
	.quad	Lfunc_end101
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	139
	.long	33406
Lset1776 = Ldebug_loc604-Lsection_loc
	.long	Lset1776
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	139
	.long	3652
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	139
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1940
	.byte	12
	.long	20208
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	139
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1946
	.byte	15
	.long	25048
	.long	20256
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	139
	.long	33335
	.byte	12
	.long	20304
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	139
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	20352
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	139
	.long	33335
	.byte	12
	.long	20400
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	139
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	25355
	.ascii	 "atomic_sub_ptr"
	.byte	0
	.ascii	 "atomic_sub_ptr"
	.byte	0
	.byte	1
	.byte	124
	.byte	1
	.byte	1
	.quad	Lfunc_begin102
	.quad	Lfunc_end102
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	123
	.long	1262
Lset1777 = Ldebug_loc608-Lsection_loc
	.long	Lset1777
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	123
	.long	33430
Lset1778 = Ldebug_loc612-Lsection_loc
	.long	Lset1778
	.byte	7
	.quad	Ltmp1957
	.quad	Ltmp1972
	.byte	9
	.long	25277
	.quad	Ltmp1957
	.quad	Ltmp1964
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	125
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1960
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	125
	.long	33335
	.byte	12
	.long	20448
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	125
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp1966
	.quad	Ltmp1972
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	127
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1967
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	127
	.long	33335
	.byte	12
	.long	20496
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	127
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	25583
	.ascii	 "atomic_sub_64"
	.byte	0
	.ascii	 "atomic_sub_64"
	.byte	0
	.byte	1
	.byte	121
	.byte	1
	.byte	1
	.quad	Lfunc_begin103
	.quad	Lfunc_end103
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	121
	.long	33358
Lset1779 = Ldebug_loc616-Lsection_loc
	.long	Lset1779
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	121
	.long	33335
Lset1780 = Ldebug_loc620-Lsection_loc
	.long	Lset1780
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	121
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1981
	.byte	12
	.long	20544
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	121
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp1987
	.byte	15
	.long	25542
	.long	20592
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	121
	.long	33335
	.byte	12
	.long	20640
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	121
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	20688
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	121
	.long	33335
	.byte	12
	.long	20736
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	121
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	25815
	.ascii	 "atomic_sub_long"
	.byte	0
	.ascii	 "atomic_sub_long"
	.byte	0
	.byte	1
	.byte	120
	.byte	1
	.byte	1
	.quad	Lfunc_begin104
	.quad	Lfunc_end104
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	120
	.long	33310
Lset1781 = Ldebug_loc624-Lsection_loc
	.long	Lset1781
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	120
	.long	33149
Lset1782 = Ldebug_loc628-Lsection_loc
	.long	Lset1782
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	120
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2000
	.byte	12
	.long	20784
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	120
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2006
	.byte	15
	.long	25774
	.long	20832
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	120
	.long	33335
	.byte	12
	.long	20880
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	120
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	20928
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	120
	.long	33335
	.byte	12
	.long	20976
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	120
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	26045
	.ascii	 "atomic_sub_int"
	.byte	0
	.ascii	 "atomic_sub_int"
	.byte	0
	.byte	1
	.byte	119
	.byte	1
	.byte	1
	.quad	Lfunc_begin105
	.quad	Lfunc_end105
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	119
	.long	33366
Lset1783 = Ldebug_loc632-Lsection_loc
	.long	Lset1783
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	119
	.long	457
Lset1784 = Ldebug_loc636-Lsection_loc
	.long	Lset1784
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	119
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2019
	.byte	12
	.long	21024
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	119
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2025
	.byte	15
	.long	26004
	.long	21072
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	119
	.long	33335
	.byte	12
	.long	21120
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	119
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	21168
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	119
	.long	33335
	.byte	12
	.long	21216
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	119
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	26273
	.ascii	 "atomic_sub_32"
	.byte	0
	.ascii	 "atomic_sub_32"
	.byte	0
	.byte	1
	.byte	118
	.byte	1
	.byte	1
	.quad	Lfunc_begin106
	.quad	Lfunc_end106
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	118
	.long	33374
Lset1785 = Ldebug_loc640-Lsection_loc
	.long	Lset1785
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	118
	.long	33445
Lset1786 = Ldebug_loc644-Lsection_loc
	.long	Lset1786
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	118
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2038
	.byte	12
	.long	21264
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	118
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2044
	.byte	15
	.long	26232
	.long	21312
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	118
	.long	33335
	.byte	12
	.long	21360
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	118
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	21408
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	118
	.long	33335
	.byte	12
	.long	21456
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	118
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	26505
	.ascii	 "atomic_sub_short"
	.byte	0
	.ascii	 "atomic_sub_short"
	.byte	0
	.byte	1
	.byte	117
	.byte	1
	.byte	1
	.quad	Lfunc_begin107
	.quad	Lfunc_end107
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	117
	.long	33382
Lset1787 = Ldebug_loc648-Lsection_loc
	.long	Lset1787
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	117
	.long	33460
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	117
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2055
	.byte	12
	.long	21504
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	117
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2061
	.byte	15
	.long	26464
	.long	21552
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	117
	.long	33335
	.byte	12
	.long	21600
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	117
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	21648
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	117
	.long	33335
	.byte	12
	.long	21696
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	117
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	26731
	.ascii	 "atomic_sub_16"
	.byte	0
	.ascii	 "atomic_sub_16"
	.byte	0
	.byte	1
	.byte	116
	.byte	1
	.byte	1
	.quad	Lfunc_begin108
	.quad	Lfunc_end108
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	116
	.long	33390
Lset1788 = Ldebug_loc652-Lsection_loc
	.long	Lset1788
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	116
	.long	33473
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	116
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2072
	.byte	12
	.long	21744
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	116
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2078
	.byte	15
	.long	26690
	.long	21792
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	116
	.long	33335
	.byte	12
	.long	21840
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	116
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	21888
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	116
	.long	33335
	.byte	12
	.long	21936
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	116
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	26961
	.ascii	 "atomic_sub_char"
	.byte	0
	.ascii	 "atomic_sub_char"
	.byte	0
	.byte	1
	.byte	115
	.byte	1
	.byte	1
	.quad	Lfunc_begin109
	.quad	Lfunc_end109
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	115
	.long	33398
Lset1789 = Ldebug_loc656-Lsection_loc
	.long	Lset1789
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	115
	.long	33488
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	115
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2089
	.byte	12
	.long	21984
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	115
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2095
	.byte	15
	.long	26920
	.long	22032
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	115
	.long	33335
	.byte	12
	.long	22080
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	115
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	22128
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	115
	.long	33335
	.byte	12
	.long	22176
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	115
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	27185
	.ascii	 "atomic_sub_8"
	.byte	0
	.ascii	 "atomic_sub_8"
	.byte	0
	.byte	1
	.byte	114
	.byte	1
	.byte	1
	.quad	Lfunc_begin110
	.quad	Lfunc_end110
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	114
	.long	33406
Lset1790 = Ldebug_loc660-Lsection_loc
	.long	Lset1790
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	114
	.long	33503
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	114
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2106
	.byte	12
	.long	22224
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	114
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2112
	.byte	15
	.long	27144
	.long	22272
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	114
	.long	33335
	.byte	12
	.long	22320
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	114
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	22368
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	114
	.long	33335
	.byte	12
	.long	22416
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	114
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	27451
	.ascii	 "atomic_add_ptr"
	.byte	0
	.ascii	 "atomic_add_ptr"
	.byte	0
	.byte	1
	.byte	99
	.byte	1
	.byte	1
	.quad	Lfunc_begin111
	.quad	Lfunc_end111
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	98
	.long	1262
Lset1791 = Ldebug_loc664-Lsection_loc
	.long	Lset1791
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	98
	.long	33430
Lset1792 = Ldebug_loc668-Lsection_loc
	.long	Lset1792
	.byte	7
	.quad	Ltmp2123
	.quad	Ltmp2138
	.byte	9
	.long	27373
	.quad	Ltmp2123
	.quad	Ltmp2130
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	100
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2126
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	100
	.long	33335
	.byte	12
	.long	22464
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	100
	.long	33350
	.byte	0
	.byte	0
	.byte	7
	.quad	Ltmp2132
	.quad	Ltmp2138
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	102
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2133
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	102
	.long	33335
	.byte	12
	.long	22512
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	102
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	27679
	.ascii	 "atomic_add_64"
	.byte	0
	.ascii	 "atomic_add_64"
	.byte	0
	.byte	1
	.byte	96
	.byte	1
	.byte	1
	.quad	Lfunc_begin112
	.quad	Lfunc_end112
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	96
	.long	33358
Lset1793 = Ldebug_loc672-Lsection_loc
	.long	Lset1793
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	96
	.long	33335
Lset1794 = Ldebug_loc676-Lsection_loc
	.long	Lset1794
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	96
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2147
	.byte	12
	.long	22560
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	96
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2153
	.byte	15
	.long	27638
	.long	22608
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	96
	.long	33335
	.byte	12
	.long	22656
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	96
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	22704
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	96
	.long	33335
	.byte	12
	.long	22752
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	96
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	27911
	.ascii	 "atomic_add_long"
	.byte	0
	.ascii	 "atomic_add_long"
	.byte	0
	.byte	1
	.byte	95
	.byte	1
	.byte	1
	.quad	Lfunc_begin113
	.quad	Lfunc_end113
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	95
	.long	33310
Lset1795 = Ldebug_loc680-Lsection_loc
	.long	Lset1795
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	95
	.long	33149
Lset1796 = Ldebug_loc684-Lsection_loc
	.long	Lset1796
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	95
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2166
	.byte	12
	.long	22800
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	95
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2172
	.byte	15
	.long	27870
	.long	22848
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	95
	.long	33335
	.byte	12
	.long	22896
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	95
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	22944
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	95
	.long	33335
	.byte	12
	.long	22992
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	95
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	28141
	.ascii	 "atomic_add_int"
	.byte	0
	.ascii	 "atomic_add_int"
	.byte	0
	.byte	1
	.byte	94
	.byte	1
	.byte	1
	.quad	Lfunc_begin114
	.quad	Lfunc_end114
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	94
	.long	33366
Lset1797 = Ldebug_loc688-Lsection_loc
	.long	Lset1797
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	94
	.long	457
Lset1798 = Ldebug_loc692-Lsection_loc
	.long	Lset1798
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	94
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2185
	.byte	12
	.long	23040
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	94
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2191
	.byte	15
	.long	28100
	.long	23088
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	94
	.long	33335
	.byte	12
	.long	23136
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	94
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	23184
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	94
	.long	33335
	.byte	12
	.long	23232
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	94
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	28369
	.ascii	 "atomic_add_32"
	.byte	0
	.ascii	 "atomic_add_32"
	.byte	0
	.byte	1
	.byte	93
	.byte	1
	.byte	1
	.quad	Lfunc_begin115
	.quad	Lfunc_end115
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	93
	.long	33374
Lset1799 = Ldebug_loc696-Lsection_loc
	.long	Lset1799
	.byte	19
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	93
	.long	33445
Lset1800 = Ldebug_loc700-Lsection_loc
	.long	Lset1800
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	93
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2204
	.byte	12
	.long	23280
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	93
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2210
	.byte	15
	.long	28328
	.long	23328
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	93
	.long	33335
	.byte	12
	.long	23376
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	93
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	23424
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	93
	.long	33335
	.byte	12
	.long	23472
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	93
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	28601
	.ascii	 "atomic_add_short"
	.byte	0
	.ascii	 "atomic_add_short"
	.byte	0
	.byte	1
	.byte	92
	.byte	1
	.byte	1
	.quad	Lfunc_begin116
	.quad	Lfunc_end116
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	92
	.long	33382
Lset1801 = Ldebug_loc704-Lsection_loc
	.long	Lset1801
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	92
	.long	33460
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	92
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2221
	.byte	12
	.long	23520
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	92
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2227
	.byte	15
	.long	28560
	.long	23568
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	92
	.long	33335
	.byte	12
	.long	23616
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	92
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	23664
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	92
	.long	33335
	.byte	12
	.long	23712
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	92
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	28827
	.ascii	 "atomic_add_16"
	.byte	0
	.ascii	 "atomic_add_16"
	.byte	0
	.byte	1
	.byte	91
	.byte	1
	.byte	1
	.quad	Lfunc_begin117
	.quad	Lfunc_end117
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	91
	.long	33390
Lset1802 = Ldebug_loc708-Lsection_loc
	.long	Lset1802
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	91
	.long	33473
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	91
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2238
	.byte	12
	.long	23760
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	91
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2244
	.byte	15
	.long	28786
	.long	23808
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	91
	.long	33335
	.byte	12
	.long	23856
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	91
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	23904
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	91
	.long	33335
	.byte	12
	.long	23952
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	91
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	29057
	.ascii	 "atomic_add_char"
	.byte	0
	.ascii	 "atomic_add_char"
	.byte	0
	.byte	1
	.byte	90
	.byte	1
	.byte	1
	.quad	Lfunc_begin118
	.quad	Lfunc_end118
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	90
	.long	33398
Lset1803 = Ldebug_loc712-Lsection_loc
	.long	Lset1803
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	90
	.long	33488
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	90
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2255
	.byte	12
	.long	24000
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	90
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2261
	.byte	15
	.long	29016
	.long	24048
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	90
	.long	33335
	.byte	12
	.long	24096
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	90
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	24144
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	90
	.long	33335
	.byte	12
	.long	24192
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	90
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	29281
	.ascii	 "atomic_add_8"
	.byte	0
	.ascii	 "atomic_add_8"
	.byte	0
	.byte	1
	.byte	89
	.byte	1
	.byte	1
	.quad	Lfunc_begin119
	.quad	Lfunc_end119
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	89
	.long	33406
Lset1804 = Ldebug_loc716-Lsection_loc
	.long	Lset1804
	.byte	20
	.ascii	 "bits"
	.byte	0
	.byte	1
	.byte	89
	.long	33503
	.byte	1
	.byte	83
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	89
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2272
	.byte	12
	.long	24240
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	89
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2278
	.byte	15
	.long	29240
	.long	24288
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	89
	.long	33335
	.byte	12
	.long	24336
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	89
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	24384
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	89
	.long	33335
	.byte	12
	.long	24432
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	89
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	29493
	.ascii	 "atomic_dec_64"
	.byte	0
	.ascii	 "atomic_dec_64"
	.byte	0
	.byte	1
	.byte	78
	.byte	1
	.byte	1
	.quad	Lfunc_begin120
	.quad	Lfunc_end120
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	78
	.long	33358
Lset1805 = Ldebug_loc720-Lsection_loc
	.long	Lset1805
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	78
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2289
	.byte	12
	.long	24480
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	78
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2295
	.byte	15
	.long	29452
	.long	24528
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	78
	.long	33335
	.byte	12
	.long	24576
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	78
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	24624
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	78
	.long	33335
	.byte	12
	.long	24672
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	78
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	29711
	.ascii	 "atomic_dec_ulong"
	.byte	0
	.ascii	 "atomic_dec_ulong"
	.byte	0
	.byte	1
	.byte	77
	.byte	1
	.byte	1
	.quad	Lfunc_begin121
	.quad	Lfunc_end121
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	77
	.long	33310
Lset1806 = Ldebug_loc724-Lsection_loc
	.long	Lset1806
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	77
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2306
	.byte	12
	.long	24720
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	77
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2312
	.byte	15
	.long	29670
	.long	24768
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	77
	.long	33335
	.byte	12
	.long	24816
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	77
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	24864
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	77
	.long	33335
	.byte	12
	.long	24912
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	77
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	29927
	.ascii	 "atomic_dec_uint"
	.byte	0
	.ascii	 "atomic_dec_uint"
	.byte	0
	.byte	1
	.byte	76
	.byte	1
	.byte	1
	.quad	Lfunc_begin122
	.quad	Lfunc_end122
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	76
	.long	33366
Lset1807 = Ldebug_loc728-Lsection_loc
	.long	Lset1807
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	76
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2323
	.byte	12
	.long	24960
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	76
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2329
	.byte	15
	.long	29886
	.long	25008
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	76
	.long	33335
	.byte	12
	.long	25056
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	76
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	25104
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	76
	.long	33335
	.byte	12
	.long	25152
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	76
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	30139
	.ascii	 "atomic_dec_32"
	.byte	0
	.ascii	 "atomic_dec_32"
	.byte	0
	.byte	1
	.byte	75
	.byte	1
	.byte	1
	.quad	Lfunc_begin123
	.quad	Lfunc_end123
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	75
	.long	33374
Lset1808 = Ldebug_loc732-Lsection_loc
	.long	Lset1808
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	75
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2340
	.byte	12
	.long	25200
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	75
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2346
	.byte	15
	.long	30098
	.long	25248
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	75
	.long	33335
	.byte	12
	.long	25296
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	75
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	25344
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	75
	.long	33335
	.byte	12
	.long	25392
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	75
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	30359
	.ascii	 "atomic_dec_ushort"
	.byte	0
	.ascii	 "atomic_dec_ushort"
	.byte	0
	.byte	1
	.byte	74
	.byte	1
	.byte	1
	.quad	Lfunc_begin124
	.quad	Lfunc_end124
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	74
	.long	33382
Lset1809 = Ldebug_loc736-Lsection_loc
	.long	Lset1809
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	74
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2357
	.byte	12
	.long	25440
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	74
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2363
	.byte	15
	.long	30318
	.long	25488
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	74
	.long	33335
	.byte	12
	.long	25536
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	74
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	25584
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	74
	.long	33335
	.byte	12
	.long	25632
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	74
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	30571
	.ascii	 "atomic_dec_16"
	.byte	0
	.ascii	 "atomic_dec_16"
	.byte	0
	.byte	1
	.byte	73
	.byte	1
	.byte	1
	.quad	Lfunc_begin125
	.quad	Lfunc_end125
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	73
	.long	33390
Lset1810 = Ldebug_loc740-Lsection_loc
	.long	Lset1810
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	73
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2374
	.byte	12
	.long	25680
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	73
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2380
	.byte	15
	.long	30530
	.long	25728
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	73
	.long	33335
	.byte	12
	.long	25776
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	73
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	25824
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	73
	.long	33335
	.byte	12
	.long	25872
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	73
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	30789
	.ascii	 "atomic_dec_uchar"
	.byte	0
	.ascii	 "atomic_dec_uchar"
	.byte	0
	.byte	1
	.byte	72
	.byte	1
	.byte	1
	.quad	Lfunc_begin126
	.quad	Lfunc_end126
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	72
	.long	33398
Lset1811 = Ldebug_loc744-Lsection_loc
	.long	Lset1811
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	72
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2391
	.byte	12
	.long	25920
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	72
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2397
	.byte	15
	.long	30748
	.long	25968
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	72
	.long	33335
	.byte	12
	.long	26016
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	72
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	26064
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	72
	.long	33335
	.byte	12
	.long	26112
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	72
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	30999
	.ascii	 "atomic_dec_8"
	.byte	0
	.ascii	 "atomic_dec_8"
	.byte	0
	.byte	1
	.byte	71
	.byte	1
	.byte	1
	.quad	Lfunc_begin127
	.quad	Lfunc_end127
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	71
	.long	33406
Lset1812 = Ldebug_loc748-Lsection_loc
	.long	Lset1812
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	71
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2408
	.byte	12
	.long	26160
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	71
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2414
	.byte	15
	.long	30958
	.long	26208
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	71
	.long	33335
	.byte	12
	.long	26256
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	71
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	26304
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	71
	.long	33335
	.byte	12
	.long	26352
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	71
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	31215
	.ascii	 "atomic_dec_long"
	.byte	0
	.ascii	 "atomic_dec_long"
	.byte	0
	.byte	1
	.byte	70
	.byte	1
	.byte	1
	.quad	Lfunc_begin128
	.quad	Lfunc_end128
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	70
	.long	33422
Lset1813 = Ldebug_loc752-Lsection_loc
	.long	Lset1813
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	70
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2425
	.byte	12
	.long	26400
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	70
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2431
	.byte	15
	.long	31174
	.long	26448
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	70
	.long	33335
	.byte	12
	.long	26496
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	70
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	26544
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	70
	.long	33335
	.byte	12
	.long	26592
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	70
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	31427
	.ascii	 "atomic_inc_64"
	.byte	0
	.ascii	 "atomic_inc_64"
	.byte	0
	.byte	1
	.byte	59
	.byte	1
	.byte	1
	.quad	Lfunc_begin129
	.quad	Lfunc_end129
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	59
	.long	33358
Lset1814 = Ldebug_loc756-Lsection_loc
	.long	Lset1814
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	59
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2442
	.byte	12
	.long	26640
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	59
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2448
	.byte	15
	.long	31386
	.long	26688
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	59
	.long	33335
	.byte	12
	.long	26736
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	59
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	26784
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	59
	.long	33335
	.byte	12
	.long	26832
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	59
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	31645
	.ascii	 "atomic_inc_ulong"
	.byte	0
	.ascii	 "atomic_inc_ulong"
	.byte	0
	.byte	1
	.byte	58
	.byte	1
	.byte	1
	.quad	Lfunc_begin130
	.quad	Lfunc_end130
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	58
	.long	33310
Lset1815 = Ldebug_loc760-Lsection_loc
	.long	Lset1815
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	58
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2459
	.byte	12
	.long	26880
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	58
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2465
	.byte	15
	.long	31604
	.long	26928
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	58
	.long	33335
	.byte	12
	.long	26976
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	58
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	27024
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	58
	.long	33335
	.byte	12
	.long	27072
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	58
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	31861
	.ascii	 "atomic_inc_uint"
	.byte	0
	.ascii	 "atomic_inc_uint"
	.byte	0
	.byte	1
	.byte	57
	.byte	1
	.byte	1
	.quad	Lfunc_begin131
	.quad	Lfunc_end131
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	57
	.long	33366
Lset1816 = Ldebug_loc764-Lsection_loc
	.long	Lset1816
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	57
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2476
	.byte	12
	.long	27120
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	57
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2482
	.byte	15
	.long	31820
	.long	27168
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	57
	.long	33335
	.byte	12
	.long	27216
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	57
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	27264
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	57
	.long	33335
	.byte	12
	.long	27312
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	57
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	32073
	.ascii	 "atomic_inc_32"
	.byte	0
	.ascii	 "atomic_inc_32"
	.byte	0
	.byte	1
	.byte	56
	.byte	1
	.byte	1
	.quad	Lfunc_begin132
	.quad	Lfunc_end132
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	56
	.long	33374
Lset1817 = Ldebug_loc768-Lsection_loc
	.long	Lset1817
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	56
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2493
	.byte	12
	.long	27360
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	56
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2499
	.byte	15
	.long	32032
	.long	27408
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	56
	.long	33335
	.byte	12
	.long	27456
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	56
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	27504
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	56
	.long	33335
	.byte	12
	.long	27552
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	56
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	32293
	.ascii	 "atomic_inc_ushort"
	.byte	0
	.ascii	 "atomic_inc_ushort"
	.byte	0
	.byte	1
	.byte	55
	.byte	1
	.byte	1
	.quad	Lfunc_begin133
	.quad	Lfunc_end133
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	55
	.long	33382
Lset1818 = Ldebug_loc772-Lsection_loc
	.long	Lset1818
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	55
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2510
	.byte	12
	.long	27600
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	55
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2516
	.byte	15
	.long	32252
	.long	27648
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	55
	.long	33335
	.byte	12
	.long	27696
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	55
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	27744
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	55
	.long	33335
	.byte	12
	.long	27792
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	55
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	32505
	.ascii	 "atomic_inc_16"
	.byte	0
	.ascii	 "atomic_inc_16"
	.byte	0
	.byte	1
	.byte	54
	.byte	1
	.byte	1
	.quad	Lfunc_begin134
	.quad	Lfunc_end134
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	54
	.long	33390
Lset1819 = Ldebug_loc776-Lsection_loc
	.long	Lset1819
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	54
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2527
	.byte	12
	.long	27840
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	54
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2533
	.byte	15
	.long	32464
	.long	27888
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	54
	.long	33335
	.byte	12
	.long	27936
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	54
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	27984
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	54
	.long	33335
	.byte	12
	.long	28032
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	54
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	32723
	.ascii	 "atomic_inc_uchar"
	.byte	0
	.ascii	 "atomic_inc_uchar"
	.byte	0
	.byte	1
	.byte	53
	.byte	1
	.byte	1
	.quad	Lfunc_begin135
	.quad	Lfunc_end135
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	53
	.long	33398
Lset1820 = Ldebug_loc780-Lsection_loc
	.long	Lset1820
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	53
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2544
	.byte	12
	.long	28080
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	53
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2550
	.byte	15
	.long	32682
	.long	28128
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	53
	.long	33335
	.byte	12
	.long	28176
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	53
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	28224
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	53
	.long	33335
	.byte	12
	.long	28272
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	53
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	32933
	.ascii	 "atomic_inc_8"
	.byte	0
	.ascii	 "atomic_inc_8"
	.byte	0
	.byte	1
	.byte	52
	.byte	1
	.byte	1
	.quad	Lfunc_begin136
	.quad	Lfunc_end136
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	52
	.long	33406
Lset1821 = Ldebug_loc784-Lsection_loc
	.long	Lset1821
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	52
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2561
	.byte	12
	.long	28320
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	52
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2567
	.byte	15
	.long	32892
	.long	28368
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	52
	.long	33335
	.byte	12
	.long	28416
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	52
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	28464
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	52
	.long	33335
	.byte	12
	.long	28512
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	52
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	24
	.long	33149
	.ascii	 "atomic_inc_long"
	.byte	0
	.ascii	 "atomic_inc_long"
	.byte	0
	.byte	1
	.byte	51
	.byte	1
	.byte	1
	.quad	Lfunc_begin137
	.quad	Lfunc_end137
	.byte	1
	.byte	86
	.byte	19
	.ascii	 "target"
	.byte	0
	.byte	1
	.byte	51
	.long	33422
Lset1822 = Ldebug_loc788-Lsection_loc
	.long	Lset1822
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	51
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2578
	.byte	12
	.long	28560
	.byte	21
	.ascii	 "__right"
	.byte	0
	.byte	1
	.byte	51
	.long	33335
	.byte	1
	.byte	0
	.quad	Ltmp2584
	.byte	15
	.long	33108
	.long	28608
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	51
	.long	33335
	.byte	12
	.long	28656
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	51
	.long	33350
	.byte	0
	.byte	0
	.byte	12
	.long	28704
	.byte	23
	.ascii	 "__left"
	.byte	0
	.byte	1
	.byte	51
	.long	33335
	.byte	12
	.long	28752
	.byte	23
	.ascii	 "__buf"
	.byte	0
	.byte	1
	.byte	51
	.long	33350
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	5
	.ascii	 "long int"
	.byte	0
	.byte	8
	.byte	4
	.byte	6
	.ascii	 "char"
	.byte	0
	.byte	1
	.byte	25
	.byte	4
	.byte	5
	.byte	26
	.long	33188
	.long	33161
	.byte	27
	.long	33169
	.byte	55
	.byte	0
	.byte	28
	.long	33256
	.ascii	 "_opaque_pthread_mutex_t"
	.byte	0
	.byte	64
	.byte	1
	.byte	67
	.byte	29
	.ascii	 "__sig"
	.byte	0
	.long	33149
	.byte	1
	.byte	67
	.byte	2
	.byte	35
	.byte	0
	.byte	29
	.ascii	 "__opaque"
	.byte	0
	.long	33172
	.byte	1
	.byte	67
	.byte	2
	.byte	35
	.byte	8
	.byte	0
	.byte	30
	.long	33188
	.ascii	 "pthread_mutex_t"
	.byte	0
	.byte	1
	.short	319
	.byte	31
	.ascii	 "atomic_lock"
	.byte	0
	.long	33256
	.byte	1
	.byte	1
	.byte	37
	.byte	9
	.byte	3
	.quad	_atomic_lock
	.byte	32
	.long	1897
	.byte	8
	.byte	1
	.byte	0
	.byte	4
	.byte	5
	.ascii	 "long long int"
	.byte	0
	.byte	8
	.byte	14
	.long	33318
	.ascii	 "int64_t"
	.byte	0
	.byte	1
	.byte	95
	.byte	32
	.long	33161
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	1595
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	2199
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	2482
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	2785
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	3072
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	3368
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	3652
	.byte	8
	.byte	1
	.byte	0
	.byte	33
	.long	1876
	.byte	8
	.byte	1
	.byte	0
	.byte	32
	.long	33414
	.byte	8
	.byte	1
	.byte	0
	.byte	14
	.long	33149
	.ascii	 "ssize_t"
	.byte	0
	.byte	1
	.byte	240
	.byte	14
	.long	457
	.ascii	 "int32_t"
	.byte	0
	.byte	1
	.byte	90
	.byte	4
	.byte	5
	.ascii	 "short int"
	.byte	0
	.byte	2
	.byte	14
	.long	33460
	.ascii	 "int16_t"
	.byte	0
	.byte	1
	.byte	85
	.byte	4
	.byte	6
	.ascii	 "signed char"
	.byte	0
	.byte	1
	.byte	14
	.long	33488
	.ascii	 "int8_t"
	.byte	0
	.byte	1
	.byte	80
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
	.byte	225
	.byte	127
	.byte	12
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
	.byte	3
	.byte	11
	.byte	0
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	0
	.byte	0
	.byte	4
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
	.byte	5
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
	.byte	6
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
	.byte	6
	.byte	0
	.byte	0
	.byte	7
	.byte	11
	.byte	1
	.byte	17
	.byte	1
	.byte	18
	.byte	1
	.byte	0
	.byte	0
	.byte	8
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
	.byte	44
	.byte	1
	.byte	0
	.byte	0
	.byte	9
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
	.byte	10
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
	.byte	28
	.byte	10
	.byte	44
	.byte	1
	.byte	0
	.byte	0
	.byte	11
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
	.byte	0
	.byte	0
	.byte	12
	.byte	11
	.byte	1
	.byte	85
	.byte	6
	.byte	0
	.byte	0
	.byte	13
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
	.byte	14
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
	.byte	15
	.byte	11
	.byte	1
	.byte	1
	.byte	19
	.byte	85
	.byte	6
	.byte	0
	.byte	0
	.byte	16
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
	.byte	17
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
	.byte	0
	.byte	0
	.byte	18
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
	.byte	19
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
	.byte	6
	.byte	0
	.byte	0
	.byte	20
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
	.byte	21
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
	.byte	28
	.byte	10
	.byte	44
	.byte	1
	.byte	0
	.byte	0
	.byte	22
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
	.byte	44
	.byte	1
	.byte	0
	.byte	0
	.byte	23
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
	.byte	0
	.byte	0
	.byte	24
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
	.byte	25
	.byte	36
	.byte	0
	.byte	11
	.byte	11
	.byte	62
	.byte	11
	.byte	0
	.byte	0
	.byte	26
	.byte	1
	.byte	1
	.byte	1
	.byte	19
	.byte	73
	.byte	19
	.byte	0
	.byte	0
	.byte	27
	.byte	33
	.byte	0
	.byte	73
	.byte	19
	.byte	47
	.byte	11
	.byte	0
	.byte	0
	.byte	28
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
	.byte	29
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
	.byte	30
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
	.byte	31
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
	.byte	32
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
	.byte	33
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
	.byte	0
Labbrev_end:
	.section	__DWARF,__debug_line,regular,debug
Lset1823 = Lline_end-Lline_begin
	.long	Lset1823
Lline_begin:
	.short	2
Lset1824 = Lline_prolog_end-Lline_prolog_begin
	.long	Lset1824
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
	.asciz	 "/Users/lundman/src/zfs/osx.zfs/x/zfs/lib/libspl/asm-generic/"
	.byte	0
	.asciz	 "atomic.c"
	.byte	1
	.byte	0
	.byte	0
	.byte	0
Lline_prolog_end:
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2
	.byte	3
	.byte	169
	.byte	3
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp3
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp7
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp8
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp12
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp13
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp17
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp18
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp23
	.byte	3
	.byte	95
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp24
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp25
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp26
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp29
	.byte	1
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
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp35
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp36
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp37
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp38
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp40
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp41
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp43
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp44
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp45
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp47
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp48
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp50
	.byte	17
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp55
	.byte	3
	.byte	105
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp56
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp57
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp58
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp61
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp63
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp64
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp66
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp67
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp68
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp69
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp70
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp72
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp73
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp75
	.byte	23
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp76
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp77
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp79
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp80
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp82
	.byte	17
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp87
	.byte	3
	.byte	108
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp88
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp89
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp90
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp93
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp95
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp96
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp98
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp99
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp100
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp101
	.byte	21
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
	.quad	Ltmp107
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp112
	.byte	3
	.byte	117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp113
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp114
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp119
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp120
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp122
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp123
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp126
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp128
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp133
	.byte	19
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
	.quad	Ltmp138
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp140
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp141
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp143
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp144
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp146
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp147
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp149
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp154
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp155
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp156
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp159
	.byte	1
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
	.quad	Ltmp167
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp168
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp170
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp175
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp176
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp177
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp180
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp182
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp183
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp185
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp186
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp188
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp189
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp191
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp196
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp197
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp199
	.byte	1
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
	.quad	Ltmp207
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp208
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp210
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp215
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp216
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp218
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp220
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp221
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp223
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp224
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp226
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp227
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp229
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp234
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp235
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp237
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp239
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp240
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp242
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp243
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp245
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp246
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp248
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp253
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp254
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp256
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp258
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp259
	.byte	1
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
	.quad	Ltmp267
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp272
	.byte	3
	.byte	100
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp273
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp274
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp275
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp276
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp280
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp282
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp283
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp285
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp286
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp287
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp288
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp289
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp291
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp292
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp294
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp298
	.byte	136
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp299
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp300
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp301
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp305
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp310
	.byte	3
	.byte	255
	.byte	126
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp311
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp312
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp313
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp317
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp319
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp320
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp322
	.byte	1
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
	.quad	Ltmp329
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp333
	.byte	138
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp334
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp335
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp336
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp340
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp345
	.byte	3
	.byte	136
	.byte	127
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
	.quad	Ltmp348
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp352
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp354
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp355
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp357
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp358
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp359
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp361
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp362
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp364
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp368
	.byte	144
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp369
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp370
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp371
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp375
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp380
	.byte	3
	.byte	130
	.byte	127
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp381
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp382
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp383
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp387
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp389
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp390
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp392
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp393
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp394
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp396
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp397
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
	.byte	19
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
	.quad	Ltmp407
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp411
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp413
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp414
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp416
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp417
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp418
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp420
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp421
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp423
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp427
	.byte	136
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp428
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp429
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp430
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp434
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp439
	.byte	3
	.byte	138
	.byte	127
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp440
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp442
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp444
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp445
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp447
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
	.quad	Ltmp451
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp452
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp454
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp459
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp460
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp462
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp464
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp465
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp467
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
	.quad	Ltmp471
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp472
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp474
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp479
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp480
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp482
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp484
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp485
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp487
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
	.quad	Ltmp491
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp492
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp494
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp499
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp500
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp502
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp504
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp505
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp507
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
	.quad	Ltmp511
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp512
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp514
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp518
	.byte	135
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp519
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp521
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp526
	.byte	3
	.byte	249
	.byte	126
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp527
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp528
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp531
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp533
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp534
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp536
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp537
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp538
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp540
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp541
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp543
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp548
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp549
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp550
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp553
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp555
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp556
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp558
	.byte	1
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
	.byte	19
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
	.quad	Ltmp578
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp580
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp581
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp582
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp584
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp585
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp587
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp592
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp593
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp594
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp597
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp599
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp600
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp602
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp603
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp604
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp606
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp607
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp609
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp614
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp615
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp617
	.byte	1
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
	.quad	Ltmp624
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp626
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp627
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp629
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp634
	.byte	19
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
	.quad	Ltmp639
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp640
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp642
	.byte	1
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
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp655
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp657
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp659
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp660
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp662
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp663
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp664
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp666
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp667
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp669
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp674
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp675
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp677
	.byte	1
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
	.quad	Ltmp684
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp686
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp687
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp689
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp694
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp695
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp696
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp699
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp701
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp702
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp704
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp705
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp706
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp708
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp709
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp711
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp716
	.byte	3
	.byte	115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp717
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp718
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp721
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp723
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp724
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp726
	.byte	1
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
	.byte	19
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
	.quad	Ltmp746
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp748
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp749
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp750
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp752
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp753
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp755
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp760
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp761
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp762
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp765
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp767
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp768
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp770
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp771
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp772
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp774
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp775
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp777
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp782
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp783
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp784
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp787
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp789
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp790
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp792
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp793
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp794
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp796
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp797
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp799
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp804
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp805
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp807
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp809
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp810
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp812
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp813
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp814
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp816
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp817
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp819
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp824
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp825
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
	.quad	Ltmp830
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp832
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp833
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp834
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp836
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp837
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp839
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp844
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp845
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp847
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp849
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp850
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp852
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp853
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp854
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp856
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp857
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp859
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp864
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp865
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp867
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp869
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp870
	.byte	1
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
	.quad	Ltmp874
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp876
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp877
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp879
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp884
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp885
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp886
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp889
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp891
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp892
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp894
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp895
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp896
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp898
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp899
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp901
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp906
	.byte	3
	.byte	107
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp907
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp908
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp909
	.byte	24
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
	.quad	Ltmp915
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp917
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp918
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp919
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp921
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp922
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp924
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp929
	.byte	10
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp930
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp931
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp934
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp936
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp937
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp939
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp940
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp941
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp943
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp944
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp946
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp951
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp952
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp953
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp956
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp958
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp959
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp961
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp962
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp963
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp965
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp966
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp968
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp973
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp974
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp975
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp978
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp980
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp981
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp983
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
	.quad	Ltmp988
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp990
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp995
	.byte	19
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
	.quad	Ltmp1000
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1002
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1003
	.byte	1
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
	.quad	Ltmp1007
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1009
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1010
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1012
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1017
	.byte	19
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
	.quad	Ltmp1022
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1023
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1025
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1026
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1027
	.byte	1
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
	.quad	Ltmp1037
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1038
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1040
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1042
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1043
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1045
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1046
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1047
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1049
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1050
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1052
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1057
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1058
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1060
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1062
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1063
	.byte	1
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
	.quad	Ltmp1067
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1069
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1070
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1072
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1077
	.byte	19
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
	.quad	Ltmp1082
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1083
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1085
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1086
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1087
	.byte	1
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
	.quad	Ltmp1097
	.byte	3
	.byte	107
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1098
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1099
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1100
	.byte	24
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1103
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1105
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1106
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1108
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1109
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1110
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1112
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1113
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1115
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1120
	.byte	10
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1121
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1122
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1127
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1128
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1130
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1131
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1132
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1134
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1135
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1137
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1142
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1143
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1144
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1147
	.byte	1
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
	.quad	Ltmp1154
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1156
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1157
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1159
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1164
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1165
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1166
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1169
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1171
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1172
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1174
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1175
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1176
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1178
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1179
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1181
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1186
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1187
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1188
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1191
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1193
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1194
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1196
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1197
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1198
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1200
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1201
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1203
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1208
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1209
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1211
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1213
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1214
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1216
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1217
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1218
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1220
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1221
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1223
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1228
	.byte	19
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
	.quad	Ltmp1233
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1234
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1236
	.byte	1
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
	.quad	Ltmp1243
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1248
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1249
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
	.quad	Ltmp1256
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1257
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1258
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1260
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1261
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1263
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1268
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1269
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1271
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1273
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1274
	.byte	1
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
	.quad	Ltmp1278
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
	.byte	3
	.byte	115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1289
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1291
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1293
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1294
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1296
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1297
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1298
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1300
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1301
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1303
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1308
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1309
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1311
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1313
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1314
	.byte	1
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
	.quad	Ltmp1318
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1320
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1321
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1323
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1328
	.byte	19
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
	.quad	Ltmp1333
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1334
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1336
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1337
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1338
	.byte	1
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
	.quad	Ltmp1348
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1349
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1351
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1353
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1354
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1356
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1357
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1358
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1360
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1361
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1363
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1368
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1369
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1371
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1373
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1374
	.byte	1
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
	.quad	Ltmp1378
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1380
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1381
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1383
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1388
	.byte	19
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
	.quad	Ltmp1393
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1394
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1396
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1397
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1398
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1400
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1401
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1403
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1408
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1409
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1411
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1413
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1414
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1416
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1417
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1418
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1420
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1421
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1423
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1428
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1429
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1431
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1433
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1434
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1436
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1437
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1438
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1440
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1441
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1443
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1448
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1449
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1451
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1453
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1454
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1456
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1457
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1458
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1460
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1461
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1463
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1468
	.byte	3
	.byte	115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1469
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1471
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1473
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1474
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1476
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1477
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1478
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1480
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1481
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1483
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1488
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1489
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1491
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1493
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1494
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1496
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1497
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1498
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1500
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1501
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1503
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1508
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1509
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1511
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1513
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1514
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1516
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1517
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1518
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1520
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1521
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1523
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1528
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1529
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1531
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1533
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1534
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1536
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1537
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1538
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1540
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1541
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1543
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1548
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1549
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1551
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1553
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1554
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1556
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1557
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1558
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1560
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1561
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1563
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1568
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1569
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1571
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1573
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1574
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1576
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1577
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1578
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1580
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1581
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1583
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1588
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1589
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1591
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1593
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1594
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1596
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1597
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1598
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1600
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1601
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1603
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1608
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1609
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1611
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1613
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1614
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1616
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1617
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1618
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1620
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1621
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1623
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1628
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1629
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1631
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1633
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1634
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1636
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1637
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1638
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1640
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1641
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1643
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1648
	.byte	3
	.byte	111
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1649
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1650
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1653
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1655
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1656
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1658
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1659
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1661
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1662
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1667
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1668
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1669
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1672
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1674
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1675
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1677
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1678
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1680
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1681
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1685
	.byte	3
	.byte	182
	.byte	2
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1686
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1687
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1690
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1695
	.byte	3
	.byte	200
	.byte	125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1696
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1697
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1700
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1702
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1703
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1705
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1706
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1708
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1709
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1714
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1715
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1716
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1719
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1721
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1722
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1724
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1725
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1727
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1728
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1733
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1734
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1736
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1738
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1739
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1741
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1742
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1744
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1745
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1750
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1751
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1753
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1755
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1756
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1758
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1759
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1761
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1762
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1767
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1768
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1770
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1772
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1773
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1775
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1776
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1778
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1779
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1784
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1785
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1787
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1789
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1790
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1792
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1793
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1795
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1796
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1801
	.byte	3
	.byte	117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1802
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1803
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1806
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1808
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1809
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1811
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1812
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1814
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1815
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1820
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1821
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1822
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1825
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1827
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1828
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1830
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1831
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1833
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1834
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1838
	.byte	3
	.byte	205
	.byte	2
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1839
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1840
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1843
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1848
	.byte	3
	.byte	177
	.byte	125
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1849
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1850
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1853
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1855
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1856
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1858
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1859
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1861
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1862
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1867
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1868
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1869
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1872
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1874
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1875
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1877
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1878
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1880
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1881
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1886
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1887
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1889
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1891
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1892
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1894
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1895
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1897
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1898
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1903
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1904
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1906
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1908
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1909
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1911
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1912
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1914
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1915
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1920
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1921
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1923
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1925
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1926
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1928
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1929
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1931
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1932
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1937
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1938
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1940
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1942
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1943
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1945
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1946
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1948
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1949
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1954
	.byte	3
	.byte	113
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1955
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1956
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1957
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1960
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1962
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1963
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1965
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1966
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1967
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1969
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1970
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1971
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1976
	.byte	13
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1977
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1978
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1981
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1983
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1984
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1986
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1987
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1989
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1990
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1995
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1996
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp1997
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2000
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2002
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2003
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2005
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2006
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2008
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2009
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2014
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2015
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2016
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2019
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2021
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2022
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2024
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2025
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2027
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2028
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2033
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2034
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2035
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2038
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2040
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2041
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2043
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2044
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2046
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2047
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2052
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2053
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2055
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2057
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2058
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2060
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2061
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2063
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2064
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2069
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2070
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2072
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2074
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2075
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2077
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2078
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2080
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2081
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2086
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2087
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2089
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2091
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2092
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2094
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2095
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2097
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2098
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2103
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2104
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2106
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2108
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2109
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2111
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2112
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2114
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2115
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2120
	.byte	3
	.byte	113
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2121
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2122
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2123
	.byte	22
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2126
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2128
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2129
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2131
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2132
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2133
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2135
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2136
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2137
	.byte	21
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2142
	.byte	13
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2143
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2144
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2147
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2149
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2150
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2152
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2153
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2155
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2156
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2161
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2162
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2163
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2166
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2168
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2169
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2171
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2172
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2174
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2175
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2180
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2181
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2182
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2185
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2187
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2188
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2190
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2191
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2193
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2194
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2199
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2200
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2201
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2204
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2206
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2207
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2209
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2210
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2212
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2213
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2218
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2219
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2221
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2223
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2224
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2226
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2227
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2229
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2230
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2235
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2236
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2238
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2240
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2241
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2243
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2244
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2246
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2247
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2252
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2253
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2255
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2257
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2258
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2260
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2261
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2263
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2264
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2269
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2270
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2272
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2274
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2275
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2277
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2278
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2280
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2281
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2286
	.byte	3
	.byte	117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2287
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2289
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2291
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2292
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2294
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2295
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2297
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2298
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2303
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2304
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2306
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2308
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2309
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2311
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2312
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2314
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2315
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2320
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2321
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2323
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2325
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2326
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2328
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2329
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2331
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2332
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2337
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2338
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2340
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2342
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2343
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2345
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2346
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2348
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2349
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2354
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2355
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2357
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2359
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2360
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2362
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2363
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2365
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2366
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2371
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2372
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2374
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2376
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2377
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2379
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2380
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2382
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2383
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2388
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2389
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2391
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2393
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2394
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2396
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2397
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2399
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2400
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2405
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2406
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2408
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2410
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2411
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2413
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2414
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2416
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2417
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2422
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2423
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2425
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2427
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2428
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2430
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2431
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2433
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2434
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2439
	.byte	3
	.byte	117
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2440
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2442
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2444
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2445
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2447
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2448
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2450
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2451
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2456
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2457
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2459
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2461
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2462
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2464
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2465
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2467
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2468
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2473
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2474
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2476
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2478
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2479
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2481
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2482
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2484
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2485
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2490
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2491
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2493
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2495
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2496
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2498
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2499
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2501
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2502
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2507
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2508
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2510
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2512
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2513
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2515
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2516
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2518
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2519
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2524
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2525
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2527
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2529
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2530
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2532
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2533
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2535
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2536
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2541
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2542
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2544
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2546
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2547
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2549
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2550
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2552
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2553
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2558
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2559
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2561
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2563
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2564
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2566
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2567
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2569
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2570
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2575
	.byte	19
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2576
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2578
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2580
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2581
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2583
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2584
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2586
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Ltmp2587
	.byte	1
	.byte	0
	.byte	9
	.byte	2
	.quad	Lsection_end1
	.byte	0
	.byte	1
	.byte	1
Lline_end:
	.section	__DWARF,__debug_pubnames,regular,debug
Lset1825 = Lpubnames_end1-Lpubnames_begin1
	.long	Lset1825
Lpubnames_begin1:
	.short	2
Lset1826 = Linfo_begin1-Lsection_info
	.long	Lset1826
Lset1827 = Linfo_end1-Linfo_begin1
	.long	Lset1827
	.long	32073
	.asciz	 "atomic_inc_ushort"
	.long	4655
	.asciz	 "cas64"
	.long	865
	.asciz	 "atomic_set_long_excl"
	.long	23381
	.asciz	 "atomic_or_ulong"
	.long	22931
	.asciz	 "atomic_and_8"
	.long	23155
	.asciz	 "atomic_or_64"
	.long	3928
	.asciz	 "atomic_cas_ptr"
	.long	9053
	.asciz	 "atomic_and_8_nv"
	.long	9589
	.asciz	 "atomic_or_64_nv"
	.long	28601
	.asciz	 "atomic_add_16"
	.long	3667
	.asciz	 "atomic_swap_8"
	.long	17037
	.asciz	 "atomic_dec_ulong_nv"
	.long	18023
	.asciz	 "atomic_dec_16_nv"
	.long	5187
	.asciz	 "atomic_cas_uint"
	.long	30359
	.asciz	 "atomic_dec_16"
	.long	22473
	.asciz	 "atomic_and_16"
	.long	31645
	.asciz	 "atomic_inc_uint"
	.long	25089
	.asciz	 "atomic_sub_ptr"
	.long	4363
	.asciz	 "atomic_cas_64"
	.long	3088
	.asciz	 "atomic_swap_16"
	.long	24181
	.asciz	 "atomic_or_ushort"
	.long	9855
	.asciz	 "atomic_or_ulong_nv"
	.long	32933
	.asciz	 "atomic_inc_long"
	.long	1266
	.asciz	 "atomic_swap_ptr"
	.long	26505
	.asciz	 "atomic_sub_16"
	.long	7054
	.asciz	 "cas8"
	.long	24637
	.asciz	 "atomic_or_uchar"
	.long	12298
	.asciz	 "atomic_sub_64_nv"
	.long	27679
	.asciz	 "atomic_add_long"
	.long	26273
	.asciz	 "atomic_sub_short"
	.long	7973
	.asciz	 "atomic_and_32_nv"
	.long	5890
	.asciz	 "atomic_cas_ushort"
	.long	12566
	.asciz	 "atomic_sub_long_nv"
	.long	29057
	.asciz	 "atomic_add_8"
	.long	19241
	.asciz	 "atomic_inc_ulong_nv"
	.long	26961
	.asciz	 "atomic_sub_8"
	.long	18513
	.asciz	 "atomic_dec_8_nv"
	.long	10663
	.asciz	 "atomic_or_ushort_nv"
	.long	10935
	.asciz	 "atomic_or_16_nv"
	.long	5068
	.asciz	 "caslong"
	.long	28141
	.asciz	 "atomic_add_32"
	.long	17285
	.asciz	 "atomic_dec_uint_nv"
	.long	29927
	.asciz	 "atomic_dec_32"
	.long	30139
	.asciz	 "atomic_dec_ushort"
	.long	27911
	.asciz	 "atomic_add_int"
	.long	12838
	.asciz	 "atomic_sub_int_nv"
	.long	22011
	.asciz	 "atomic_and_32"
	.long	7427
	.asciz	 "atomic_and_ulong_nv"
	.long	4770
	.asciz	 "atomic_cas_ulong"
	.long	18753
	.asciz	 "atomic_dec_long_nv"
	.long	2498
	.asciz	 "atomic_swap_32"
	.long	14428
	.asciz	 "atomic_add_ptr_nv"
	.long	31215
	.asciz	 "atomic_inc_64"
	.long	28827
	.asciz	 "atomic_add_char"
	.long	24413
	.asciz	 "atomic_or_16"
	.long	33280
	.asciz	 "atomic_lock"
	.long	26045
	.asciz	 "atomic_sub_32"
	.long	15505
	.asciz	 "atomic_add_32_nv"
	.long	13648
	.asciz	 "atomic_sub_16_nv"
	.long	20717
	.asciz	 "atomic_inc_8_nv"
	.long	21431
	.asciz	 "atomic_and_ulong"
	.long	14983
	.asciz	 "atomic_add_long_nv"
	.long	6186
	.asciz	 "atomic_cas_16"
	.long	1912
	.asciz	 "atomic_swap_ulong"
	.long	23725
	.asciz	 "atomic_or_uint"
	.long	18265
	.asciz	 "atomic_dec_uchar_nv"
	.long	19735
	.asciz	 "atomic_inc_32_nv"
	.long	16541
	.asciz	 "atomic_add_8_nv"
	.long	19977
	.asciz	 "atomic_inc_ushort_nv"
	.long	7159
	.asciz	 "atomic_and_64_nv"
	.long	464
	.asciz	 "atomic_clear_long_excl"
	.long	6474
	.asciz	 "atomic_cas_uchar"
	.long	23613
	.asciz	 "atomic_or_long"
	.long	4246
	.asciz	 "casptr"
	.long	17531
	.asciz	 "atomic_dec_32_nv"
	.long	17773
	.asciz	 "atomic_dec_ushort_nv"
	.long	25815
	.asciz	 "atomic_sub_int"
	.long	11199
	.asciz	 "atomic_or_uchar_nv"
	.long	24867
	.asciz	 "atomic_or_8"
	.long	25583
	.asciz	 "atomic_sub_long"
	.long	5775
	.asciz	 "cas32"
	.long	22699
	.asciz	 "atomic_and_uchar"
	.long	23955
	.asciz	 "atomic_or_32"
	.long	13914
	.asciz	 "atomic_sub_char_nv"
	.long	3383
	.asciz	 "atomic_swap_uchar"
	.long	20469
	.asciz	 "atomic_inc_uchar_nv"
	.long	231
	.asciz	 "membar_exit"
	.long	21779
	.asciz	 "atomic_and_uint"
	.long	27451
	.asciz	 "atomic_add_64"
	.long	7701
	.asciz	 "atomic_and_uint_nv"
	.long	15245
	.asciz	 "atomic_add_int_nv"
	.long	14725
	.asciz	 "atomic_add_64_nv"
	.long	28369
	.asciz	 "atomic_add_short"
	.long	8241
	.asciz	 "atomic_and_ushort_nv"
	.long	2213
	.asciz	 "atomic_swap_uint"
	.long	21203
	.asciz	 "atomic_and_64"
	.long	8515
	.asciz	 "atomic_and_16_nv"
	.long	5483
	.asciz	 "atomic_cas_32"
	.long	19489
	.asciz	 "atomic_inc_uint_nv"
	.long	32293
	.asciz	 "atomic_inc_16"
	.long	31427
	.asciz	 "atomic_inc_ulong"
	.long	21665
	.asciz	 "atomic_and_long"
	.long	10127
	.asciz	 "atomic_or_uint_nv"
	.long	1611
	.asciz	 "atomic_swap_64"
	.long	9317
	.asciz	 "atomic_and_long_nv"
	.long	379
	.asciz	 "membar_consumer"
	.long	18999
	.asciz	 "atomic_inc_64_nv"
	.long	8781
	.asciz	 "atomic_and_uchar_nv"
	.long	10397
	.asciz	 "atomic_or_32_nv"
	.long	26731
	.asciz	 "atomic_sub_char"
	.long	20957
	.asciz	 "atomic_inc_long_nv"
	.long	29493
	.asciz	 "atomic_dec_ulong"
	.long	29281
	.asciz	 "atomic_dec_64"
	.long	32723
	.asciz	 "atomic_inc_8"
	.long	11731
	.asciz	 "atomic_or_long_nv"
	.long	25355
	.asciz	 "atomic_sub_64"
	.long	159
	.asciz	 "membar_enter"
	.long	22239
	.asciz	 "atomic_and_ushort"
	.long	16795
	.asciz	 "atomic_dec_64_nv"
	.long	11469
	.asciz	 "atomic_or_8_nv"
	.long	13376
	.asciz	 "atomic_sub_short_nv"
	.long	27185
	.asciz	 "atomic_add_ptr"
	.long	2801
	.asciz	 "atomic_swap_ushort"
	.long	30789
	.asciz	 "atomic_dec_8"
	.long	14174
	.asciz	 "atomic_sub_8_nv"
	.long	16281
	.asciz	 "atomic_add_char_nv"
	.long	29711
	.asciz	 "atomic_dec_uint"
	.long	32505
	.asciz	 "atomic_inc_uchar"
	.long	6768
	.asciz	 "atomic_cas_8"
	.long	13108
	.asciz	 "atomic_sub_32_nv"
	.long	16025
	.asciz	 "atomic_add_16_nv"
	.long	301
	.asciz	 "membar_producer"
	.long	15763
	.asciz	 "atomic_add_short_nv"
	.long	30571
	.asciz	 "atomic_dec_uchar"
	.long	31861
	.asciz	 "atomic_inc_32"
	.long	30999
	.asciz	 "atomic_dec_long"
	.long	12001
	.asciz	 "atomic_sub_ptr_nv"
	.long	20227
	.asciz	 "atomic_inc_16_nv"
	.long	0
Lpubnames_end1:
	.section	__DWARF,__debug_pubtypes,regular,debug
Lset1828 = Lpubtypes_end1-Lpubtypes_begin1
	.long	Lset1828
Lpubtypes_begin1:
	.short	2
Lset1829 = Linfo_begin1-Lsection_info
	.long	Lset1829
Lset1830 = Linfo_end1-Linfo_begin1
	.long	Lset1830
	.long	0
Lpubtypes_end1:
	.section	__DWARF,__debug_loc,regular,debug
Ldebug_loc:
	.quad	Lfunc_begin5
	.quad	Ltmp25
	.short	1
	.byte	85
	.quad	Ltmp25
	.quad	Ltmp28
	.short	1
	.byte	94
	.quad	Ltmp28
	.quad	Lfunc_end5
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc4:
	.quad	Lfunc_begin5
	.quad	Ltmp24
	.short	1
	.byte	84
	.quad	Ltmp24
	.quad	Ltmp27
	.short	1
	.byte	83
	.quad	Ltmp27
	.quad	Lfunc_end5
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc8:
	.quad	Lfunc_begin6
	.quad	Ltmp57
	.short	1
	.byte	85
	.quad	Ltmp57
	.quad	Ltmp60
	.short	1
	.byte	94
	.quad	Ltmp60
	.quad	Lfunc_end6
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc12:
	.quad	Lfunc_begin6
	.quad	Ltmp56
	.short	1
	.byte	84
	.quad	Ltmp56
	.quad	Ltmp59
	.short	1
	.byte	83
	.quad	Ltmp59
	.quad	Lfunc_end6
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc16:
	.quad	Lfunc_begin7
	.quad	Ltmp89
	.short	1
	.byte	85
	.quad	Ltmp89
	.quad	Ltmp92
	.short	1
	.byte	94
	.quad	Ltmp92
	.quad	Lfunc_end7
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc20:
	.quad	Lfunc_begin7
	.quad	Ltmp88
	.short	1
	.byte	84
	.quad	Ltmp88
	.quad	Ltmp91
	.short	1
	.byte	83
	.quad	Ltmp91
	.quad	Lfunc_end7
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc24:
	.quad	Lfunc_begin8
	.quad	Ltmp114
	.short	1
	.byte	85
	.quad	Ltmp114
	.quad	Ltmp116
	.short	1
	.byte	94
	.quad	Ltmp116
	.quad	Lfunc_end8
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc28:
	.quad	Lfunc_begin8
	.quad	Ltmp113
	.short	1
	.byte	84
	.quad	Ltmp113
	.quad	Ltmp115
	.short	1
	.byte	83
	.quad	Ltmp115
	.quad	Lfunc_end8
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc32:
	.quad	Lfunc_begin9
	.quad	Ltmp135
	.short	1
	.byte	85
	.quad	Ltmp135
	.quad	Ltmp137
	.short	1
	.byte	94
	.quad	Ltmp137
	.quad	Lfunc_end9
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc36:
	.quad	Lfunc_begin9
	.quad	Ltmp134
	.short	1
	.byte	84
	.quad	Ltmp134
	.quad	Ltmp136
	.short	1
	.byte	83
	.quad	Ltmp136
	.quad	Lfunc_end9
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc40:
	.quad	Lfunc_begin10
	.quad	Ltmp156
	.short	1
	.byte	85
	.quad	Ltmp156
	.quad	Ltmp158
	.short	1
	.byte	94
	.quad	Ltmp158
	.quad	Lfunc_end10
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc44:
	.quad	Lfunc_begin10
	.quad	Ltmp155
	.short	1
	.byte	84
	.quad	Ltmp155
	.quad	Ltmp157
	.short	1
	.byte	83
	.quad	Ltmp157
	.quad	Lfunc_end10
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc48:
	.quad	Lfunc_begin11
	.quad	Ltmp177
	.short	1
	.byte	85
	.quad	Ltmp177
	.quad	Ltmp179
	.short	1
	.byte	94
	.quad	Ltmp179
	.quad	Lfunc_end11
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc52:
	.quad	Lfunc_begin11
	.quad	Ltmp176
	.short	1
	.byte	84
	.quad	Ltmp176
	.quad	Ltmp178
	.short	1
	.byte	83
	.quad	Ltmp178
	.quad	Lfunc_end11
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc56:
	.quad	Lfunc_begin12
	.quad	Ltmp197
	.short	1
	.byte	85
	.quad	Ltmp197
	.quad	Ltmp198
	.short	1
	.byte	94
	.quad	Ltmp198
	.quad	Lfunc_end12
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc60:
	.quad	Lfunc_begin13
	.quad	Ltmp216
	.short	1
	.byte	85
	.quad	Ltmp216
	.quad	Ltmp217
	.short	1
	.byte	94
	.quad	Ltmp217
	.quad	Lfunc_end13
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc64:
	.quad	Lfunc_begin14
	.quad	Ltmp235
	.short	1
	.byte	85
	.quad	Ltmp235
	.quad	Ltmp236
	.short	1
	.byte	94
	.quad	Ltmp236
	.quad	Lfunc_end14
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc68:
	.quad	Lfunc_begin15
	.quad	Ltmp254
	.short	1
	.byte	85
	.quad	Ltmp254
	.quad	Ltmp255
	.short	1
	.byte	94
	.quad	Ltmp255
	.quad	Lfunc_end15
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc72:
	.quad	Lfunc_begin16
	.quad	Ltmp275
	.short	1
	.byte	85
	.quad	Ltmp275
	.quad	Ltmp279
	.short	1
	.byte	95
	.quad	Ltmp279
	.quad	Lfunc_end16
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc76:
	.quad	Lfunc_begin16
	.quad	Ltmp274
	.short	1
	.byte	84
	.quad	Ltmp274
	.quad	Ltmp278
	.short	1
	.byte	94
	.quad	Ltmp278
	.quad	Lfunc_end16
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc80:
	.quad	Lfunc_begin16
	.quad	Ltmp273
	.short	1
	.byte	81
	.quad	Ltmp273
	.quad	Ltmp277
	.short	1
	.byte	83
	.quad	Ltmp277
	.quad	Lfunc_end16
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc84:
	.quad	Lfunc_begin17
	.quad	Ltmp301
	.short	1
	.byte	85
	.quad	Ltmp301
	.quad	Ltmp302
	.short	1
	.byte	85
	.quad	Ltmp302
	.quad	Lfunc_end17
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc88:
	.quad	Lfunc_begin17
	.quad	Ltmp300
	.short	1
	.byte	84
	.quad	Ltmp300
	.quad	Ltmp303
	.short	1
	.byte	84
	.quad	Ltmp303
	.quad	Lfunc_end17
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc92:
	.quad	Lfunc_begin17
	.quad	Ltmp299
	.short	1
	.byte	81
	.quad	Ltmp299
	.quad	Ltmp304
	.short	1
	.byte	81
	.quad	Ltmp304
	.quad	Lfunc_end17
	.short	1
	.byte	81
	.quad	0
	.quad	0
Ldebug_loc96:
	.quad	Lfunc_begin18
	.quad	Ltmp313
	.short	1
	.byte	85
	.quad	Ltmp313
	.quad	Ltmp316
	.short	1
	.byte	95
	.quad	Ltmp316
	.quad	Lfunc_end18
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc100:
	.quad	Lfunc_begin18
	.quad	Ltmp312
	.short	1
	.byte	84
	.quad	Ltmp312
	.quad	Ltmp315
	.short	1
	.byte	94
	.quad	Ltmp315
	.quad	Lfunc_end18
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc104:
	.quad	Lfunc_begin18
	.quad	Ltmp311
	.short	1
	.byte	81
	.quad	Ltmp311
	.quad	Ltmp314
	.short	1
	.byte	83
	.quad	Ltmp314
	.quad	Lfunc_end18
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc108:
	.quad	Lfunc_begin19
	.quad	Ltmp336
	.short	1
	.byte	85
	.quad	Ltmp336
	.quad	Ltmp337
	.short	1
	.byte	85
	.quad	Ltmp337
	.quad	Lfunc_end19
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc112:
	.quad	Lfunc_begin19
	.quad	Ltmp335
	.short	1
	.byte	84
	.quad	Ltmp335
	.quad	Ltmp338
	.short	1
	.byte	84
	.quad	Ltmp338
	.quad	Lfunc_end19
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc116:
	.quad	Lfunc_begin19
	.quad	Ltmp334
	.short	1
	.byte	81
	.quad	Ltmp334
	.quad	Ltmp339
	.short	1
	.byte	81
	.quad	Ltmp339
	.quad	Lfunc_end19
	.short	1
	.byte	81
	.quad	0
	.quad	0
Ldebug_loc120:
	.quad	Lfunc_begin20
	.quad	Ltmp348
	.short	1
	.byte	85
	.quad	Ltmp348
	.quad	Ltmp351
	.short	1
	.byte	95
	.quad	Ltmp351
	.quad	Lfunc_end20
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc124:
	.quad	Lfunc_begin20
	.quad	Ltmp347
	.short	1
	.byte	84
	.quad	Ltmp347
	.quad	Ltmp350
	.short	1
	.byte	94
	.quad	Ltmp350
	.quad	Lfunc_end20
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc128:
	.quad	Lfunc_begin20
	.quad	Ltmp346
	.short	1
	.byte	81
	.quad	Ltmp346
	.quad	Ltmp349
	.short	1
	.byte	83
	.quad	Ltmp349
	.quad	Lfunc_end20
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc132:
	.quad	Lfunc_begin21
	.quad	Ltmp371
	.short	1
	.byte	85
	.quad	Ltmp371
	.quad	Ltmp372
	.short	1
	.byte	85
	.quad	Ltmp372
	.quad	Lfunc_end21
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc136:
	.quad	Lfunc_begin21
	.quad	Ltmp370
	.short	1
	.byte	84
	.quad	Ltmp370
	.quad	Ltmp373
	.short	1
	.byte	84
	.quad	Ltmp373
	.quad	Lfunc_end21
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc140:
	.quad	Lfunc_begin21
	.quad	Ltmp369
	.short	1
	.byte	81
	.quad	Ltmp369
	.quad	Ltmp374
	.short	1
	.byte	81
	.quad	Ltmp374
	.quad	Lfunc_end21
	.short	1
	.byte	81
	.quad	0
	.quad	0
Ldebug_loc144:
	.quad	Lfunc_begin22
	.quad	Ltmp383
	.short	1
	.byte	85
	.quad	Ltmp383
	.quad	Ltmp386
	.short	1
	.byte	95
	.quad	Ltmp386
	.quad	Lfunc_end22
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc148:
	.quad	Lfunc_begin22
	.quad	Ltmp382
	.short	1
	.byte	84
	.quad	Ltmp382
	.quad	Ltmp385
	.short	1
	.byte	94
	.quad	Ltmp385
	.quad	Lfunc_end22
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc152:
	.quad	Lfunc_begin22
	.quad	Ltmp381
	.short	1
	.byte	81
	.quad	Ltmp381
	.quad	Ltmp384
	.short	1
	.byte	83
	.quad	Ltmp384
	.quad	Lfunc_end22
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc156:
	.quad	Lfunc_begin23
	.quad	Ltmp407
	.short	1
	.byte	85
	.quad	Ltmp407
	.quad	Ltmp410
	.short	1
	.byte	95
	.quad	Ltmp410
	.quad	Lfunc_end23
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc160:
	.quad	Lfunc_begin23
	.quad	Ltmp406
	.short	1
	.byte	84
	.quad	Ltmp406
	.quad	Ltmp409
	.short	1
	.byte	94
	.quad	Ltmp409
	.quad	Lfunc_end23
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc164:
	.quad	Lfunc_begin23
	.quad	Ltmp405
	.short	1
	.byte	81
	.quad	Ltmp405
	.quad	Ltmp408
	.short	1
	.byte	83
	.quad	Ltmp408
	.quad	Lfunc_end23
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc168:
	.quad	Lfunc_begin24
	.quad	Ltmp430
	.short	1
	.byte	85
	.quad	Ltmp430
	.quad	Ltmp431
	.short	1
	.byte	85
	.quad	Ltmp431
	.quad	Lfunc_end24
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc172:
	.quad	Lfunc_begin24
	.quad	Ltmp429
	.short	1
	.byte	84
	.quad	Ltmp429
	.quad	Ltmp432
	.short	1
	.byte	84
	.quad	Ltmp432
	.quad	Lfunc_end24
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc176:
	.quad	Lfunc_begin24
	.quad	Ltmp428
	.short	1
	.byte	81
	.quad	Ltmp428
	.quad	Ltmp433
	.short	1
	.byte	81
	.quad	Ltmp433
	.quad	Lfunc_end24
	.short	1
	.byte	81
	.quad	0
	.quad	0
Ldebug_loc180:
	.quad	Lfunc_begin25
	.quad	Ltmp440
	.short	1
	.byte	85
	.quad	Ltmp440
	.quad	Ltmp441
	.short	1
	.byte	95
	.quad	Ltmp441
	.quad	Lfunc_end25
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc184:
	.quad	Lfunc_begin26
	.quad	Ltmp460
	.short	1
	.byte	85
	.quad	Ltmp460
	.quad	Ltmp461
	.short	1
	.byte	95
	.quad	Ltmp461
	.quad	Lfunc_end26
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc188:
	.quad	Lfunc_begin27
	.quad	Ltmp480
	.short	1
	.byte	85
	.quad	Ltmp480
	.quad	Ltmp481
	.short	1
	.byte	95
	.quad	Ltmp481
	.quad	Lfunc_end27
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc192:
	.quad	Lfunc_begin28
	.quad	Ltmp500
	.short	1
	.byte	85
	.quad	Ltmp500
	.quad	Ltmp501
	.short	1
	.byte	95
	.quad	Ltmp501
	.quad	Lfunc_end28
	.short	1
	.byte	95
	.quad	0
	.quad	0
Ldebug_loc196:
	.quad	Lfunc_begin29
	.quad	Ltmp519
	.short	1
	.byte	85
	.quad	Ltmp519
	.quad	Ltmp520
	.short	1
	.byte	85
	.quad	Ltmp520
	.quad	Lfunc_end29
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc200:
	.quad	Lfunc_begin30
	.quad	Ltmp528
	.short	1
	.byte	85
	.quad	Ltmp528
	.quad	Ltmp530
	.short	1
	.byte	94
	.quad	Ltmp530
	.quad	Lfunc_end30
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc204:
	.quad	Lfunc_begin30
	.quad	Ltmp527
	.short	1
	.byte	84
	.quad	Ltmp527
	.quad	Ltmp529
	.short	1
	.byte	83
	.quad	Ltmp529
	.quad	Lfunc_end30
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc208:
	.quad	Lfunc_begin31
	.quad	Ltmp550
	.short	1
	.byte	85
	.quad	Ltmp550
	.quad	Ltmp552
	.short	1
	.byte	94
	.quad	Ltmp552
	.quad	Lfunc_end31
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc212:
	.quad	Lfunc_begin31
	.quad	Ltmp549
	.short	1
	.byte	84
	.quad	Ltmp549
	.quad	Ltmp551
	.short	1
	.byte	83
	.quad	Ltmp551
	.quad	Lfunc_end31
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc216:
	.quad	Lfunc_begin32
	.quad	Ltmp572
	.short	1
	.byte	85
	.quad	Ltmp572
	.quad	Ltmp574
	.short	1
	.byte	94
	.quad	Ltmp574
	.quad	Lfunc_end32
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc220:
	.quad	Lfunc_begin32
	.quad	Ltmp571
	.short	1
	.byte	84
	.quad	Ltmp571
	.quad	Ltmp573
	.short	1
	.byte	83
	.quad	Ltmp573
	.quad	Lfunc_end32
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc224:
	.quad	Lfunc_begin33
	.quad	Ltmp594
	.short	1
	.byte	85
	.quad	Ltmp594
	.quad	Ltmp596
	.short	1
	.byte	94
	.quad	Ltmp596
	.quad	Lfunc_end33
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc228:
	.quad	Lfunc_begin33
	.quad	Ltmp593
	.short	1
	.byte	84
	.quad	Ltmp593
	.quad	Ltmp595
	.short	1
	.byte	83
	.quad	Ltmp595
	.quad	Lfunc_end33
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc232:
	.quad	Lfunc_begin34
	.quad	Ltmp615
	.short	1
	.byte	85
	.quad	Ltmp615
	.quad	Ltmp616
	.short	1
	.byte	94
	.quad	Ltmp616
	.quad	Lfunc_end34
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc236:
	.quad	Lfunc_begin35
	.quad	Ltmp635
	.short	1
	.byte	85
	.quad	Ltmp635
	.quad	Ltmp636
	.short	1
	.byte	94
	.quad	Ltmp636
	.quad	Lfunc_end35
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc240:
	.quad	Lfunc_begin36
	.quad	Ltmp655
	.short	1
	.byte	85
	.quad	Ltmp655
	.quad	Ltmp656
	.short	1
	.byte	94
	.quad	Ltmp656
	.quad	Lfunc_end36
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc244:
	.quad	Lfunc_begin37
	.quad	Ltmp675
	.short	1
	.byte	85
	.quad	Ltmp675
	.quad	Ltmp676
	.short	1
	.byte	94
	.quad	Ltmp676
	.quad	Lfunc_end37
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc248:
	.quad	Lfunc_begin38
	.quad	Ltmp696
	.short	1
	.byte	85
	.quad	Ltmp696
	.quad	Ltmp698
	.short	1
	.byte	94
	.quad	Ltmp698
	.quad	Lfunc_end38
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc252:
	.quad	Lfunc_begin38
	.quad	Ltmp695
	.short	1
	.byte	84
	.quad	Ltmp695
	.quad	Ltmp697
	.short	1
	.byte	83
	.quad	Ltmp697
	.quad	Lfunc_end38
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc256:
	.quad	Lfunc_begin39
	.quad	Ltmp718
	.short	1
	.byte	85
	.quad	Ltmp718
	.quad	Ltmp720
	.short	1
	.byte	94
	.quad	Ltmp720
	.quad	Lfunc_end39
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc260:
	.quad	Lfunc_begin39
	.quad	Ltmp717
	.short	1
	.byte	84
	.quad	Ltmp717
	.quad	Ltmp719
	.short	1
	.byte	83
	.quad	Ltmp719
	.quad	Lfunc_end39
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc264:
	.quad	Lfunc_begin40
	.quad	Ltmp740
	.short	1
	.byte	85
	.quad	Ltmp740
	.quad	Ltmp742
	.short	1
	.byte	94
	.quad	Ltmp742
	.quad	Lfunc_end40
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc268:
	.quad	Lfunc_begin40
	.quad	Ltmp739
	.short	1
	.byte	84
	.quad	Ltmp739
	.quad	Ltmp741
	.short	1
	.byte	83
	.quad	Ltmp741
	.quad	Lfunc_end40
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc272:
	.quad	Lfunc_begin41
	.quad	Ltmp762
	.short	1
	.byte	85
	.quad	Ltmp762
	.quad	Ltmp764
	.short	1
	.byte	94
	.quad	Ltmp764
	.quad	Lfunc_end41
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc276:
	.quad	Lfunc_begin41
	.quad	Ltmp761
	.short	1
	.byte	84
	.quad	Ltmp761
	.quad	Ltmp763
	.short	1
	.byte	83
	.quad	Ltmp763
	.quad	Lfunc_end41
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc280:
	.quad	Lfunc_begin42
	.quad	Ltmp784
	.short	1
	.byte	85
	.quad	Ltmp784
	.quad	Ltmp786
	.short	1
	.byte	94
	.quad	Ltmp786
	.quad	Lfunc_end42
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc284:
	.quad	Lfunc_begin42
	.quad	Ltmp783
	.short	1
	.byte	84
	.quad	Ltmp783
	.quad	Ltmp785
	.short	1
	.byte	83
	.quad	Ltmp785
	.quad	Lfunc_end42
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc288:
	.quad	Lfunc_begin43
	.quad	Ltmp805
	.short	1
	.byte	85
	.quad	Ltmp805
	.quad	Ltmp806
	.short	1
	.byte	94
	.quad	Ltmp806
	.quad	Lfunc_end43
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc292:
	.quad	Lfunc_begin44
	.quad	Ltmp825
	.short	1
	.byte	85
	.quad	Ltmp825
	.quad	Ltmp826
	.short	1
	.byte	94
	.quad	Ltmp826
	.quad	Lfunc_end44
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc296:
	.quad	Lfunc_begin45
	.quad	Ltmp845
	.short	1
	.byte	85
	.quad	Ltmp845
	.quad	Ltmp846
	.short	1
	.byte	94
	.quad	Ltmp846
	.quad	Lfunc_end45
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc300:
	.quad	Lfunc_begin46
	.quad	Ltmp865
	.short	1
	.byte	85
	.quad	Ltmp865
	.quad	Ltmp866
	.short	1
	.byte	94
	.quad	Ltmp866
	.quad	Lfunc_end46
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc304:
	.quad	Lfunc_begin47
	.quad	Ltmp886
	.short	1
	.byte	85
	.quad	Ltmp886
	.quad	Ltmp888
	.short	1
	.byte	94
	.quad	Ltmp888
	.quad	Lfunc_end47
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc308:
	.quad	Lfunc_begin47
	.quad	Ltmp885
	.short	1
	.byte	84
	.quad	Ltmp885
	.quad	Ltmp887
	.short	1
	.byte	83
	.quad	Ltmp887
	.quad	Lfunc_end47
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc312:
	.quad	Lfunc_begin48
	.quad	Ltmp908
	.short	1
	.byte	85
	.quad	Ltmp908
	.quad	Ltmp911
	.short	1
	.byte	94
	.quad	Ltmp911
	.quad	Lfunc_end48
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc316:
	.quad	Lfunc_begin48
	.quad	Ltmp907
	.short	1
	.byte	84
	.quad	Ltmp907
	.quad	Ltmp910
	.short	1
	.byte	83
	.quad	Ltmp910
	.quad	Lfunc_end48
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc320:
	.quad	Lfunc_begin49
	.quad	Ltmp931
	.short	1
	.byte	85
	.quad	Ltmp931
	.quad	Ltmp933
	.short	1
	.byte	94
	.quad	Ltmp933
	.quad	Lfunc_end49
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc324:
	.quad	Lfunc_begin49
	.quad	Ltmp930
	.short	1
	.byte	84
	.quad	Ltmp930
	.quad	Ltmp932
	.short	1
	.byte	83
	.quad	Ltmp932
	.quad	Lfunc_end49
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc328:
	.quad	Lfunc_begin50
	.quad	Ltmp953
	.short	1
	.byte	85
	.quad	Ltmp953
	.quad	Ltmp955
	.short	1
	.byte	94
	.quad	Ltmp955
	.quad	Lfunc_end50
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc332:
	.quad	Lfunc_begin50
	.quad	Ltmp952
	.short	1
	.byte	84
	.quad	Ltmp952
	.quad	Ltmp954
	.short	1
	.byte	83
	.quad	Ltmp954
	.quad	Lfunc_end50
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc336:
	.quad	Lfunc_begin51
	.quad	Ltmp975
	.short	1
	.byte	85
	.quad	Ltmp975
	.quad	Ltmp977
	.short	1
	.byte	94
	.quad	Ltmp977
	.quad	Lfunc_end51
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc340:
	.quad	Lfunc_begin51
	.quad	Ltmp974
	.short	1
	.byte	84
	.quad	Ltmp974
	.quad	Ltmp976
	.short	1
	.byte	83
	.quad	Ltmp976
	.quad	Lfunc_end51
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc344:
	.quad	Lfunc_begin52
	.quad	Ltmp997
	.short	1
	.byte	85
	.quad	Ltmp997
	.quad	Ltmp999
	.short	1
	.byte	94
	.quad	Ltmp999
	.quad	Lfunc_end52
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc348:
	.quad	Lfunc_begin52
	.quad	Ltmp996
	.short	1
	.byte	84
	.quad	Ltmp996
	.quad	Ltmp998
	.short	1
	.byte	83
	.quad	Ltmp998
	.quad	Lfunc_end52
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc352:
	.quad	Lfunc_begin53
	.quad	Ltmp1018
	.short	1
	.byte	85
	.quad	Ltmp1018
	.quad	Ltmp1019
	.short	1
	.byte	94
	.quad	Ltmp1019
	.quad	Lfunc_end53
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc356:
	.quad	Lfunc_begin54
	.quad	Ltmp1038
	.short	1
	.byte	85
	.quad	Ltmp1038
	.quad	Ltmp1039
	.short	1
	.byte	94
	.quad	Ltmp1039
	.quad	Lfunc_end54
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc360:
	.quad	Lfunc_begin55
	.quad	Ltmp1058
	.short	1
	.byte	85
	.quad	Ltmp1058
	.quad	Ltmp1059
	.short	1
	.byte	94
	.quad	Ltmp1059
	.quad	Lfunc_end55
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc364:
	.quad	Lfunc_begin56
	.quad	Ltmp1078
	.short	1
	.byte	85
	.quad	Ltmp1078
	.quad	Ltmp1079
	.short	1
	.byte	94
	.quad	Ltmp1079
	.quad	Lfunc_end56
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc368:
	.quad	Lfunc_begin57
	.quad	Ltmp1099
	.short	1
	.byte	85
	.quad	Ltmp1099
	.quad	Ltmp1102
	.short	1
	.byte	94
	.quad	Ltmp1102
	.quad	Lfunc_end57
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc372:
	.quad	Lfunc_begin57
	.quad	Ltmp1098
	.short	1
	.byte	84
	.quad	Ltmp1098
	.quad	Ltmp1101
	.short	1
	.byte	83
	.quad	Ltmp1101
	.quad	Lfunc_end57
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc376:
	.quad	Lfunc_begin58
	.quad	Ltmp1122
	.short	1
	.byte	85
	.quad	Ltmp1122
	.quad	Ltmp1124
	.short	1
	.byte	94
	.quad	Ltmp1124
	.quad	Lfunc_end58
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc380:
	.quad	Lfunc_begin58
	.quad	Ltmp1121
	.short	1
	.byte	84
	.quad	Ltmp1121
	.quad	Ltmp1123
	.short	1
	.byte	83
	.quad	Ltmp1123
	.quad	Lfunc_end58
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc384:
	.quad	Lfunc_begin59
	.quad	Ltmp1144
	.short	1
	.byte	85
	.quad	Ltmp1144
	.quad	Ltmp1146
	.short	1
	.byte	94
	.quad	Ltmp1146
	.quad	Lfunc_end59
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc388:
	.quad	Lfunc_begin59
	.quad	Ltmp1143
	.short	1
	.byte	84
	.quad	Ltmp1143
	.quad	Ltmp1145
	.short	1
	.byte	83
	.quad	Ltmp1145
	.quad	Lfunc_end59
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc392:
	.quad	Lfunc_begin60
	.quad	Ltmp1166
	.short	1
	.byte	85
	.quad	Ltmp1166
	.quad	Ltmp1168
	.short	1
	.byte	94
	.quad	Ltmp1168
	.quad	Lfunc_end60
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc396:
	.quad	Lfunc_begin60
	.quad	Ltmp1165
	.short	1
	.byte	84
	.quad	Ltmp1165
	.quad	Ltmp1167
	.short	1
	.byte	83
	.quad	Ltmp1167
	.quad	Lfunc_end60
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc400:
	.quad	Lfunc_begin61
	.quad	Ltmp1188
	.short	1
	.byte	85
	.quad	Ltmp1188
	.quad	Ltmp1190
	.short	1
	.byte	94
	.quad	Ltmp1190
	.quad	Lfunc_end61
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc404:
	.quad	Lfunc_begin61
	.quad	Ltmp1187
	.short	1
	.byte	84
	.quad	Ltmp1187
	.quad	Ltmp1189
	.short	1
	.byte	83
	.quad	Ltmp1189
	.quad	Lfunc_end61
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc408:
	.quad	Lfunc_begin62
	.quad	Ltmp1209
	.short	1
	.byte	85
	.quad	Ltmp1209
	.quad	Ltmp1210
	.short	1
	.byte	94
	.quad	Ltmp1210
	.quad	Lfunc_end62
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc412:
	.quad	Lfunc_begin63
	.quad	Ltmp1229
	.short	1
	.byte	85
	.quad	Ltmp1229
	.quad	Ltmp1230
	.short	1
	.byte	94
	.quad	Ltmp1230
	.quad	Lfunc_end63
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc416:
	.quad	Lfunc_begin64
	.quad	Ltmp1249
	.short	1
	.byte	85
	.quad	Ltmp1249
	.quad	Ltmp1250
	.short	1
	.byte	94
	.quad	Ltmp1250
	.quad	Lfunc_end64
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc420:
	.quad	Lfunc_begin65
	.quad	Ltmp1269
	.short	1
	.byte	85
	.quad	Ltmp1269
	.quad	Ltmp1270
	.short	1
	.byte	94
	.quad	Ltmp1270
	.quad	Lfunc_end65
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc424:
	.quad	Lfunc_begin66
	.quad	Ltmp1289
	.short	1
	.byte	85
	.quad	Ltmp1289
	.quad	Ltmp1290
	.short	1
	.byte	83
	.quad	Ltmp1290
	.quad	Lfunc_end66
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc428:
	.quad	Lfunc_begin67
	.quad	Ltmp1309
	.short	1
	.byte	85
	.quad	Ltmp1309
	.quad	Ltmp1310
	.short	1
	.byte	83
	.quad	Ltmp1310
	.quad	Lfunc_end67
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc432:
	.quad	Lfunc_begin68
	.quad	Ltmp1329
	.short	1
	.byte	85
	.quad	Ltmp1329
	.quad	Ltmp1330
	.short	1
	.byte	83
	.quad	Ltmp1330
	.quad	Lfunc_end68
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc436:
	.quad	Lfunc_begin69
	.quad	Ltmp1349
	.short	1
	.byte	85
	.quad	Ltmp1349
	.quad	Ltmp1350
	.short	1
	.byte	83
	.quad	Ltmp1350
	.quad	Lfunc_end69
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc440:
	.quad	Lfunc_begin70
	.quad	Ltmp1369
	.short	1
	.byte	85
	.quad	Ltmp1369
	.quad	Ltmp1370
	.short	1
	.byte	83
	.quad	Ltmp1370
	.quad	Lfunc_end70
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc444:
	.quad	Lfunc_begin71
	.quad	Ltmp1389
	.short	1
	.byte	85
	.quad	Ltmp1389
	.quad	Ltmp1390
	.short	1
	.byte	83
	.quad	Ltmp1390
	.quad	Lfunc_end71
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc448:
	.quad	Lfunc_begin72
	.quad	Ltmp1409
	.short	1
	.byte	85
	.quad	Ltmp1409
	.quad	Ltmp1410
	.short	1
	.byte	83
	.quad	Ltmp1410
	.quad	Lfunc_end72
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc452:
	.quad	Lfunc_begin73
	.quad	Ltmp1429
	.short	1
	.byte	85
	.quad	Ltmp1429
	.quad	Ltmp1430
	.short	1
	.byte	83
	.quad	Ltmp1430
	.quad	Lfunc_end73
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc456:
	.quad	Lfunc_begin74
	.quad	Ltmp1449
	.short	1
	.byte	85
	.quad	Ltmp1449
	.quad	Ltmp1450
	.short	1
	.byte	83
	.quad	Ltmp1450
	.quad	Lfunc_end74
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc460:
	.quad	Lfunc_begin75
	.quad	Ltmp1469
	.short	1
	.byte	85
	.quad	Ltmp1469
	.quad	Ltmp1470
	.short	1
	.byte	83
	.quad	Ltmp1470
	.quad	Lfunc_end75
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc464:
	.quad	Lfunc_begin76
	.quad	Ltmp1489
	.short	1
	.byte	85
	.quad	Ltmp1489
	.quad	Ltmp1490
	.short	1
	.byte	83
	.quad	Ltmp1490
	.quad	Lfunc_end76
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc468:
	.quad	Lfunc_begin77
	.quad	Ltmp1509
	.short	1
	.byte	85
	.quad	Ltmp1509
	.quad	Ltmp1510
	.short	1
	.byte	83
	.quad	Ltmp1510
	.quad	Lfunc_end77
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc472:
	.quad	Lfunc_begin78
	.quad	Ltmp1529
	.short	1
	.byte	85
	.quad	Ltmp1529
	.quad	Ltmp1530
	.short	1
	.byte	83
	.quad	Ltmp1530
	.quad	Lfunc_end78
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc476:
	.quad	Lfunc_begin79
	.quad	Ltmp1549
	.short	1
	.byte	85
	.quad	Ltmp1549
	.quad	Ltmp1550
	.short	1
	.byte	83
	.quad	Ltmp1550
	.quad	Lfunc_end79
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc480:
	.quad	Lfunc_begin80
	.quad	Ltmp1569
	.short	1
	.byte	85
	.quad	Ltmp1569
	.quad	Ltmp1570
	.short	1
	.byte	83
	.quad	Ltmp1570
	.quad	Lfunc_end80
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc484:
	.quad	Lfunc_begin81
	.quad	Ltmp1589
	.short	1
	.byte	85
	.quad	Ltmp1589
	.quad	Ltmp1590
	.short	1
	.byte	83
	.quad	Ltmp1590
	.quad	Lfunc_end81
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc488:
	.quad	Lfunc_begin82
	.quad	Ltmp1609
	.short	1
	.byte	85
	.quad	Ltmp1609
	.quad	Ltmp1610
	.short	1
	.byte	83
	.quad	Ltmp1610
	.quad	Lfunc_end82
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc492:
	.quad	Lfunc_begin83
	.quad	Ltmp1629
	.short	1
	.byte	85
	.quad	Ltmp1629
	.quad	Ltmp1630
	.short	1
	.byte	83
	.quad	Ltmp1630
	.quad	Lfunc_end83
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc496:
	.quad	Lfunc_begin84
	.quad	Ltmp1650
	.short	1
	.byte	85
	.quad	Ltmp1650
	.quad	Ltmp1652
	.short	1
	.byte	94
	.quad	Ltmp1652
	.quad	Lfunc_end84
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc500:
	.quad	Lfunc_begin84
	.quad	Ltmp1649
	.short	1
	.byte	84
	.quad	Ltmp1649
	.quad	Ltmp1651
	.short	1
	.byte	83
	.quad	Ltmp1651
	.quad	Lfunc_end84
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc504:
	.quad	Lfunc_begin85
	.quad	Ltmp1669
	.short	1
	.byte	85
	.quad	Ltmp1669
	.quad	Ltmp1671
	.short	1
	.byte	94
	.quad	Ltmp1671
	.quad	Lfunc_end85
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc508:
	.quad	Lfunc_begin85
	.quad	Ltmp1668
	.short	1
	.byte	84
	.quad	Ltmp1668
	.quad	Ltmp1670
	.short	1
	.byte	83
	.quad	Ltmp1670
	.quad	Lfunc_end85
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc512:
	.quad	Lfunc_begin86
	.quad	Ltmp1687
	.short	1
	.byte	85
	.quad	Ltmp1687
	.quad	Ltmp1688
	.short	1
	.byte	85
	.quad	Ltmp1688
	.quad	Lfunc_end86
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc516:
	.quad	Lfunc_begin86
	.quad	Ltmp1686
	.short	1
	.byte	84
	.quad	Ltmp1686
	.quad	Ltmp1689
	.short	1
	.byte	84
	.quad	Ltmp1689
	.quad	Lfunc_end86
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc520:
	.quad	Lfunc_begin87
	.quad	Ltmp1697
	.short	1
	.byte	85
	.quad	Ltmp1697
	.quad	Ltmp1699
	.short	1
	.byte	94
	.quad	Ltmp1699
	.quad	Lfunc_end87
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc524:
	.quad	Lfunc_begin87
	.quad	Ltmp1696
	.short	1
	.byte	84
	.quad	Ltmp1696
	.quad	Ltmp1698
	.short	1
	.byte	83
	.quad	Ltmp1698
	.quad	Lfunc_end87
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc528:
	.quad	Lfunc_begin88
	.quad	Ltmp1716
	.short	1
	.byte	85
	.quad	Ltmp1716
	.quad	Ltmp1718
	.short	1
	.byte	94
	.quad	Ltmp1718
	.quad	Lfunc_end88
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc532:
	.quad	Lfunc_begin88
	.quad	Ltmp1715
	.short	1
	.byte	84
	.quad	Ltmp1715
	.quad	Ltmp1717
	.short	1
	.byte	83
	.quad	Ltmp1717
	.quad	Lfunc_end88
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc536:
	.quad	Lfunc_begin89
	.quad	Ltmp1734
	.short	1
	.byte	85
	.quad	Ltmp1734
	.quad	Ltmp1735
	.short	1
	.byte	94
	.quad	Ltmp1735
	.quad	Lfunc_end89
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc540:
	.quad	Lfunc_begin90
	.quad	Ltmp1751
	.short	1
	.byte	85
	.quad	Ltmp1751
	.quad	Ltmp1752
	.short	1
	.byte	94
	.quad	Ltmp1752
	.quad	Lfunc_end90
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc544:
	.quad	Lfunc_begin91
	.quad	Ltmp1768
	.short	1
	.byte	85
	.quad	Ltmp1768
	.quad	Ltmp1769
	.short	1
	.byte	94
	.quad	Ltmp1769
	.quad	Lfunc_end91
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc548:
	.quad	Lfunc_begin92
	.quad	Ltmp1785
	.short	1
	.byte	85
	.quad	Ltmp1785
	.quad	Ltmp1786
	.short	1
	.byte	94
	.quad	Ltmp1786
	.quad	Lfunc_end92
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc552:
	.quad	Lfunc_begin93
	.quad	Ltmp1803
	.short	1
	.byte	85
	.quad	Ltmp1803
	.quad	Ltmp1805
	.short	1
	.byte	94
	.quad	Ltmp1805
	.quad	Lfunc_end93
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc556:
	.quad	Lfunc_begin93
	.quad	Ltmp1802
	.short	1
	.byte	84
	.quad	Ltmp1802
	.quad	Ltmp1804
	.short	1
	.byte	83
	.quad	Ltmp1804
	.quad	Lfunc_end93
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc560:
	.quad	Lfunc_begin94
	.quad	Ltmp1822
	.short	1
	.byte	85
	.quad	Ltmp1822
	.quad	Ltmp1824
	.short	1
	.byte	94
	.quad	Ltmp1824
	.quad	Lfunc_end94
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc564:
	.quad	Lfunc_begin94
	.quad	Ltmp1821
	.short	1
	.byte	84
	.quad	Ltmp1821
	.quad	Ltmp1823
	.short	1
	.byte	83
	.quad	Ltmp1823
	.quad	Lfunc_end94
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc568:
	.quad	Lfunc_begin95
	.quad	Ltmp1840
	.short	1
	.byte	85
	.quad	Ltmp1840
	.quad	Ltmp1841
	.short	1
	.byte	85
	.quad	Ltmp1841
	.quad	Lfunc_end95
	.short	1
	.byte	85
	.quad	0
	.quad	0
Ldebug_loc572:
	.quad	Lfunc_begin95
	.quad	Ltmp1839
	.short	1
	.byte	84
	.quad	Ltmp1839
	.quad	Ltmp1842
	.short	1
	.byte	84
	.quad	Ltmp1842
	.quad	Lfunc_end95
	.short	1
	.byte	84
	.quad	0
	.quad	0
Ldebug_loc576:
	.quad	Lfunc_begin96
	.quad	Ltmp1850
	.short	1
	.byte	85
	.quad	Ltmp1850
	.quad	Ltmp1852
	.short	1
	.byte	94
	.quad	Ltmp1852
	.quad	Lfunc_end96
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc580:
	.quad	Lfunc_begin96
	.quad	Ltmp1849
	.short	1
	.byte	84
	.quad	Ltmp1849
	.quad	Ltmp1851
	.short	1
	.byte	83
	.quad	Ltmp1851
	.quad	Lfunc_end96
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc584:
	.quad	Lfunc_begin97
	.quad	Ltmp1869
	.short	1
	.byte	85
	.quad	Ltmp1869
	.quad	Ltmp1871
	.short	1
	.byte	94
	.quad	Ltmp1871
	.quad	Lfunc_end97
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc588:
	.quad	Lfunc_begin97
	.quad	Ltmp1868
	.short	1
	.byte	84
	.quad	Ltmp1868
	.quad	Ltmp1870
	.short	1
	.byte	83
	.quad	Ltmp1870
	.quad	Lfunc_end97
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc592:
	.quad	Lfunc_begin98
	.quad	Ltmp1887
	.short	1
	.byte	85
	.quad	Ltmp1887
	.quad	Ltmp1888
	.short	1
	.byte	94
	.quad	Ltmp1888
	.quad	Lfunc_end98
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc596:
	.quad	Lfunc_begin99
	.quad	Ltmp1904
	.short	1
	.byte	85
	.quad	Ltmp1904
	.quad	Ltmp1905
	.short	1
	.byte	94
	.quad	Ltmp1905
	.quad	Lfunc_end99
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc600:
	.quad	Lfunc_begin100
	.quad	Ltmp1921
	.short	1
	.byte	85
	.quad	Ltmp1921
	.quad	Ltmp1922
	.short	1
	.byte	94
	.quad	Ltmp1922
	.quad	Lfunc_end100
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc604:
	.quad	Lfunc_begin101
	.quad	Ltmp1938
	.short	1
	.byte	85
	.quad	Ltmp1938
	.quad	Ltmp1939
	.short	1
	.byte	94
	.quad	Ltmp1939
	.quad	Lfunc_end101
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc608:
	.quad	Lfunc_begin102
	.quad	Ltmp1956
	.short	1
	.byte	85
	.quad	Ltmp1956
	.quad	Ltmp1959
	.short	1
	.byte	94
	.quad	Ltmp1959
	.quad	Lfunc_end102
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc612:
	.quad	Lfunc_begin102
	.quad	Ltmp1955
	.short	1
	.byte	84
	.quad	Ltmp1955
	.quad	Ltmp1958
	.short	1
	.byte	83
	.quad	Ltmp1958
	.quad	Lfunc_end102
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc616:
	.quad	Lfunc_begin103
	.quad	Ltmp1978
	.short	1
	.byte	85
	.quad	Ltmp1978
	.quad	Ltmp1980
	.short	1
	.byte	94
	.quad	Ltmp1980
	.quad	Lfunc_end103
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc620:
	.quad	Lfunc_begin103
	.quad	Ltmp1977
	.short	1
	.byte	84
	.quad	Ltmp1977
	.quad	Ltmp1979
	.short	1
	.byte	83
	.quad	Ltmp1979
	.quad	Lfunc_end103
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc624:
	.quad	Lfunc_begin104
	.quad	Ltmp1997
	.short	1
	.byte	85
	.quad	Ltmp1997
	.quad	Ltmp1999
	.short	1
	.byte	94
	.quad	Ltmp1999
	.quad	Lfunc_end104
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc628:
	.quad	Lfunc_begin104
	.quad	Ltmp1996
	.short	1
	.byte	84
	.quad	Ltmp1996
	.quad	Ltmp1998
	.short	1
	.byte	83
	.quad	Ltmp1998
	.quad	Lfunc_end104
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc632:
	.quad	Lfunc_begin105
	.quad	Ltmp2016
	.short	1
	.byte	85
	.quad	Ltmp2016
	.quad	Ltmp2018
	.short	1
	.byte	94
	.quad	Ltmp2018
	.quad	Lfunc_end105
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc636:
	.quad	Lfunc_begin105
	.quad	Ltmp2015
	.short	1
	.byte	84
	.quad	Ltmp2015
	.quad	Ltmp2017
	.short	1
	.byte	83
	.quad	Ltmp2017
	.quad	Lfunc_end105
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc640:
	.quad	Lfunc_begin106
	.quad	Ltmp2035
	.short	1
	.byte	85
	.quad	Ltmp2035
	.quad	Ltmp2037
	.short	1
	.byte	94
	.quad	Ltmp2037
	.quad	Lfunc_end106
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc644:
	.quad	Lfunc_begin106
	.quad	Ltmp2034
	.short	1
	.byte	84
	.quad	Ltmp2034
	.quad	Ltmp2036
	.short	1
	.byte	83
	.quad	Ltmp2036
	.quad	Lfunc_end106
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc648:
	.quad	Lfunc_begin107
	.quad	Ltmp2053
	.short	1
	.byte	85
	.quad	Ltmp2053
	.quad	Ltmp2054
	.short	1
	.byte	94
	.quad	Ltmp2054
	.quad	Lfunc_end107
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc652:
	.quad	Lfunc_begin108
	.quad	Ltmp2070
	.short	1
	.byte	85
	.quad	Ltmp2070
	.quad	Ltmp2071
	.short	1
	.byte	94
	.quad	Ltmp2071
	.quad	Lfunc_end108
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc656:
	.quad	Lfunc_begin109
	.quad	Ltmp2087
	.short	1
	.byte	85
	.quad	Ltmp2087
	.quad	Ltmp2088
	.short	1
	.byte	94
	.quad	Ltmp2088
	.quad	Lfunc_end109
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc660:
	.quad	Lfunc_begin110
	.quad	Ltmp2104
	.short	1
	.byte	85
	.quad	Ltmp2104
	.quad	Ltmp2105
	.short	1
	.byte	94
	.quad	Ltmp2105
	.quad	Lfunc_end110
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc664:
	.quad	Lfunc_begin111
	.quad	Ltmp2122
	.short	1
	.byte	85
	.quad	Ltmp2122
	.quad	Ltmp2125
	.short	1
	.byte	94
	.quad	Ltmp2125
	.quad	Lfunc_end111
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc668:
	.quad	Lfunc_begin111
	.quad	Ltmp2121
	.short	1
	.byte	84
	.quad	Ltmp2121
	.quad	Ltmp2124
	.short	1
	.byte	83
	.quad	Ltmp2124
	.quad	Lfunc_end111
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc672:
	.quad	Lfunc_begin112
	.quad	Ltmp2144
	.short	1
	.byte	85
	.quad	Ltmp2144
	.quad	Ltmp2146
	.short	1
	.byte	94
	.quad	Ltmp2146
	.quad	Lfunc_end112
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc676:
	.quad	Lfunc_begin112
	.quad	Ltmp2143
	.short	1
	.byte	84
	.quad	Ltmp2143
	.quad	Ltmp2145
	.short	1
	.byte	83
	.quad	Ltmp2145
	.quad	Lfunc_end112
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc680:
	.quad	Lfunc_begin113
	.quad	Ltmp2163
	.short	1
	.byte	85
	.quad	Ltmp2163
	.quad	Ltmp2165
	.short	1
	.byte	94
	.quad	Ltmp2165
	.quad	Lfunc_end113
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc684:
	.quad	Lfunc_begin113
	.quad	Ltmp2162
	.short	1
	.byte	84
	.quad	Ltmp2162
	.quad	Ltmp2164
	.short	1
	.byte	83
	.quad	Ltmp2164
	.quad	Lfunc_end113
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc688:
	.quad	Lfunc_begin114
	.quad	Ltmp2182
	.short	1
	.byte	85
	.quad	Ltmp2182
	.quad	Ltmp2184
	.short	1
	.byte	94
	.quad	Ltmp2184
	.quad	Lfunc_end114
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc692:
	.quad	Lfunc_begin114
	.quad	Ltmp2181
	.short	1
	.byte	84
	.quad	Ltmp2181
	.quad	Ltmp2183
	.short	1
	.byte	83
	.quad	Ltmp2183
	.quad	Lfunc_end114
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc696:
	.quad	Lfunc_begin115
	.quad	Ltmp2201
	.short	1
	.byte	85
	.quad	Ltmp2201
	.quad	Ltmp2203
	.short	1
	.byte	94
	.quad	Ltmp2203
	.quad	Lfunc_end115
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc700:
	.quad	Lfunc_begin115
	.quad	Ltmp2200
	.short	1
	.byte	84
	.quad	Ltmp2200
	.quad	Ltmp2202
	.short	1
	.byte	83
	.quad	Ltmp2202
	.quad	Lfunc_end115
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc704:
	.quad	Lfunc_begin116
	.quad	Ltmp2219
	.short	1
	.byte	85
	.quad	Ltmp2219
	.quad	Ltmp2220
	.short	1
	.byte	94
	.quad	Ltmp2220
	.quad	Lfunc_end116
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc708:
	.quad	Lfunc_begin117
	.quad	Ltmp2236
	.short	1
	.byte	85
	.quad	Ltmp2236
	.quad	Ltmp2237
	.short	1
	.byte	94
	.quad	Ltmp2237
	.quad	Lfunc_end117
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc712:
	.quad	Lfunc_begin118
	.quad	Ltmp2253
	.short	1
	.byte	85
	.quad	Ltmp2253
	.quad	Ltmp2254
	.short	1
	.byte	94
	.quad	Ltmp2254
	.quad	Lfunc_end118
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc716:
	.quad	Lfunc_begin119
	.quad	Ltmp2270
	.short	1
	.byte	85
	.quad	Ltmp2270
	.quad	Ltmp2271
	.short	1
	.byte	94
	.quad	Ltmp2271
	.quad	Lfunc_end119
	.short	1
	.byte	94
	.quad	0
	.quad	0
Ldebug_loc720:
	.quad	Lfunc_begin120
	.quad	Ltmp2287
	.short	1
	.byte	85
	.quad	Ltmp2287
	.quad	Ltmp2288
	.short	1
	.byte	83
	.quad	Ltmp2288
	.quad	Lfunc_end120
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc724:
	.quad	Lfunc_begin121
	.quad	Ltmp2304
	.short	1
	.byte	85
	.quad	Ltmp2304
	.quad	Ltmp2305
	.short	1
	.byte	83
	.quad	Ltmp2305
	.quad	Lfunc_end121
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc728:
	.quad	Lfunc_begin122
	.quad	Ltmp2321
	.short	1
	.byte	85
	.quad	Ltmp2321
	.quad	Ltmp2322
	.short	1
	.byte	83
	.quad	Ltmp2322
	.quad	Lfunc_end122
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc732:
	.quad	Lfunc_begin123
	.quad	Ltmp2338
	.short	1
	.byte	85
	.quad	Ltmp2338
	.quad	Ltmp2339
	.short	1
	.byte	83
	.quad	Ltmp2339
	.quad	Lfunc_end123
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc736:
	.quad	Lfunc_begin124
	.quad	Ltmp2355
	.short	1
	.byte	85
	.quad	Ltmp2355
	.quad	Ltmp2356
	.short	1
	.byte	83
	.quad	Ltmp2356
	.quad	Lfunc_end124
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc740:
	.quad	Lfunc_begin125
	.quad	Ltmp2372
	.short	1
	.byte	85
	.quad	Ltmp2372
	.quad	Ltmp2373
	.short	1
	.byte	83
	.quad	Ltmp2373
	.quad	Lfunc_end125
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc744:
	.quad	Lfunc_begin126
	.quad	Ltmp2389
	.short	1
	.byte	85
	.quad	Ltmp2389
	.quad	Ltmp2390
	.short	1
	.byte	83
	.quad	Ltmp2390
	.quad	Lfunc_end126
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc748:
	.quad	Lfunc_begin127
	.quad	Ltmp2406
	.short	1
	.byte	85
	.quad	Ltmp2406
	.quad	Ltmp2407
	.short	1
	.byte	83
	.quad	Ltmp2407
	.quad	Lfunc_end127
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc752:
	.quad	Lfunc_begin128
	.quad	Ltmp2423
	.short	1
	.byte	85
	.quad	Ltmp2423
	.quad	Ltmp2424
	.short	1
	.byte	83
	.quad	Ltmp2424
	.quad	Lfunc_end128
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc756:
	.quad	Lfunc_begin129
	.quad	Ltmp2440
	.short	1
	.byte	85
	.quad	Ltmp2440
	.quad	Ltmp2441
	.short	1
	.byte	83
	.quad	Ltmp2441
	.quad	Lfunc_end129
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc760:
	.quad	Lfunc_begin130
	.quad	Ltmp2457
	.short	1
	.byte	85
	.quad	Ltmp2457
	.quad	Ltmp2458
	.short	1
	.byte	83
	.quad	Ltmp2458
	.quad	Lfunc_end130
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc764:
	.quad	Lfunc_begin131
	.quad	Ltmp2474
	.short	1
	.byte	85
	.quad	Ltmp2474
	.quad	Ltmp2475
	.short	1
	.byte	83
	.quad	Ltmp2475
	.quad	Lfunc_end131
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc768:
	.quad	Lfunc_begin132
	.quad	Ltmp2491
	.short	1
	.byte	85
	.quad	Ltmp2491
	.quad	Ltmp2492
	.short	1
	.byte	83
	.quad	Ltmp2492
	.quad	Lfunc_end132
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc772:
	.quad	Lfunc_begin133
	.quad	Ltmp2508
	.short	1
	.byte	85
	.quad	Ltmp2508
	.quad	Ltmp2509
	.short	1
	.byte	83
	.quad	Ltmp2509
	.quad	Lfunc_end133
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc776:
	.quad	Lfunc_begin134
	.quad	Ltmp2525
	.short	1
	.byte	85
	.quad	Ltmp2525
	.quad	Ltmp2526
	.short	1
	.byte	83
	.quad	Ltmp2526
	.quad	Lfunc_end134
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc780:
	.quad	Lfunc_begin135
	.quad	Ltmp2542
	.short	1
	.byte	85
	.quad	Ltmp2542
	.quad	Ltmp2543
	.short	1
	.byte	83
	.quad	Ltmp2543
	.quad	Lfunc_end135
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc784:
	.quad	Lfunc_begin136
	.quad	Ltmp2559
	.short	1
	.byte	85
	.quad	Ltmp2559
	.quad	Ltmp2560
	.short	1
	.byte	83
	.quad	Ltmp2560
	.quad	Lfunc_end136
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc788:
	.quad	Lfunc_begin137
	.quad	Ltmp2576
	.short	1
	.byte	85
	.quad	Ltmp2576
	.quad	Ltmp2577
	.short	1
	.byte	83
	.quad	Ltmp2577
	.quad	Lfunc_end137
	.short	1
	.byte	83
	.quad	0
	.quad	0
Ldebug_loc792:
	.section	__DWARF,__debug_aranges,regular,debug
	.section	__DWARF,__debug_ranges,regular,debug
	.quad	Ltmp29
	.quad	Ltmp30
	.quad	Ltmp32
	.quad	Ltmp33
	.quad	0
	.quad	0
	.quad	Ltmp38
	.quad	Ltmp39
	.quad	Ltmp41
	.quad	Ltmp42
	.quad	0
	.quad	0
	.quad	Ltmp45
	.quad	Ltmp46
	.quad	Ltmp48
	.quad	Ltmp49
	.quad	0
	.quad	0
	.quad	Ltmp61
	.quad	Ltmp62
	.quad	Ltmp64
	.quad	Ltmp65
	.quad	0
	.quad	0
	.quad	Ltmp70
	.quad	Ltmp71
	.quad	Ltmp73
	.quad	Ltmp74
	.quad	0
	.quad	0
	.quad	Ltmp77
	.quad	Ltmp78
	.quad	Ltmp80
	.quad	Ltmp81
	.quad	0
	.quad	0
	.quad	Ltmp93
	.quad	Ltmp94
	.quad	Ltmp96
	.quad	Ltmp97
	.quad	0
	.quad	0
	.quad	Ltmp102
	.quad	Ltmp103
	.quad	Ltmp105
	.quad	Ltmp106
	.quad	0
	.quad	0
	.quad	Ltmp117
	.quad	Ltmp118
	.quad	Ltmp120
	.quad	Ltmp129
	.quad	0
	.quad	0
	.quad	Ltmp117
	.quad	Ltmp118
	.quad	Ltmp120
	.quad	Ltmp121
	.quad	0
	.quad	0
	.quad	Ltmp117
	.quad	Ltmp118
	.quad	Ltmp120
	.quad	Ltmp121
	.quad	0
	.quad	0
	.quad	Ltmp123
	.quad	Ltmp124
	.quad	Ltmp126
	.quad	Ltmp127
	.quad	0
	.quad	0
	.quad	Ltmp123
	.quad	Ltmp124
	.quad	Ltmp126
	.quad	Ltmp127
	.quad	0
	.quad	0
	.quad	Ltmp138
	.quad	Ltmp139
	.quad	Ltmp141
	.quad	Ltmp150
	.quad	0
	.quad	0
	.quad	Ltmp138
	.quad	Ltmp139
	.quad	Ltmp141
	.quad	Ltmp142
	.quad	0
	.quad	0
	.quad	Ltmp138
	.quad	Ltmp139
	.quad	Ltmp141
	.quad	Ltmp142
	.quad	0
	.quad	0
	.quad	Ltmp144
	.quad	Ltmp145
	.quad	Ltmp147
	.quad	Ltmp148
	.quad	0
	.quad	0
	.quad	Ltmp144
	.quad	Ltmp145
	.quad	Ltmp147
	.quad	Ltmp148
	.quad	0
	.quad	0
	.quad	Ltmp159
	.quad	Ltmp160
	.quad	Ltmp162
	.quad	Ltmp171
	.quad	0
	.quad	0
	.quad	Ltmp159
	.quad	Ltmp160
	.quad	Ltmp162
	.quad	Ltmp163
	.quad	0
	.quad	0
	.quad	Ltmp159
	.quad	Ltmp160
	.quad	Ltmp162
	.quad	Ltmp163
	.quad	0
	.quad	0
	.quad	Ltmp165
	.quad	Ltmp166
	.quad	Ltmp168
	.quad	Ltmp169
	.quad	0
	.quad	0
	.quad	Ltmp165
	.quad	Ltmp166
	.quad	Ltmp168
	.quad	Ltmp169
	.quad	0
	.quad	0
	.quad	Ltmp180
	.quad	Ltmp181
	.quad	Ltmp183
	.quad	Ltmp192
	.quad	0
	.quad	0
	.quad	Ltmp180
	.quad	Ltmp181
	.quad	Ltmp183
	.quad	Ltmp184
	.quad	0
	.quad	0
	.quad	Ltmp180
	.quad	Ltmp181
	.quad	Ltmp183
	.quad	Ltmp184
	.quad	0
	.quad	0
	.quad	Ltmp186
	.quad	Ltmp187
	.quad	Ltmp189
	.quad	Ltmp190
	.quad	0
	.quad	0
	.quad	Ltmp186
	.quad	Ltmp187
	.quad	Ltmp189
	.quad	Ltmp190
	.quad	0
	.quad	0
	.quad	Ltmp199
	.quad	Ltmp200
	.quad	Ltmp202
	.quad	Ltmp211
	.quad	0
	.quad	0
	.quad	Ltmp199
	.quad	Ltmp200
	.quad	Ltmp202
	.quad	Ltmp203
	.quad	0
	.quad	0
	.quad	Ltmp199
	.quad	Ltmp200
	.quad	Ltmp202
	.quad	Ltmp203
	.quad	0
	.quad	0
	.quad	Ltmp205
	.quad	Ltmp206
	.quad	Ltmp208
	.quad	Ltmp209
	.quad	0
	.quad	0
	.quad	Ltmp205
	.quad	Ltmp206
	.quad	Ltmp208
	.quad	Ltmp209
	.quad	0
	.quad	0
	.quad	Ltmp218
	.quad	Ltmp219
	.quad	Ltmp221
	.quad	Ltmp230
	.quad	0
	.quad	0
	.quad	Ltmp218
	.quad	Ltmp219
	.quad	Ltmp221
	.quad	Ltmp222
	.quad	0
	.quad	0
	.quad	Ltmp218
	.quad	Ltmp219
	.quad	Ltmp221
	.quad	Ltmp222
	.quad	0
	.quad	0
	.quad	Ltmp224
	.quad	Ltmp225
	.quad	Ltmp227
	.quad	Ltmp228
	.quad	0
	.quad	0
	.quad	Ltmp224
	.quad	Ltmp225
	.quad	Ltmp227
	.quad	Ltmp228
	.quad	0
	.quad	0
	.quad	Ltmp237
	.quad	Ltmp238
	.quad	Ltmp240
	.quad	Ltmp249
	.quad	0
	.quad	0
	.quad	Ltmp237
	.quad	Ltmp238
	.quad	Ltmp240
	.quad	Ltmp241
	.quad	0
	.quad	0
	.quad	Ltmp237
	.quad	Ltmp238
	.quad	Ltmp240
	.quad	Ltmp241
	.quad	0
	.quad	0
	.quad	Ltmp243
	.quad	Ltmp244
	.quad	Ltmp246
	.quad	Ltmp247
	.quad	0
	.quad	0
	.quad	Ltmp243
	.quad	Ltmp244
	.quad	Ltmp246
	.quad	Ltmp247
	.quad	0
	.quad	0
	.quad	Ltmp256
	.quad	Ltmp257
	.quad	Ltmp259
	.quad	Ltmp268
	.quad	0
	.quad	0
	.quad	Ltmp256
	.quad	Ltmp257
	.quad	Ltmp259
	.quad	Ltmp260
	.quad	0
	.quad	0
	.quad	Ltmp256
	.quad	Ltmp257
	.quad	Ltmp259
	.quad	Ltmp260
	.quad	0
	.quad	0
	.quad	Ltmp262
	.quad	Ltmp263
	.quad	Ltmp265
	.quad	Ltmp266
	.quad	0
	.quad	0
	.quad	Ltmp262
	.quad	Ltmp263
	.quad	Ltmp265
	.quad	Ltmp266
	.quad	0
	.quad	0
	.quad	Ltmp280
	.quad	Ltmp281
	.quad	Ltmp283
	.quad	Ltmp284
	.quad	0
	.quad	0
	.quad	Ltmp289
	.quad	Ltmp290
	.quad	Ltmp292
	.quad	Ltmp293
	.quad	0
	.quad	0
	.quad	Ltmp317
	.quad	Ltmp318
	.quad	Ltmp320
	.quad	Ltmp330
	.quad	0
	.quad	0
	.quad	Ltmp317
	.quad	Ltmp318
	.quad	Ltmp320
	.quad	Ltmp321
	.quad	0
	.quad	0
	.quad	Ltmp317
	.quad	Ltmp318
	.quad	Ltmp320
	.quad	Ltmp321
	.quad	0
	.quad	0
	.quad	Ltmp324
	.quad	Ltmp325
	.quad	Ltmp327
	.quad	Ltmp328
	.quad	0
	.quad	0
	.quad	Ltmp352
	.quad	Ltmp353
	.quad	Ltmp355
	.quad	Ltmp365
	.quad	0
	.quad	0
	.quad	Ltmp352
	.quad	Ltmp353
	.quad	Ltmp355
	.quad	Ltmp356
	.quad	0
	.quad	0
	.quad	Ltmp352
	.quad	Ltmp353
	.quad	Ltmp355
	.quad	Ltmp356
	.quad	0
	.quad	0
	.quad	Ltmp359
	.quad	Ltmp360
	.quad	Ltmp362
	.quad	Ltmp363
	.quad	0
	.quad	0
	.quad	Ltmp387
	.quad	Ltmp388
	.quad	Ltmp390
	.quad	Ltmp400
	.quad	0
	.quad	0
	.quad	Ltmp387
	.quad	Ltmp388
	.quad	Ltmp390
	.quad	Ltmp391
	.quad	0
	.quad	0
	.quad	Ltmp387
	.quad	Ltmp388
	.quad	Ltmp390
	.quad	Ltmp391
	.quad	0
	.quad	0
	.quad	Ltmp394
	.quad	Ltmp395
	.quad	Ltmp397
	.quad	Ltmp398
	.quad	0
	.quad	0
	.quad	Ltmp411
	.quad	Ltmp412
	.quad	Ltmp414
	.quad	Ltmp424
	.quad	0
	.quad	0
	.quad	Ltmp411
	.quad	Ltmp412
	.quad	Ltmp414
	.quad	Ltmp415
	.quad	0
	.quad	0
	.quad	Ltmp411
	.quad	Ltmp412
	.quad	Ltmp414
	.quad	Ltmp415
	.quad	0
	.quad	0
	.quad	Ltmp418
	.quad	Ltmp419
	.quad	Ltmp421
	.quad	Ltmp422
	.quad	0
	.quad	0
	.quad	Ltmp442
	.quad	Ltmp443
	.quad	Ltmp445
	.quad	Ltmp455
	.quad	0
	.quad	0
	.quad	Ltmp442
	.quad	Ltmp443
	.quad	Ltmp445
	.quad	Ltmp446
	.quad	0
	.quad	0
	.quad	Ltmp442
	.quad	Ltmp443
	.quad	Ltmp445
	.quad	Ltmp446
	.quad	0
	.quad	0
	.quad	Ltmp449
	.quad	Ltmp450
	.quad	Ltmp452
	.quad	Ltmp453
	.quad	0
	.quad	0
	.quad	Ltmp462
	.quad	Ltmp463
	.quad	Ltmp465
	.quad	Ltmp475
	.quad	0
	.quad	0
	.quad	Ltmp462
	.quad	Ltmp463
	.quad	Ltmp465
	.quad	Ltmp466
	.quad	0
	.quad	0
	.quad	Ltmp462
	.quad	Ltmp463
	.quad	Ltmp465
	.quad	Ltmp466
	.quad	0
	.quad	0
	.quad	Ltmp469
	.quad	Ltmp470
	.quad	Ltmp472
	.quad	Ltmp473
	.quad	0
	.quad	0
	.quad	Ltmp482
	.quad	Ltmp483
	.quad	Ltmp485
	.quad	Ltmp495
	.quad	0
	.quad	0
	.quad	Ltmp482
	.quad	Ltmp483
	.quad	Ltmp485
	.quad	Ltmp486
	.quad	0
	.quad	0
	.quad	Ltmp482
	.quad	Ltmp483
	.quad	Ltmp485
	.quad	Ltmp486
	.quad	0
	.quad	0
	.quad	Ltmp489
	.quad	Ltmp490
	.quad	Ltmp492
	.quad	Ltmp493
	.quad	0
	.quad	0
	.quad	Ltmp502
	.quad	Ltmp503
	.quad	Ltmp505
	.quad	Ltmp515
	.quad	0
	.quad	0
	.quad	Ltmp502
	.quad	Ltmp503
	.quad	Ltmp505
	.quad	Ltmp506
	.quad	0
	.quad	0
	.quad	Ltmp502
	.quad	Ltmp503
	.quad	Ltmp505
	.quad	Ltmp506
	.quad	0
	.quad	0
	.quad	Ltmp509
	.quad	Ltmp510
	.quad	Ltmp512
	.quad	Ltmp513
	.quad	0
	.quad	0
	.quad	Ltmp531
	.quad	Ltmp532
	.quad	Ltmp534
	.quad	Ltmp544
	.quad	0
	.quad	0
	.quad	Ltmp531
	.quad	Ltmp532
	.quad	Ltmp534
	.quad	Ltmp535
	.quad	0
	.quad	0
	.quad	Ltmp531
	.quad	Ltmp532
	.quad	Ltmp534
	.quad	Ltmp535
	.quad	0
	.quad	0
	.quad	Ltmp538
	.quad	Ltmp539
	.quad	Ltmp541
	.quad	Ltmp542
	.quad	0
	.quad	0
	.quad	Ltmp538
	.quad	Ltmp539
	.quad	Ltmp541
	.quad	Ltmp542
	.quad	0
	.quad	0
	.quad	Ltmp553
	.quad	Ltmp554
	.quad	Ltmp556
	.quad	Ltmp566
	.quad	0
	.quad	0
	.quad	Ltmp553
	.quad	Ltmp554
	.quad	Ltmp556
	.quad	Ltmp557
	.quad	0
	.quad	0
	.quad	Ltmp553
	.quad	Ltmp554
	.quad	Ltmp556
	.quad	Ltmp557
	.quad	0
	.quad	0
	.quad	Ltmp560
	.quad	Ltmp561
	.quad	Ltmp563
	.quad	Ltmp564
	.quad	0
	.quad	0
	.quad	Ltmp560
	.quad	Ltmp561
	.quad	Ltmp563
	.quad	Ltmp564
	.quad	0
	.quad	0
	.quad	Ltmp575
	.quad	Ltmp576
	.quad	Ltmp578
	.quad	Ltmp588
	.quad	0
	.quad	0
	.quad	Ltmp575
	.quad	Ltmp576
	.quad	Ltmp578
	.quad	Ltmp579
	.quad	0
	.quad	0
	.quad	Ltmp575
	.quad	Ltmp576
	.quad	Ltmp578
	.quad	Ltmp579
	.quad	0
	.quad	0
	.quad	Ltmp582
	.quad	Ltmp583
	.quad	Ltmp585
	.quad	Ltmp586
	.quad	0
	.quad	0
	.quad	Ltmp582
	.quad	Ltmp583
	.quad	Ltmp585
	.quad	Ltmp586
	.quad	0
	.quad	0
	.quad	Ltmp597
	.quad	Ltmp598
	.quad	Ltmp600
	.quad	Ltmp610
	.quad	0
	.quad	0
	.quad	Ltmp597
	.quad	Ltmp598
	.quad	Ltmp600
	.quad	Ltmp601
	.quad	0
	.quad	0
	.quad	Ltmp597
	.quad	Ltmp598
	.quad	Ltmp600
	.quad	Ltmp601
	.quad	0
	.quad	0
	.quad	Ltmp604
	.quad	Ltmp605
	.quad	Ltmp607
	.quad	Ltmp608
	.quad	0
	.quad	0
	.quad	Ltmp604
	.quad	Ltmp605
	.quad	Ltmp607
	.quad	Ltmp608
	.quad	0
	.quad	0
	.quad	Ltmp617
	.quad	Ltmp618
	.quad	Ltmp620
	.quad	Ltmp630
	.quad	0
	.quad	0
	.quad	Ltmp617
	.quad	Ltmp618
	.quad	Ltmp620
	.quad	Ltmp621
	.quad	0
	.quad	0
	.quad	Ltmp617
	.quad	Ltmp618
	.quad	Ltmp620
	.quad	Ltmp621
	.quad	0
	.quad	0
	.quad	Ltmp624
	.quad	Ltmp625
	.quad	Ltmp627
	.quad	Ltmp628
	.quad	0
	.quad	0
	.quad	Ltmp624
	.quad	Ltmp625
	.quad	Ltmp627
	.quad	Ltmp628
	.quad	0
	.quad	0
	.quad	Ltmp637
	.quad	Ltmp638
	.quad	Ltmp640
	.quad	Ltmp650
	.quad	0
	.quad	0
	.quad	Ltmp637
	.quad	Ltmp638
	.quad	Ltmp640
	.quad	Ltmp641
	.quad	0
	.quad	0
	.quad	Ltmp637
	.quad	Ltmp638
	.quad	Ltmp640
	.quad	Ltmp641
	.quad	0
	.quad	0
	.quad	Ltmp644
	.quad	Ltmp645
	.quad	Ltmp647
	.quad	Ltmp648
	.quad	0
	.quad	0
	.quad	Ltmp644
	.quad	Ltmp645
	.quad	Ltmp647
	.quad	Ltmp648
	.quad	0
	.quad	0
	.quad	Ltmp657
	.quad	Ltmp658
	.quad	Ltmp660
	.quad	Ltmp670
	.quad	0
	.quad	0
	.quad	Ltmp657
	.quad	Ltmp658
	.quad	Ltmp660
	.quad	Ltmp661
	.quad	0
	.quad	0
	.quad	Ltmp657
	.quad	Ltmp658
	.quad	Ltmp660
	.quad	Ltmp661
	.quad	0
	.quad	0
	.quad	Ltmp664
	.quad	Ltmp665
	.quad	Ltmp667
	.quad	Ltmp668
	.quad	0
	.quad	0
	.quad	Ltmp664
	.quad	Ltmp665
	.quad	Ltmp667
	.quad	Ltmp668
	.quad	0
	.quad	0
	.quad	Ltmp677
	.quad	Ltmp678
	.quad	Ltmp680
	.quad	Ltmp690
	.quad	0
	.quad	0
	.quad	Ltmp677
	.quad	Ltmp678
	.quad	Ltmp680
	.quad	Ltmp681
	.quad	0
	.quad	0
	.quad	Ltmp677
	.quad	Ltmp678
	.quad	Ltmp680
	.quad	Ltmp681
	.quad	0
	.quad	0
	.quad	Ltmp684
	.quad	Ltmp685
	.quad	Ltmp687
	.quad	Ltmp688
	.quad	0
	.quad	0
	.quad	Ltmp684
	.quad	Ltmp685
	.quad	Ltmp687
	.quad	Ltmp688
	.quad	0
	.quad	0
	.quad	Ltmp699
	.quad	Ltmp700
	.quad	Ltmp702
	.quad	Ltmp712
	.quad	0
	.quad	0
	.quad	Ltmp699
	.quad	Ltmp700
	.quad	Ltmp702
	.quad	Ltmp703
	.quad	0
	.quad	0
	.quad	Ltmp699
	.quad	Ltmp700
	.quad	Ltmp702
	.quad	Ltmp703
	.quad	0
	.quad	0
	.quad	Ltmp706
	.quad	Ltmp707
	.quad	Ltmp709
	.quad	Ltmp710
	.quad	0
	.quad	0
	.quad	Ltmp706
	.quad	Ltmp707
	.quad	Ltmp709
	.quad	Ltmp710
	.quad	0
	.quad	0
	.quad	Ltmp721
	.quad	Ltmp722
	.quad	Ltmp724
	.quad	Ltmp734
	.quad	0
	.quad	0
	.quad	Ltmp721
	.quad	Ltmp722
	.quad	Ltmp724
	.quad	Ltmp725
	.quad	0
	.quad	0
	.quad	Ltmp721
	.quad	Ltmp722
	.quad	Ltmp724
	.quad	Ltmp725
	.quad	0
	.quad	0
	.quad	Ltmp728
	.quad	Ltmp729
	.quad	Ltmp731
	.quad	Ltmp732
	.quad	0
	.quad	0
	.quad	Ltmp728
	.quad	Ltmp729
	.quad	Ltmp731
	.quad	Ltmp732
	.quad	0
	.quad	0
	.quad	Ltmp743
	.quad	Ltmp744
	.quad	Ltmp746
	.quad	Ltmp756
	.quad	0
	.quad	0
	.quad	Ltmp743
	.quad	Ltmp744
	.quad	Ltmp746
	.quad	Ltmp747
	.quad	0
	.quad	0
	.quad	Ltmp743
	.quad	Ltmp744
	.quad	Ltmp746
	.quad	Ltmp747
	.quad	0
	.quad	0
	.quad	Ltmp750
	.quad	Ltmp751
	.quad	Ltmp753
	.quad	Ltmp754
	.quad	0
	.quad	0
	.quad	Ltmp750
	.quad	Ltmp751
	.quad	Ltmp753
	.quad	Ltmp754
	.quad	0
	.quad	0
	.quad	Ltmp765
	.quad	Ltmp766
	.quad	Ltmp768
	.quad	Ltmp778
	.quad	0
	.quad	0
	.quad	Ltmp765
	.quad	Ltmp766
	.quad	Ltmp768
	.quad	Ltmp769
	.quad	0
	.quad	0
	.quad	Ltmp765
	.quad	Ltmp766
	.quad	Ltmp768
	.quad	Ltmp769
	.quad	0
	.quad	0
	.quad	Ltmp772
	.quad	Ltmp773
	.quad	Ltmp775
	.quad	Ltmp776
	.quad	0
	.quad	0
	.quad	Ltmp772
	.quad	Ltmp773
	.quad	Ltmp775
	.quad	Ltmp776
	.quad	0
	.quad	0
	.quad	Ltmp787
	.quad	Ltmp788
	.quad	Ltmp790
	.quad	Ltmp800
	.quad	0
	.quad	0
	.quad	Ltmp787
	.quad	Ltmp788
	.quad	Ltmp790
	.quad	Ltmp791
	.quad	0
	.quad	0
	.quad	Ltmp787
	.quad	Ltmp788
	.quad	Ltmp790
	.quad	Ltmp791
	.quad	0
	.quad	0
	.quad	Ltmp794
	.quad	Ltmp795
	.quad	Ltmp797
	.quad	Ltmp798
	.quad	0
	.quad	0
	.quad	Ltmp794
	.quad	Ltmp795
	.quad	Ltmp797
	.quad	Ltmp798
	.quad	0
	.quad	0
	.quad	Ltmp807
	.quad	Ltmp808
	.quad	Ltmp810
	.quad	Ltmp820
	.quad	0
	.quad	0
	.quad	Ltmp807
	.quad	Ltmp808
	.quad	Ltmp810
	.quad	Ltmp811
	.quad	0
	.quad	0
	.quad	Ltmp807
	.quad	Ltmp808
	.quad	Ltmp810
	.quad	Ltmp811
	.quad	0
	.quad	0
	.quad	Ltmp814
	.quad	Ltmp815
	.quad	Ltmp817
	.quad	Ltmp818
	.quad	0
	.quad	0
	.quad	Ltmp814
	.quad	Ltmp815
	.quad	Ltmp817
	.quad	Ltmp818
	.quad	0
	.quad	0
	.quad	Ltmp827
	.quad	Ltmp828
	.quad	Ltmp830
	.quad	Ltmp840
	.quad	0
	.quad	0
	.quad	Ltmp827
	.quad	Ltmp828
	.quad	Ltmp830
	.quad	Ltmp831
	.quad	0
	.quad	0
	.quad	Ltmp827
	.quad	Ltmp828
	.quad	Ltmp830
	.quad	Ltmp831
	.quad	0
	.quad	0
	.quad	Ltmp834
	.quad	Ltmp835
	.quad	Ltmp837
	.quad	Ltmp838
	.quad	0
	.quad	0
	.quad	Ltmp834
	.quad	Ltmp835
	.quad	Ltmp837
	.quad	Ltmp838
	.quad	0
	.quad	0
	.quad	Ltmp847
	.quad	Ltmp848
	.quad	Ltmp850
	.quad	Ltmp860
	.quad	0
	.quad	0
	.quad	Ltmp847
	.quad	Ltmp848
	.quad	Ltmp850
	.quad	Ltmp851
	.quad	0
	.quad	0
	.quad	Ltmp847
	.quad	Ltmp848
	.quad	Ltmp850
	.quad	Ltmp851
	.quad	0
	.quad	0
	.quad	Ltmp854
	.quad	Ltmp855
	.quad	Ltmp857
	.quad	Ltmp858
	.quad	0
	.quad	0
	.quad	Ltmp854
	.quad	Ltmp855
	.quad	Ltmp857
	.quad	Ltmp858
	.quad	0
	.quad	0
	.quad	Ltmp867
	.quad	Ltmp868
	.quad	Ltmp870
	.quad	Ltmp880
	.quad	0
	.quad	0
	.quad	Ltmp867
	.quad	Ltmp868
	.quad	Ltmp870
	.quad	Ltmp871
	.quad	0
	.quad	0
	.quad	Ltmp867
	.quad	Ltmp868
	.quad	Ltmp870
	.quad	Ltmp871
	.quad	0
	.quad	0
	.quad	Ltmp874
	.quad	Ltmp875
	.quad	Ltmp877
	.quad	Ltmp878
	.quad	0
	.quad	0
	.quad	Ltmp874
	.quad	Ltmp875
	.quad	Ltmp877
	.quad	Ltmp878
	.quad	0
	.quad	0
	.quad	Ltmp889
	.quad	Ltmp890
	.quad	Ltmp892
	.quad	Ltmp902
	.quad	0
	.quad	0
	.quad	Ltmp889
	.quad	Ltmp890
	.quad	Ltmp892
	.quad	Ltmp893
	.quad	0
	.quad	0
	.quad	Ltmp889
	.quad	Ltmp890
	.quad	Ltmp892
	.quad	Ltmp893
	.quad	0
	.quad	0
	.quad	Ltmp896
	.quad	Ltmp897
	.quad	Ltmp899
	.quad	Ltmp900
	.quad	0
	.quad	0
	.quad	Ltmp896
	.quad	Ltmp897
	.quad	Ltmp899
	.quad	Ltmp900
	.quad	0
	.quad	0
	.quad	Ltmp912
	.quad	Ltmp913
	.quad	Ltmp915
	.quad	Ltmp916
	.quad	0
	.quad	0
	.quad	Ltmp919
	.quad	Ltmp920
	.quad	Ltmp922
	.quad	Ltmp923
	.quad	0
	.quad	0
	.quad	Ltmp934
	.quad	Ltmp935
	.quad	Ltmp937
	.quad	Ltmp947
	.quad	0
	.quad	0
	.quad	Ltmp934
	.quad	Ltmp935
	.quad	Ltmp937
	.quad	Ltmp938
	.quad	0
	.quad	0
	.quad	Ltmp934
	.quad	Ltmp935
	.quad	Ltmp937
	.quad	Ltmp938
	.quad	0
	.quad	0
	.quad	Ltmp941
	.quad	Ltmp942
	.quad	Ltmp944
	.quad	Ltmp945
	.quad	0
	.quad	0
	.quad	Ltmp941
	.quad	Ltmp942
	.quad	Ltmp944
	.quad	Ltmp945
	.quad	0
	.quad	0
	.quad	Ltmp956
	.quad	Ltmp957
	.quad	Ltmp959
	.quad	Ltmp969
	.quad	0
	.quad	0
	.quad	Ltmp956
	.quad	Ltmp957
	.quad	Ltmp959
	.quad	Ltmp960
	.quad	0
	.quad	0
	.quad	Ltmp956
	.quad	Ltmp957
	.quad	Ltmp959
	.quad	Ltmp960
	.quad	0
	.quad	0
	.quad	Ltmp963
	.quad	Ltmp964
	.quad	Ltmp966
	.quad	Ltmp967
	.quad	0
	.quad	0
	.quad	Ltmp963
	.quad	Ltmp964
	.quad	Ltmp966
	.quad	Ltmp967
	.quad	0
	.quad	0
	.quad	Ltmp978
	.quad	Ltmp979
	.quad	Ltmp981
	.quad	Ltmp991
	.quad	0
	.quad	0
	.quad	Ltmp978
	.quad	Ltmp979
	.quad	Ltmp981
	.quad	Ltmp982
	.quad	0
	.quad	0
	.quad	Ltmp978
	.quad	Ltmp979
	.quad	Ltmp981
	.quad	Ltmp982
	.quad	0
	.quad	0
	.quad	Ltmp985
	.quad	Ltmp986
	.quad	Ltmp988
	.quad	Ltmp989
	.quad	0
	.quad	0
	.quad	Ltmp985
	.quad	Ltmp986
	.quad	Ltmp988
	.quad	Ltmp989
	.quad	0
	.quad	0
	.quad	Ltmp1000
	.quad	Ltmp1001
	.quad	Ltmp1003
	.quad	Ltmp1013
	.quad	0
	.quad	0
	.quad	Ltmp1000
	.quad	Ltmp1001
	.quad	Ltmp1003
	.quad	Ltmp1004
	.quad	0
	.quad	0
	.quad	Ltmp1000
	.quad	Ltmp1001
	.quad	Ltmp1003
	.quad	Ltmp1004
	.quad	0
	.quad	0
	.quad	Ltmp1007
	.quad	Ltmp1008
	.quad	Ltmp1010
	.quad	Ltmp1011
	.quad	0
	.quad	0
	.quad	Ltmp1007
	.quad	Ltmp1008
	.quad	Ltmp1010
	.quad	Ltmp1011
	.quad	0
	.quad	0
	.quad	Ltmp1020
	.quad	Ltmp1021
	.quad	Ltmp1023
	.quad	Ltmp1033
	.quad	0
	.quad	0
	.quad	Ltmp1020
	.quad	Ltmp1021
	.quad	Ltmp1023
	.quad	Ltmp1024
	.quad	0
	.quad	0
	.quad	Ltmp1020
	.quad	Ltmp1021
	.quad	Ltmp1023
	.quad	Ltmp1024
	.quad	0
	.quad	0
	.quad	Ltmp1027
	.quad	Ltmp1028
	.quad	Ltmp1030
	.quad	Ltmp1031
	.quad	0
	.quad	0
	.quad	Ltmp1027
	.quad	Ltmp1028
	.quad	Ltmp1030
	.quad	Ltmp1031
	.quad	0
	.quad	0
	.quad	Ltmp1040
	.quad	Ltmp1041
	.quad	Ltmp1043
	.quad	Ltmp1053
	.quad	0
	.quad	0
	.quad	Ltmp1040
	.quad	Ltmp1041
	.quad	Ltmp1043
	.quad	Ltmp1044
	.quad	0
	.quad	0
	.quad	Ltmp1040
	.quad	Ltmp1041
	.quad	Ltmp1043
	.quad	Ltmp1044
	.quad	0
	.quad	0
	.quad	Ltmp1047
	.quad	Ltmp1048
	.quad	Ltmp1050
	.quad	Ltmp1051
	.quad	0
	.quad	0
	.quad	Ltmp1047
	.quad	Ltmp1048
	.quad	Ltmp1050
	.quad	Ltmp1051
	.quad	0
	.quad	0
	.quad	Ltmp1060
	.quad	Ltmp1061
	.quad	Ltmp1063
	.quad	Ltmp1073
	.quad	0
	.quad	0
	.quad	Ltmp1060
	.quad	Ltmp1061
	.quad	Ltmp1063
	.quad	Ltmp1064
	.quad	0
	.quad	0
	.quad	Ltmp1060
	.quad	Ltmp1061
	.quad	Ltmp1063
	.quad	Ltmp1064
	.quad	0
	.quad	0
	.quad	Ltmp1067
	.quad	Ltmp1068
	.quad	Ltmp1070
	.quad	Ltmp1071
	.quad	0
	.quad	0
	.quad	Ltmp1067
	.quad	Ltmp1068
	.quad	Ltmp1070
	.quad	Ltmp1071
	.quad	0
	.quad	0
	.quad	Ltmp1080
	.quad	Ltmp1081
	.quad	Ltmp1083
	.quad	Ltmp1093
	.quad	0
	.quad	0
	.quad	Ltmp1080
	.quad	Ltmp1081
	.quad	Ltmp1083
	.quad	Ltmp1084
	.quad	0
	.quad	0
	.quad	Ltmp1080
	.quad	Ltmp1081
	.quad	Ltmp1083
	.quad	Ltmp1084
	.quad	0
	.quad	0
	.quad	Ltmp1087
	.quad	Ltmp1088
	.quad	Ltmp1090
	.quad	Ltmp1091
	.quad	0
	.quad	0
	.quad	Ltmp1087
	.quad	Ltmp1088
	.quad	Ltmp1090
	.quad	Ltmp1091
	.quad	0
	.quad	0
	.quad	Ltmp1103
	.quad	Ltmp1104
	.quad	Ltmp1106
	.quad	Ltmp1107
	.quad	0
	.quad	0
	.quad	Ltmp1110
	.quad	Ltmp1111
	.quad	Ltmp1113
	.quad	Ltmp1114
	.quad	0
	.quad	0
	.quad	Ltmp1125
	.quad	Ltmp1126
	.quad	Ltmp1128
	.quad	Ltmp1138
	.quad	0
	.quad	0
	.quad	Ltmp1125
	.quad	Ltmp1126
	.quad	Ltmp1128
	.quad	Ltmp1129
	.quad	0
	.quad	0
	.quad	Ltmp1125
	.quad	Ltmp1126
	.quad	Ltmp1128
	.quad	Ltmp1129
	.quad	0
	.quad	0
	.quad	Ltmp1132
	.quad	Ltmp1133
	.quad	Ltmp1135
	.quad	Ltmp1136
	.quad	0
	.quad	0
	.quad	Ltmp1132
	.quad	Ltmp1133
	.quad	Ltmp1135
	.quad	Ltmp1136
	.quad	0
	.quad	0
	.quad	Ltmp1147
	.quad	Ltmp1148
	.quad	Ltmp1150
	.quad	Ltmp1160
	.quad	0
	.quad	0
	.quad	Ltmp1147
	.quad	Ltmp1148
	.quad	Ltmp1150
	.quad	Ltmp1151
	.quad	0
	.quad	0
	.quad	Ltmp1147
	.quad	Ltmp1148
	.quad	Ltmp1150
	.quad	Ltmp1151
	.quad	0
	.quad	0
	.quad	Ltmp1154
	.quad	Ltmp1155
	.quad	Ltmp1157
	.quad	Ltmp1158
	.quad	0
	.quad	0
	.quad	Ltmp1154
	.quad	Ltmp1155
	.quad	Ltmp1157
	.quad	Ltmp1158
	.quad	0
	.quad	0
	.quad	Ltmp1169
	.quad	Ltmp1170
	.quad	Ltmp1172
	.quad	Ltmp1182
	.quad	0
	.quad	0
	.quad	Ltmp1169
	.quad	Ltmp1170
	.quad	Ltmp1172
	.quad	Ltmp1173
	.quad	0
	.quad	0
	.quad	Ltmp1169
	.quad	Ltmp1170
	.quad	Ltmp1172
	.quad	Ltmp1173
	.quad	0
	.quad	0
	.quad	Ltmp1176
	.quad	Ltmp1177
	.quad	Ltmp1179
	.quad	Ltmp1180
	.quad	0
	.quad	0
	.quad	Ltmp1176
	.quad	Ltmp1177
	.quad	Ltmp1179
	.quad	Ltmp1180
	.quad	0
	.quad	0
	.quad	Ltmp1191
	.quad	Ltmp1192
	.quad	Ltmp1194
	.quad	Ltmp1204
	.quad	0
	.quad	0
	.quad	Ltmp1191
	.quad	Ltmp1192
	.quad	Ltmp1194
	.quad	Ltmp1195
	.quad	0
	.quad	0
	.quad	Ltmp1191
	.quad	Ltmp1192
	.quad	Ltmp1194
	.quad	Ltmp1195
	.quad	0
	.quad	0
	.quad	Ltmp1198
	.quad	Ltmp1199
	.quad	Ltmp1201
	.quad	Ltmp1202
	.quad	0
	.quad	0
	.quad	Ltmp1198
	.quad	Ltmp1199
	.quad	Ltmp1201
	.quad	Ltmp1202
	.quad	0
	.quad	0
	.quad	Ltmp1211
	.quad	Ltmp1212
	.quad	Ltmp1214
	.quad	Ltmp1224
	.quad	0
	.quad	0
	.quad	Ltmp1211
	.quad	Ltmp1212
	.quad	Ltmp1214
	.quad	Ltmp1215
	.quad	0
	.quad	0
	.quad	Ltmp1211
	.quad	Ltmp1212
	.quad	Ltmp1214
	.quad	Ltmp1215
	.quad	0
	.quad	0
	.quad	Ltmp1218
	.quad	Ltmp1219
	.quad	Ltmp1221
	.quad	Ltmp1222
	.quad	0
	.quad	0
	.quad	Ltmp1218
	.quad	Ltmp1219
	.quad	Ltmp1221
	.quad	Ltmp1222
	.quad	0
	.quad	0
	.quad	Ltmp1231
	.quad	Ltmp1232
	.quad	Ltmp1234
	.quad	Ltmp1244
	.quad	0
	.quad	0
	.quad	Ltmp1231
	.quad	Ltmp1232
	.quad	Ltmp1234
	.quad	Ltmp1235
	.quad	0
	.quad	0
	.quad	Ltmp1231
	.quad	Ltmp1232
	.quad	Ltmp1234
	.quad	Ltmp1235
	.quad	0
	.quad	0
	.quad	Ltmp1238
	.quad	Ltmp1239
	.quad	Ltmp1241
	.quad	Ltmp1242
	.quad	0
	.quad	0
	.quad	Ltmp1238
	.quad	Ltmp1239
	.quad	Ltmp1241
	.quad	Ltmp1242
	.quad	0
	.quad	0
	.quad	Ltmp1251
	.quad	Ltmp1252
	.quad	Ltmp1254
	.quad	Ltmp1264
	.quad	0
	.quad	0
	.quad	Ltmp1251
	.quad	Ltmp1252
	.quad	Ltmp1254
	.quad	Ltmp1255
	.quad	0
	.quad	0
	.quad	Ltmp1251
	.quad	Ltmp1252
	.quad	Ltmp1254
	.quad	Ltmp1255
	.quad	0
	.quad	0
	.quad	Ltmp1258
	.quad	Ltmp1259
	.quad	Ltmp1261
	.quad	Ltmp1262
	.quad	0
	.quad	0
	.quad	Ltmp1258
	.quad	Ltmp1259
	.quad	Ltmp1261
	.quad	Ltmp1262
	.quad	0
	.quad	0
	.quad	Ltmp1271
	.quad	Ltmp1272
	.quad	Ltmp1274
	.quad	Ltmp1284
	.quad	0
	.quad	0
	.quad	Ltmp1271
	.quad	Ltmp1272
	.quad	Ltmp1274
	.quad	Ltmp1275
	.quad	0
	.quad	0
	.quad	Ltmp1271
	.quad	Ltmp1272
	.quad	Ltmp1274
	.quad	Ltmp1275
	.quad	0
	.quad	0
	.quad	Ltmp1278
	.quad	Ltmp1279
	.quad	Ltmp1281
	.quad	Ltmp1282
	.quad	0
	.quad	0
	.quad	Ltmp1278
	.quad	Ltmp1279
	.quad	Ltmp1281
	.quad	Ltmp1282
	.quad	0
	.quad	0
	.quad	Ltmp1291
	.quad	Ltmp1292
	.quad	Ltmp1294
	.quad	Ltmp1304
	.quad	0
	.quad	0
	.quad	Ltmp1291
	.quad	Ltmp1292
	.quad	Ltmp1294
	.quad	Ltmp1295
	.quad	0
	.quad	0
	.quad	Ltmp1291
	.quad	Ltmp1292
	.quad	Ltmp1294
	.quad	Ltmp1295
	.quad	0
	.quad	0
	.quad	Ltmp1298
	.quad	Ltmp1299
	.quad	Ltmp1301
	.quad	Ltmp1302
	.quad	0
	.quad	0
	.quad	Ltmp1298
	.quad	Ltmp1299
	.quad	Ltmp1301
	.quad	Ltmp1302
	.quad	0
	.quad	0
	.quad	Ltmp1311
	.quad	Ltmp1312
	.quad	Ltmp1314
	.quad	Ltmp1324
	.quad	0
	.quad	0
	.quad	Ltmp1311
	.quad	Ltmp1312
	.quad	Ltmp1314
	.quad	Ltmp1315
	.quad	0
	.quad	0
	.quad	Ltmp1311
	.quad	Ltmp1312
	.quad	Ltmp1314
	.quad	Ltmp1315
	.quad	0
	.quad	0
	.quad	Ltmp1318
	.quad	Ltmp1319
	.quad	Ltmp1321
	.quad	Ltmp1322
	.quad	0
	.quad	0
	.quad	Ltmp1318
	.quad	Ltmp1319
	.quad	Ltmp1321
	.quad	Ltmp1322
	.quad	0
	.quad	0
	.quad	Ltmp1331
	.quad	Ltmp1332
	.quad	Ltmp1334
	.quad	Ltmp1344
	.quad	0
	.quad	0
	.quad	Ltmp1331
	.quad	Ltmp1332
	.quad	Ltmp1334
	.quad	Ltmp1335
	.quad	0
	.quad	0
	.quad	Ltmp1331
	.quad	Ltmp1332
	.quad	Ltmp1334
	.quad	Ltmp1335
	.quad	0
	.quad	0
	.quad	Ltmp1338
	.quad	Ltmp1339
	.quad	Ltmp1341
	.quad	Ltmp1342
	.quad	0
	.quad	0
	.quad	Ltmp1338
	.quad	Ltmp1339
	.quad	Ltmp1341
	.quad	Ltmp1342
	.quad	0
	.quad	0
	.quad	Ltmp1351
	.quad	Ltmp1352
	.quad	Ltmp1354
	.quad	Ltmp1364
	.quad	0
	.quad	0
	.quad	Ltmp1351
	.quad	Ltmp1352
	.quad	Ltmp1354
	.quad	Ltmp1355
	.quad	0
	.quad	0
	.quad	Ltmp1351
	.quad	Ltmp1352
	.quad	Ltmp1354
	.quad	Ltmp1355
	.quad	0
	.quad	0
	.quad	Ltmp1358
	.quad	Ltmp1359
	.quad	Ltmp1361
	.quad	Ltmp1362
	.quad	0
	.quad	0
	.quad	Ltmp1358
	.quad	Ltmp1359
	.quad	Ltmp1361
	.quad	Ltmp1362
	.quad	0
	.quad	0
	.quad	Ltmp1371
	.quad	Ltmp1372
	.quad	Ltmp1374
	.quad	Ltmp1384
	.quad	0
	.quad	0
	.quad	Ltmp1371
	.quad	Ltmp1372
	.quad	Ltmp1374
	.quad	Ltmp1375
	.quad	0
	.quad	0
	.quad	Ltmp1371
	.quad	Ltmp1372
	.quad	Ltmp1374
	.quad	Ltmp1375
	.quad	0
	.quad	0
	.quad	Ltmp1378
	.quad	Ltmp1379
	.quad	Ltmp1381
	.quad	Ltmp1382
	.quad	0
	.quad	0
	.quad	Ltmp1378
	.quad	Ltmp1379
	.quad	Ltmp1381
	.quad	Ltmp1382
	.quad	0
	.quad	0
	.quad	Ltmp1391
	.quad	Ltmp1392
	.quad	Ltmp1394
	.quad	Ltmp1404
	.quad	0
	.quad	0
	.quad	Ltmp1391
	.quad	Ltmp1392
	.quad	Ltmp1394
	.quad	Ltmp1395
	.quad	0
	.quad	0
	.quad	Ltmp1391
	.quad	Ltmp1392
	.quad	Ltmp1394
	.quad	Ltmp1395
	.quad	0
	.quad	0
	.quad	Ltmp1398
	.quad	Ltmp1399
	.quad	Ltmp1401
	.quad	Ltmp1402
	.quad	0
	.quad	0
	.quad	Ltmp1398
	.quad	Ltmp1399
	.quad	Ltmp1401
	.quad	Ltmp1402
	.quad	0
	.quad	0
	.quad	Ltmp1411
	.quad	Ltmp1412
	.quad	Ltmp1414
	.quad	Ltmp1424
	.quad	0
	.quad	0
	.quad	Ltmp1411
	.quad	Ltmp1412
	.quad	Ltmp1414
	.quad	Ltmp1415
	.quad	0
	.quad	0
	.quad	Ltmp1411
	.quad	Ltmp1412
	.quad	Ltmp1414
	.quad	Ltmp1415
	.quad	0
	.quad	0
	.quad	Ltmp1418
	.quad	Ltmp1419
	.quad	Ltmp1421
	.quad	Ltmp1422
	.quad	0
	.quad	0
	.quad	Ltmp1418
	.quad	Ltmp1419
	.quad	Ltmp1421
	.quad	Ltmp1422
	.quad	0
	.quad	0
	.quad	Ltmp1431
	.quad	Ltmp1432
	.quad	Ltmp1434
	.quad	Ltmp1444
	.quad	0
	.quad	0
	.quad	Ltmp1431
	.quad	Ltmp1432
	.quad	Ltmp1434
	.quad	Ltmp1435
	.quad	0
	.quad	0
	.quad	Ltmp1431
	.quad	Ltmp1432
	.quad	Ltmp1434
	.quad	Ltmp1435
	.quad	0
	.quad	0
	.quad	Ltmp1438
	.quad	Ltmp1439
	.quad	Ltmp1441
	.quad	Ltmp1442
	.quad	0
	.quad	0
	.quad	Ltmp1438
	.quad	Ltmp1439
	.quad	Ltmp1441
	.quad	Ltmp1442
	.quad	0
	.quad	0
	.quad	Ltmp1451
	.quad	Ltmp1452
	.quad	Ltmp1454
	.quad	Ltmp1464
	.quad	0
	.quad	0
	.quad	Ltmp1451
	.quad	Ltmp1452
	.quad	Ltmp1454
	.quad	Ltmp1455
	.quad	0
	.quad	0
	.quad	Ltmp1451
	.quad	Ltmp1452
	.quad	Ltmp1454
	.quad	Ltmp1455
	.quad	0
	.quad	0
	.quad	Ltmp1458
	.quad	Ltmp1459
	.quad	Ltmp1461
	.quad	Ltmp1462
	.quad	0
	.quad	0
	.quad	Ltmp1458
	.quad	Ltmp1459
	.quad	Ltmp1461
	.quad	Ltmp1462
	.quad	0
	.quad	0
	.quad	Ltmp1471
	.quad	Ltmp1472
	.quad	Ltmp1474
	.quad	Ltmp1484
	.quad	0
	.quad	0
	.quad	Ltmp1471
	.quad	Ltmp1472
	.quad	Ltmp1474
	.quad	Ltmp1475
	.quad	0
	.quad	0
	.quad	Ltmp1471
	.quad	Ltmp1472
	.quad	Ltmp1474
	.quad	Ltmp1475
	.quad	0
	.quad	0
	.quad	Ltmp1478
	.quad	Ltmp1479
	.quad	Ltmp1481
	.quad	Ltmp1482
	.quad	0
	.quad	0
	.quad	Ltmp1478
	.quad	Ltmp1479
	.quad	Ltmp1481
	.quad	Ltmp1482
	.quad	0
	.quad	0
	.quad	Ltmp1491
	.quad	Ltmp1492
	.quad	Ltmp1494
	.quad	Ltmp1504
	.quad	0
	.quad	0
	.quad	Ltmp1491
	.quad	Ltmp1492
	.quad	Ltmp1494
	.quad	Ltmp1495
	.quad	0
	.quad	0
	.quad	Ltmp1491
	.quad	Ltmp1492
	.quad	Ltmp1494
	.quad	Ltmp1495
	.quad	0
	.quad	0
	.quad	Ltmp1498
	.quad	Ltmp1499
	.quad	Ltmp1501
	.quad	Ltmp1502
	.quad	0
	.quad	0
	.quad	Ltmp1498
	.quad	Ltmp1499
	.quad	Ltmp1501
	.quad	Ltmp1502
	.quad	0
	.quad	0
	.quad	Ltmp1511
	.quad	Ltmp1512
	.quad	Ltmp1514
	.quad	Ltmp1524
	.quad	0
	.quad	0
	.quad	Ltmp1511
	.quad	Ltmp1512
	.quad	Ltmp1514
	.quad	Ltmp1515
	.quad	0
	.quad	0
	.quad	Ltmp1511
	.quad	Ltmp1512
	.quad	Ltmp1514
	.quad	Ltmp1515
	.quad	0
	.quad	0
	.quad	Ltmp1518
	.quad	Ltmp1519
	.quad	Ltmp1521
	.quad	Ltmp1522
	.quad	0
	.quad	0
	.quad	Ltmp1518
	.quad	Ltmp1519
	.quad	Ltmp1521
	.quad	Ltmp1522
	.quad	0
	.quad	0
	.quad	Ltmp1531
	.quad	Ltmp1532
	.quad	Ltmp1534
	.quad	Ltmp1544
	.quad	0
	.quad	0
	.quad	Ltmp1531
	.quad	Ltmp1532
	.quad	Ltmp1534
	.quad	Ltmp1535
	.quad	0
	.quad	0
	.quad	Ltmp1531
	.quad	Ltmp1532
	.quad	Ltmp1534
	.quad	Ltmp1535
	.quad	0
	.quad	0
	.quad	Ltmp1538
	.quad	Ltmp1539
	.quad	Ltmp1541
	.quad	Ltmp1542
	.quad	0
	.quad	0
	.quad	Ltmp1538
	.quad	Ltmp1539
	.quad	Ltmp1541
	.quad	Ltmp1542
	.quad	0
	.quad	0
	.quad	Ltmp1551
	.quad	Ltmp1552
	.quad	Ltmp1554
	.quad	Ltmp1564
	.quad	0
	.quad	0
	.quad	Ltmp1551
	.quad	Ltmp1552
	.quad	Ltmp1554
	.quad	Ltmp1555
	.quad	0
	.quad	0
	.quad	Ltmp1551
	.quad	Ltmp1552
	.quad	Ltmp1554
	.quad	Ltmp1555
	.quad	0
	.quad	0
	.quad	Ltmp1558
	.quad	Ltmp1559
	.quad	Ltmp1561
	.quad	Ltmp1562
	.quad	0
	.quad	0
	.quad	Ltmp1558
	.quad	Ltmp1559
	.quad	Ltmp1561
	.quad	Ltmp1562
	.quad	0
	.quad	0
	.quad	Ltmp1571
	.quad	Ltmp1572
	.quad	Ltmp1574
	.quad	Ltmp1584
	.quad	0
	.quad	0
	.quad	Ltmp1571
	.quad	Ltmp1572
	.quad	Ltmp1574
	.quad	Ltmp1575
	.quad	0
	.quad	0
	.quad	Ltmp1571
	.quad	Ltmp1572
	.quad	Ltmp1574
	.quad	Ltmp1575
	.quad	0
	.quad	0
	.quad	Ltmp1578
	.quad	Ltmp1579
	.quad	Ltmp1581
	.quad	Ltmp1582
	.quad	0
	.quad	0
	.quad	Ltmp1578
	.quad	Ltmp1579
	.quad	Ltmp1581
	.quad	Ltmp1582
	.quad	0
	.quad	0
	.quad	Ltmp1591
	.quad	Ltmp1592
	.quad	Ltmp1594
	.quad	Ltmp1604
	.quad	0
	.quad	0
	.quad	Ltmp1591
	.quad	Ltmp1592
	.quad	Ltmp1594
	.quad	Ltmp1595
	.quad	0
	.quad	0
	.quad	Ltmp1591
	.quad	Ltmp1592
	.quad	Ltmp1594
	.quad	Ltmp1595
	.quad	0
	.quad	0
	.quad	Ltmp1598
	.quad	Ltmp1599
	.quad	Ltmp1601
	.quad	Ltmp1602
	.quad	0
	.quad	0
	.quad	Ltmp1598
	.quad	Ltmp1599
	.quad	Ltmp1601
	.quad	Ltmp1602
	.quad	0
	.quad	0
	.quad	Ltmp1611
	.quad	Ltmp1612
	.quad	Ltmp1614
	.quad	Ltmp1624
	.quad	0
	.quad	0
	.quad	Ltmp1611
	.quad	Ltmp1612
	.quad	Ltmp1614
	.quad	Ltmp1615
	.quad	0
	.quad	0
	.quad	Ltmp1611
	.quad	Ltmp1612
	.quad	Ltmp1614
	.quad	Ltmp1615
	.quad	0
	.quad	0
	.quad	Ltmp1618
	.quad	Ltmp1619
	.quad	Ltmp1621
	.quad	Ltmp1622
	.quad	0
	.quad	0
	.quad	Ltmp1618
	.quad	Ltmp1619
	.quad	Ltmp1621
	.quad	Ltmp1622
	.quad	0
	.quad	0
	.quad	Ltmp1631
	.quad	Ltmp1632
	.quad	Ltmp1634
	.quad	Ltmp1644
	.quad	0
	.quad	0
	.quad	Ltmp1631
	.quad	Ltmp1632
	.quad	Ltmp1634
	.quad	Ltmp1635
	.quad	0
	.quad	0
	.quad	Ltmp1631
	.quad	Ltmp1632
	.quad	Ltmp1634
	.quad	Ltmp1635
	.quad	0
	.quad	0
	.quad	Ltmp1638
	.quad	Ltmp1639
	.quad	Ltmp1641
	.quad	Ltmp1642
	.quad	0
	.quad	0
	.quad	Ltmp1638
	.quad	Ltmp1639
	.quad	Ltmp1641
	.quad	Ltmp1642
	.quad	0
	.quad	0
	.quad	Ltmp1653
	.quad	Ltmp1654
	.quad	Ltmp1656
	.quad	Ltmp1663
	.quad	0
	.quad	0
	.quad	Ltmp1653
	.quad	Ltmp1654
	.quad	Ltmp1656
	.quad	Ltmp1657
	.quad	0
	.quad	0
	.quad	Ltmp1653
	.quad	Ltmp1654
	.quad	Ltmp1656
	.quad	Ltmp1657
	.quad	0
	.quad	0
	.quad	Ltmp1659
	.quad	Ltmp1660
	.quad	Ltmp1662
	.quad	Ltmp1663
	.quad	0
	.quad	0
	.quad	Ltmp1659
	.quad	Ltmp1660
	.quad	Ltmp1662
	.quad	Ltmp1663
	.quad	0
	.quad	0
	.quad	Ltmp1672
	.quad	Ltmp1673
	.quad	Ltmp1675
	.quad	Ltmp1682
	.quad	0
	.quad	0
	.quad	Ltmp1672
	.quad	Ltmp1673
	.quad	Ltmp1675
	.quad	Ltmp1676
	.quad	0
	.quad	0
	.quad	Ltmp1672
	.quad	Ltmp1673
	.quad	Ltmp1675
	.quad	Ltmp1676
	.quad	0
	.quad	0
	.quad	Ltmp1678
	.quad	Ltmp1679
	.quad	Ltmp1681
	.quad	Ltmp1682
	.quad	0
	.quad	0
	.quad	Ltmp1678
	.quad	Ltmp1679
	.quad	Ltmp1681
	.quad	Ltmp1682
	.quad	0
	.quad	0
	.quad	Ltmp1700
	.quad	Ltmp1701
	.quad	Ltmp1703
	.quad	Ltmp1710
	.quad	0
	.quad	0
	.quad	Ltmp1700
	.quad	Ltmp1701
	.quad	Ltmp1703
	.quad	Ltmp1704
	.quad	0
	.quad	0
	.quad	Ltmp1700
	.quad	Ltmp1701
	.quad	Ltmp1703
	.quad	Ltmp1704
	.quad	0
	.quad	0
	.quad	Ltmp1706
	.quad	Ltmp1707
	.quad	Ltmp1709
	.quad	Ltmp1710
	.quad	0
	.quad	0
	.quad	Ltmp1706
	.quad	Ltmp1707
	.quad	Ltmp1709
	.quad	Ltmp1710
	.quad	0
	.quad	0
	.quad	Ltmp1719
	.quad	Ltmp1720
	.quad	Ltmp1722
	.quad	Ltmp1729
	.quad	0
	.quad	0
	.quad	Ltmp1719
	.quad	Ltmp1720
	.quad	Ltmp1722
	.quad	Ltmp1723
	.quad	0
	.quad	0
	.quad	Ltmp1719
	.quad	Ltmp1720
	.quad	Ltmp1722
	.quad	Ltmp1723
	.quad	0
	.quad	0
	.quad	Ltmp1725
	.quad	Ltmp1726
	.quad	Ltmp1728
	.quad	Ltmp1729
	.quad	0
	.quad	0
	.quad	Ltmp1725
	.quad	Ltmp1726
	.quad	Ltmp1728
	.quad	Ltmp1729
	.quad	0
	.quad	0
	.quad	Ltmp1736
	.quad	Ltmp1737
	.quad	Ltmp1739
	.quad	Ltmp1746
	.quad	0
	.quad	0
	.quad	Ltmp1736
	.quad	Ltmp1737
	.quad	Ltmp1739
	.quad	Ltmp1740
	.quad	0
	.quad	0
	.quad	Ltmp1736
	.quad	Ltmp1737
	.quad	Ltmp1739
	.quad	Ltmp1740
	.quad	0
	.quad	0
	.quad	Ltmp1742
	.quad	Ltmp1743
	.quad	Ltmp1745
	.quad	Ltmp1746
	.quad	0
	.quad	0
	.quad	Ltmp1742
	.quad	Ltmp1743
	.quad	Ltmp1745
	.quad	Ltmp1746
	.quad	0
	.quad	0
	.quad	Ltmp1753
	.quad	Ltmp1754
	.quad	Ltmp1756
	.quad	Ltmp1763
	.quad	0
	.quad	0
	.quad	Ltmp1753
	.quad	Ltmp1754
	.quad	Ltmp1756
	.quad	Ltmp1757
	.quad	0
	.quad	0
	.quad	Ltmp1753
	.quad	Ltmp1754
	.quad	Ltmp1756
	.quad	Ltmp1757
	.quad	0
	.quad	0
	.quad	Ltmp1759
	.quad	Ltmp1760
	.quad	Ltmp1762
	.quad	Ltmp1763
	.quad	0
	.quad	0
	.quad	Ltmp1759
	.quad	Ltmp1760
	.quad	Ltmp1762
	.quad	Ltmp1763
	.quad	0
	.quad	0
	.quad	Ltmp1770
	.quad	Ltmp1771
	.quad	Ltmp1773
	.quad	Ltmp1780
	.quad	0
	.quad	0
	.quad	Ltmp1770
	.quad	Ltmp1771
	.quad	Ltmp1773
	.quad	Ltmp1774
	.quad	0
	.quad	0
	.quad	Ltmp1770
	.quad	Ltmp1771
	.quad	Ltmp1773
	.quad	Ltmp1774
	.quad	0
	.quad	0
	.quad	Ltmp1776
	.quad	Ltmp1777
	.quad	Ltmp1779
	.quad	Ltmp1780
	.quad	0
	.quad	0
	.quad	Ltmp1776
	.quad	Ltmp1777
	.quad	Ltmp1779
	.quad	Ltmp1780
	.quad	0
	.quad	0
	.quad	Ltmp1787
	.quad	Ltmp1788
	.quad	Ltmp1790
	.quad	Ltmp1797
	.quad	0
	.quad	0
	.quad	Ltmp1787
	.quad	Ltmp1788
	.quad	Ltmp1790
	.quad	Ltmp1791
	.quad	0
	.quad	0
	.quad	Ltmp1787
	.quad	Ltmp1788
	.quad	Ltmp1790
	.quad	Ltmp1791
	.quad	0
	.quad	0
	.quad	Ltmp1793
	.quad	Ltmp1794
	.quad	Ltmp1796
	.quad	Ltmp1797
	.quad	0
	.quad	0
	.quad	Ltmp1793
	.quad	Ltmp1794
	.quad	Ltmp1796
	.quad	Ltmp1797
	.quad	0
	.quad	0
	.quad	Ltmp1806
	.quad	Ltmp1807
	.quad	Ltmp1809
	.quad	Ltmp1816
	.quad	0
	.quad	0
	.quad	Ltmp1806
	.quad	Ltmp1807
	.quad	Ltmp1809
	.quad	Ltmp1810
	.quad	0
	.quad	0
	.quad	Ltmp1806
	.quad	Ltmp1807
	.quad	Ltmp1809
	.quad	Ltmp1810
	.quad	0
	.quad	0
	.quad	Ltmp1812
	.quad	Ltmp1813
	.quad	Ltmp1815
	.quad	Ltmp1816
	.quad	0
	.quad	0
	.quad	Ltmp1812
	.quad	Ltmp1813
	.quad	Ltmp1815
	.quad	Ltmp1816
	.quad	0
	.quad	0
	.quad	Ltmp1825
	.quad	Ltmp1826
	.quad	Ltmp1828
	.quad	Ltmp1835
	.quad	0
	.quad	0
	.quad	Ltmp1825
	.quad	Ltmp1826
	.quad	Ltmp1828
	.quad	Ltmp1829
	.quad	0
	.quad	0
	.quad	Ltmp1825
	.quad	Ltmp1826
	.quad	Ltmp1828
	.quad	Ltmp1829
	.quad	0
	.quad	0
	.quad	Ltmp1831
	.quad	Ltmp1832
	.quad	Ltmp1834
	.quad	Ltmp1835
	.quad	0
	.quad	0
	.quad	Ltmp1831
	.quad	Ltmp1832
	.quad	Ltmp1834
	.quad	Ltmp1835
	.quad	0
	.quad	0
	.quad	Ltmp1853
	.quad	Ltmp1854
	.quad	Ltmp1856
	.quad	Ltmp1863
	.quad	0
	.quad	0
	.quad	Ltmp1853
	.quad	Ltmp1854
	.quad	Ltmp1856
	.quad	Ltmp1857
	.quad	0
	.quad	0
	.quad	Ltmp1853
	.quad	Ltmp1854
	.quad	Ltmp1856
	.quad	Ltmp1857
	.quad	0
	.quad	0
	.quad	Ltmp1859
	.quad	Ltmp1860
	.quad	Ltmp1862
	.quad	Ltmp1863
	.quad	0
	.quad	0
	.quad	Ltmp1859
	.quad	Ltmp1860
	.quad	Ltmp1862
	.quad	Ltmp1863
	.quad	0
	.quad	0
	.quad	Ltmp1872
	.quad	Ltmp1873
	.quad	Ltmp1875
	.quad	Ltmp1882
	.quad	0
	.quad	0
	.quad	Ltmp1872
	.quad	Ltmp1873
	.quad	Ltmp1875
	.quad	Ltmp1876
	.quad	0
	.quad	0
	.quad	Ltmp1872
	.quad	Ltmp1873
	.quad	Ltmp1875
	.quad	Ltmp1876
	.quad	0
	.quad	0
	.quad	Ltmp1878
	.quad	Ltmp1879
	.quad	Ltmp1881
	.quad	Ltmp1882
	.quad	0
	.quad	0
	.quad	Ltmp1878
	.quad	Ltmp1879
	.quad	Ltmp1881
	.quad	Ltmp1882
	.quad	0
	.quad	0
	.quad	Ltmp1889
	.quad	Ltmp1890
	.quad	Ltmp1892
	.quad	Ltmp1899
	.quad	0
	.quad	0
	.quad	Ltmp1889
	.quad	Ltmp1890
	.quad	Ltmp1892
	.quad	Ltmp1893
	.quad	0
	.quad	0
	.quad	Ltmp1889
	.quad	Ltmp1890
	.quad	Ltmp1892
	.quad	Ltmp1893
	.quad	0
	.quad	0
	.quad	Ltmp1895
	.quad	Ltmp1896
	.quad	Ltmp1898
	.quad	Ltmp1899
	.quad	0
	.quad	0
	.quad	Ltmp1895
	.quad	Ltmp1896
	.quad	Ltmp1898
	.quad	Ltmp1899
	.quad	0
	.quad	0
	.quad	Ltmp1906
	.quad	Ltmp1907
	.quad	Ltmp1909
	.quad	Ltmp1916
	.quad	0
	.quad	0
	.quad	Ltmp1906
	.quad	Ltmp1907
	.quad	Ltmp1909
	.quad	Ltmp1910
	.quad	0
	.quad	0
	.quad	Ltmp1906
	.quad	Ltmp1907
	.quad	Ltmp1909
	.quad	Ltmp1910
	.quad	0
	.quad	0
	.quad	Ltmp1912
	.quad	Ltmp1913
	.quad	Ltmp1915
	.quad	Ltmp1916
	.quad	0
	.quad	0
	.quad	Ltmp1912
	.quad	Ltmp1913
	.quad	Ltmp1915
	.quad	Ltmp1916
	.quad	0
	.quad	0
	.quad	Ltmp1923
	.quad	Ltmp1924
	.quad	Ltmp1926
	.quad	Ltmp1933
	.quad	0
	.quad	0
	.quad	Ltmp1923
	.quad	Ltmp1924
	.quad	Ltmp1926
	.quad	Ltmp1927
	.quad	0
	.quad	0
	.quad	Ltmp1923
	.quad	Ltmp1924
	.quad	Ltmp1926
	.quad	Ltmp1927
	.quad	0
	.quad	0
	.quad	Ltmp1929
	.quad	Ltmp1930
	.quad	Ltmp1932
	.quad	Ltmp1933
	.quad	0
	.quad	0
	.quad	Ltmp1929
	.quad	Ltmp1930
	.quad	Ltmp1932
	.quad	Ltmp1933
	.quad	0
	.quad	0
	.quad	Ltmp1940
	.quad	Ltmp1941
	.quad	Ltmp1943
	.quad	Ltmp1950
	.quad	0
	.quad	0
	.quad	Ltmp1940
	.quad	Ltmp1941
	.quad	Ltmp1943
	.quad	Ltmp1944
	.quad	0
	.quad	0
	.quad	Ltmp1940
	.quad	Ltmp1941
	.quad	Ltmp1943
	.quad	Ltmp1944
	.quad	0
	.quad	0
	.quad	Ltmp1946
	.quad	Ltmp1947
	.quad	Ltmp1949
	.quad	Ltmp1950
	.quad	0
	.quad	0
	.quad	Ltmp1946
	.quad	Ltmp1947
	.quad	Ltmp1949
	.quad	Ltmp1950
	.quad	0
	.quad	0
	.quad	Ltmp1960
	.quad	Ltmp1961
	.quad	Ltmp1963
	.quad	Ltmp1964
	.quad	0
	.quad	0
	.quad	Ltmp1967
	.quad	Ltmp1968
	.quad	Ltmp1970
	.quad	Ltmp1972
	.quad	0
	.quad	0
	.quad	Ltmp1981
	.quad	Ltmp1982
	.quad	Ltmp1984
	.quad	Ltmp1991
	.quad	0
	.quad	0
	.quad	Ltmp1981
	.quad	Ltmp1982
	.quad	Ltmp1984
	.quad	Ltmp1985
	.quad	0
	.quad	0
	.quad	Ltmp1981
	.quad	Ltmp1982
	.quad	Ltmp1984
	.quad	Ltmp1985
	.quad	0
	.quad	0
	.quad	Ltmp1987
	.quad	Ltmp1988
	.quad	Ltmp1990
	.quad	Ltmp1991
	.quad	0
	.quad	0
	.quad	Ltmp1987
	.quad	Ltmp1988
	.quad	Ltmp1990
	.quad	Ltmp1991
	.quad	0
	.quad	0
	.quad	Ltmp2000
	.quad	Ltmp2001
	.quad	Ltmp2003
	.quad	Ltmp2010
	.quad	0
	.quad	0
	.quad	Ltmp2000
	.quad	Ltmp2001
	.quad	Ltmp2003
	.quad	Ltmp2004
	.quad	0
	.quad	0
	.quad	Ltmp2000
	.quad	Ltmp2001
	.quad	Ltmp2003
	.quad	Ltmp2004
	.quad	0
	.quad	0
	.quad	Ltmp2006
	.quad	Ltmp2007
	.quad	Ltmp2009
	.quad	Ltmp2010
	.quad	0
	.quad	0
	.quad	Ltmp2006
	.quad	Ltmp2007
	.quad	Ltmp2009
	.quad	Ltmp2010
	.quad	0
	.quad	0
	.quad	Ltmp2019
	.quad	Ltmp2020
	.quad	Ltmp2022
	.quad	Ltmp2029
	.quad	0
	.quad	0
	.quad	Ltmp2019
	.quad	Ltmp2020
	.quad	Ltmp2022
	.quad	Ltmp2023
	.quad	0
	.quad	0
	.quad	Ltmp2019
	.quad	Ltmp2020
	.quad	Ltmp2022
	.quad	Ltmp2023
	.quad	0
	.quad	0
	.quad	Ltmp2025
	.quad	Ltmp2026
	.quad	Ltmp2028
	.quad	Ltmp2029
	.quad	0
	.quad	0
	.quad	Ltmp2025
	.quad	Ltmp2026
	.quad	Ltmp2028
	.quad	Ltmp2029
	.quad	0
	.quad	0
	.quad	Ltmp2038
	.quad	Ltmp2039
	.quad	Ltmp2041
	.quad	Ltmp2048
	.quad	0
	.quad	0
	.quad	Ltmp2038
	.quad	Ltmp2039
	.quad	Ltmp2041
	.quad	Ltmp2042
	.quad	0
	.quad	0
	.quad	Ltmp2038
	.quad	Ltmp2039
	.quad	Ltmp2041
	.quad	Ltmp2042
	.quad	0
	.quad	0
	.quad	Ltmp2044
	.quad	Ltmp2045
	.quad	Ltmp2047
	.quad	Ltmp2048
	.quad	0
	.quad	0
	.quad	Ltmp2044
	.quad	Ltmp2045
	.quad	Ltmp2047
	.quad	Ltmp2048
	.quad	0
	.quad	0
	.quad	Ltmp2055
	.quad	Ltmp2056
	.quad	Ltmp2058
	.quad	Ltmp2065
	.quad	0
	.quad	0
	.quad	Ltmp2055
	.quad	Ltmp2056
	.quad	Ltmp2058
	.quad	Ltmp2059
	.quad	0
	.quad	0
	.quad	Ltmp2055
	.quad	Ltmp2056
	.quad	Ltmp2058
	.quad	Ltmp2059
	.quad	0
	.quad	0
	.quad	Ltmp2061
	.quad	Ltmp2062
	.quad	Ltmp2064
	.quad	Ltmp2065
	.quad	0
	.quad	0
	.quad	Ltmp2061
	.quad	Ltmp2062
	.quad	Ltmp2064
	.quad	Ltmp2065
	.quad	0
	.quad	0
	.quad	Ltmp2072
	.quad	Ltmp2073
	.quad	Ltmp2075
	.quad	Ltmp2082
	.quad	0
	.quad	0
	.quad	Ltmp2072
	.quad	Ltmp2073
	.quad	Ltmp2075
	.quad	Ltmp2076
	.quad	0
	.quad	0
	.quad	Ltmp2072
	.quad	Ltmp2073
	.quad	Ltmp2075
	.quad	Ltmp2076
	.quad	0
	.quad	0
	.quad	Ltmp2078
	.quad	Ltmp2079
	.quad	Ltmp2081
	.quad	Ltmp2082
	.quad	0
	.quad	0
	.quad	Ltmp2078
	.quad	Ltmp2079
	.quad	Ltmp2081
	.quad	Ltmp2082
	.quad	0
	.quad	0
	.quad	Ltmp2089
	.quad	Ltmp2090
	.quad	Ltmp2092
	.quad	Ltmp2099
	.quad	0
	.quad	0
	.quad	Ltmp2089
	.quad	Ltmp2090
	.quad	Ltmp2092
	.quad	Ltmp2093
	.quad	0
	.quad	0
	.quad	Ltmp2089
	.quad	Ltmp2090
	.quad	Ltmp2092
	.quad	Ltmp2093
	.quad	0
	.quad	0
	.quad	Ltmp2095
	.quad	Ltmp2096
	.quad	Ltmp2098
	.quad	Ltmp2099
	.quad	0
	.quad	0
	.quad	Ltmp2095
	.quad	Ltmp2096
	.quad	Ltmp2098
	.quad	Ltmp2099
	.quad	0
	.quad	0
	.quad	Ltmp2106
	.quad	Ltmp2107
	.quad	Ltmp2109
	.quad	Ltmp2116
	.quad	0
	.quad	0
	.quad	Ltmp2106
	.quad	Ltmp2107
	.quad	Ltmp2109
	.quad	Ltmp2110
	.quad	0
	.quad	0
	.quad	Ltmp2106
	.quad	Ltmp2107
	.quad	Ltmp2109
	.quad	Ltmp2110
	.quad	0
	.quad	0
	.quad	Ltmp2112
	.quad	Ltmp2113
	.quad	Ltmp2115
	.quad	Ltmp2116
	.quad	0
	.quad	0
	.quad	Ltmp2112
	.quad	Ltmp2113
	.quad	Ltmp2115
	.quad	Ltmp2116
	.quad	0
	.quad	0
	.quad	Ltmp2126
	.quad	Ltmp2127
	.quad	Ltmp2129
	.quad	Ltmp2130
	.quad	0
	.quad	0
	.quad	Ltmp2133
	.quad	Ltmp2134
	.quad	Ltmp2136
	.quad	Ltmp2138
	.quad	0
	.quad	0
	.quad	Ltmp2147
	.quad	Ltmp2148
	.quad	Ltmp2150
	.quad	Ltmp2157
	.quad	0
	.quad	0
	.quad	Ltmp2147
	.quad	Ltmp2148
	.quad	Ltmp2150
	.quad	Ltmp2151
	.quad	0
	.quad	0
	.quad	Ltmp2147
	.quad	Ltmp2148
	.quad	Ltmp2150
	.quad	Ltmp2151
	.quad	0
	.quad	0
	.quad	Ltmp2153
	.quad	Ltmp2154
	.quad	Ltmp2156
	.quad	Ltmp2157
	.quad	0
	.quad	0
	.quad	Ltmp2153
	.quad	Ltmp2154
	.quad	Ltmp2156
	.quad	Ltmp2157
	.quad	0
	.quad	0
	.quad	Ltmp2166
	.quad	Ltmp2167
	.quad	Ltmp2169
	.quad	Ltmp2176
	.quad	0
	.quad	0
	.quad	Ltmp2166
	.quad	Ltmp2167
	.quad	Ltmp2169
	.quad	Ltmp2170
	.quad	0
	.quad	0
	.quad	Ltmp2166
	.quad	Ltmp2167
	.quad	Ltmp2169
	.quad	Ltmp2170
	.quad	0
	.quad	0
	.quad	Ltmp2172
	.quad	Ltmp2173
	.quad	Ltmp2175
	.quad	Ltmp2176
	.quad	0
	.quad	0
	.quad	Ltmp2172
	.quad	Ltmp2173
	.quad	Ltmp2175
	.quad	Ltmp2176
	.quad	0
	.quad	0
	.quad	Ltmp2185
	.quad	Ltmp2186
	.quad	Ltmp2188
	.quad	Ltmp2195
	.quad	0
	.quad	0
	.quad	Ltmp2185
	.quad	Ltmp2186
	.quad	Ltmp2188
	.quad	Ltmp2189
	.quad	0
	.quad	0
	.quad	Ltmp2185
	.quad	Ltmp2186
	.quad	Ltmp2188
	.quad	Ltmp2189
	.quad	0
	.quad	0
	.quad	Ltmp2191
	.quad	Ltmp2192
	.quad	Ltmp2194
	.quad	Ltmp2195
	.quad	0
	.quad	0
	.quad	Ltmp2191
	.quad	Ltmp2192
	.quad	Ltmp2194
	.quad	Ltmp2195
	.quad	0
	.quad	0
	.quad	Ltmp2204
	.quad	Ltmp2205
	.quad	Ltmp2207
	.quad	Ltmp2214
	.quad	0
	.quad	0
	.quad	Ltmp2204
	.quad	Ltmp2205
	.quad	Ltmp2207
	.quad	Ltmp2208
	.quad	0
	.quad	0
	.quad	Ltmp2204
	.quad	Ltmp2205
	.quad	Ltmp2207
	.quad	Ltmp2208
	.quad	0
	.quad	0
	.quad	Ltmp2210
	.quad	Ltmp2211
	.quad	Ltmp2213
	.quad	Ltmp2214
	.quad	0
	.quad	0
	.quad	Ltmp2210
	.quad	Ltmp2211
	.quad	Ltmp2213
	.quad	Ltmp2214
	.quad	0
	.quad	0
	.quad	Ltmp2221
	.quad	Ltmp2222
	.quad	Ltmp2224
	.quad	Ltmp2231
	.quad	0
	.quad	0
	.quad	Ltmp2221
	.quad	Ltmp2222
	.quad	Ltmp2224
	.quad	Ltmp2225
	.quad	0
	.quad	0
	.quad	Ltmp2221
	.quad	Ltmp2222
	.quad	Ltmp2224
	.quad	Ltmp2225
	.quad	0
	.quad	0
	.quad	Ltmp2227
	.quad	Ltmp2228
	.quad	Ltmp2230
	.quad	Ltmp2231
	.quad	0
	.quad	0
	.quad	Ltmp2227
	.quad	Ltmp2228
	.quad	Ltmp2230
	.quad	Ltmp2231
	.quad	0
	.quad	0
	.quad	Ltmp2238
	.quad	Ltmp2239
	.quad	Ltmp2241
	.quad	Ltmp2248
	.quad	0
	.quad	0
	.quad	Ltmp2238
	.quad	Ltmp2239
	.quad	Ltmp2241
	.quad	Ltmp2242
	.quad	0
	.quad	0
	.quad	Ltmp2238
	.quad	Ltmp2239
	.quad	Ltmp2241
	.quad	Ltmp2242
	.quad	0
	.quad	0
	.quad	Ltmp2244
	.quad	Ltmp2245
	.quad	Ltmp2247
	.quad	Ltmp2248
	.quad	0
	.quad	0
	.quad	Ltmp2244
	.quad	Ltmp2245
	.quad	Ltmp2247
	.quad	Ltmp2248
	.quad	0
	.quad	0
	.quad	Ltmp2255
	.quad	Ltmp2256
	.quad	Ltmp2258
	.quad	Ltmp2265
	.quad	0
	.quad	0
	.quad	Ltmp2255
	.quad	Ltmp2256
	.quad	Ltmp2258
	.quad	Ltmp2259
	.quad	0
	.quad	0
	.quad	Ltmp2255
	.quad	Ltmp2256
	.quad	Ltmp2258
	.quad	Ltmp2259
	.quad	0
	.quad	0
	.quad	Ltmp2261
	.quad	Ltmp2262
	.quad	Ltmp2264
	.quad	Ltmp2265
	.quad	0
	.quad	0
	.quad	Ltmp2261
	.quad	Ltmp2262
	.quad	Ltmp2264
	.quad	Ltmp2265
	.quad	0
	.quad	0
	.quad	Ltmp2272
	.quad	Ltmp2273
	.quad	Ltmp2275
	.quad	Ltmp2282
	.quad	0
	.quad	0
	.quad	Ltmp2272
	.quad	Ltmp2273
	.quad	Ltmp2275
	.quad	Ltmp2276
	.quad	0
	.quad	0
	.quad	Ltmp2272
	.quad	Ltmp2273
	.quad	Ltmp2275
	.quad	Ltmp2276
	.quad	0
	.quad	0
	.quad	Ltmp2278
	.quad	Ltmp2279
	.quad	Ltmp2281
	.quad	Ltmp2282
	.quad	0
	.quad	0
	.quad	Ltmp2278
	.quad	Ltmp2279
	.quad	Ltmp2281
	.quad	Ltmp2282
	.quad	0
	.quad	0
	.quad	Ltmp2289
	.quad	Ltmp2290
	.quad	Ltmp2292
	.quad	Ltmp2299
	.quad	0
	.quad	0
	.quad	Ltmp2289
	.quad	Ltmp2290
	.quad	Ltmp2292
	.quad	Ltmp2293
	.quad	0
	.quad	0
	.quad	Ltmp2289
	.quad	Ltmp2290
	.quad	Ltmp2292
	.quad	Ltmp2293
	.quad	0
	.quad	0
	.quad	Ltmp2295
	.quad	Ltmp2296
	.quad	Ltmp2298
	.quad	Ltmp2299
	.quad	0
	.quad	0
	.quad	Ltmp2295
	.quad	Ltmp2296
	.quad	Ltmp2298
	.quad	Ltmp2299
	.quad	0
	.quad	0
	.quad	Ltmp2306
	.quad	Ltmp2307
	.quad	Ltmp2309
	.quad	Ltmp2316
	.quad	0
	.quad	0
	.quad	Ltmp2306
	.quad	Ltmp2307
	.quad	Ltmp2309
	.quad	Ltmp2310
	.quad	0
	.quad	0
	.quad	Ltmp2306
	.quad	Ltmp2307
	.quad	Ltmp2309
	.quad	Ltmp2310
	.quad	0
	.quad	0
	.quad	Ltmp2312
	.quad	Ltmp2313
	.quad	Ltmp2315
	.quad	Ltmp2316
	.quad	0
	.quad	0
	.quad	Ltmp2312
	.quad	Ltmp2313
	.quad	Ltmp2315
	.quad	Ltmp2316
	.quad	0
	.quad	0
	.quad	Ltmp2323
	.quad	Ltmp2324
	.quad	Ltmp2326
	.quad	Ltmp2333
	.quad	0
	.quad	0
	.quad	Ltmp2323
	.quad	Ltmp2324
	.quad	Ltmp2326
	.quad	Ltmp2327
	.quad	0
	.quad	0
	.quad	Ltmp2323
	.quad	Ltmp2324
	.quad	Ltmp2326
	.quad	Ltmp2327
	.quad	0
	.quad	0
	.quad	Ltmp2329
	.quad	Ltmp2330
	.quad	Ltmp2332
	.quad	Ltmp2333
	.quad	0
	.quad	0
	.quad	Ltmp2329
	.quad	Ltmp2330
	.quad	Ltmp2332
	.quad	Ltmp2333
	.quad	0
	.quad	0
	.quad	Ltmp2340
	.quad	Ltmp2341
	.quad	Ltmp2343
	.quad	Ltmp2350
	.quad	0
	.quad	0
	.quad	Ltmp2340
	.quad	Ltmp2341
	.quad	Ltmp2343
	.quad	Ltmp2344
	.quad	0
	.quad	0
	.quad	Ltmp2340
	.quad	Ltmp2341
	.quad	Ltmp2343
	.quad	Ltmp2344
	.quad	0
	.quad	0
	.quad	Ltmp2346
	.quad	Ltmp2347
	.quad	Ltmp2349
	.quad	Ltmp2350
	.quad	0
	.quad	0
	.quad	Ltmp2346
	.quad	Ltmp2347
	.quad	Ltmp2349
	.quad	Ltmp2350
	.quad	0
	.quad	0
	.quad	Ltmp2357
	.quad	Ltmp2358
	.quad	Ltmp2360
	.quad	Ltmp2367
	.quad	0
	.quad	0
	.quad	Ltmp2357
	.quad	Ltmp2358
	.quad	Ltmp2360
	.quad	Ltmp2361
	.quad	0
	.quad	0
	.quad	Ltmp2357
	.quad	Ltmp2358
	.quad	Ltmp2360
	.quad	Ltmp2361
	.quad	0
	.quad	0
	.quad	Ltmp2363
	.quad	Ltmp2364
	.quad	Ltmp2366
	.quad	Ltmp2367
	.quad	0
	.quad	0
	.quad	Ltmp2363
	.quad	Ltmp2364
	.quad	Ltmp2366
	.quad	Ltmp2367
	.quad	0
	.quad	0
	.quad	Ltmp2374
	.quad	Ltmp2375
	.quad	Ltmp2377
	.quad	Ltmp2384
	.quad	0
	.quad	0
	.quad	Ltmp2374
	.quad	Ltmp2375
	.quad	Ltmp2377
	.quad	Ltmp2378
	.quad	0
	.quad	0
	.quad	Ltmp2374
	.quad	Ltmp2375
	.quad	Ltmp2377
	.quad	Ltmp2378
	.quad	0
	.quad	0
	.quad	Ltmp2380
	.quad	Ltmp2381
	.quad	Ltmp2383
	.quad	Ltmp2384
	.quad	0
	.quad	0
	.quad	Ltmp2380
	.quad	Ltmp2381
	.quad	Ltmp2383
	.quad	Ltmp2384
	.quad	0
	.quad	0
	.quad	Ltmp2391
	.quad	Ltmp2392
	.quad	Ltmp2394
	.quad	Ltmp2401
	.quad	0
	.quad	0
	.quad	Ltmp2391
	.quad	Ltmp2392
	.quad	Ltmp2394
	.quad	Ltmp2395
	.quad	0
	.quad	0
	.quad	Ltmp2391
	.quad	Ltmp2392
	.quad	Ltmp2394
	.quad	Ltmp2395
	.quad	0
	.quad	0
	.quad	Ltmp2397
	.quad	Ltmp2398
	.quad	Ltmp2400
	.quad	Ltmp2401
	.quad	0
	.quad	0
	.quad	Ltmp2397
	.quad	Ltmp2398
	.quad	Ltmp2400
	.quad	Ltmp2401
	.quad	0
	.quad	0
	.quad	Ltmp2408
	.quad	Ltmp2409
	.quad	Ltmp2411
	.quad	Ltmp2418
	.quad	0
	.quad	0
	.quad	Ltmp2408
	.quad	Ltmp2409
	.quad	Ltmp2411
	.quad	Ltmp2412
	.quad	0
	.quad	0
	.quad	Ltmp2408
	.quad	Ltmp2409
	.quad	Ltmp2411
	.quad	Ltmp2412
	.quad	0
	.quad	0
	.quad	Ltmp2414
	.quad	Ltmp2415
	.quad	Ltmp2417
	.quad	Ltmp2418
	.quad	0
	.quad	0
	.quad	Ltmp2414
	.quad	Ltmp2415
	.quad	Ltmp2417
	.quad	Ltmp2418
	.quad	0
	.quad	0
	.quad	Ltmp2425
	.quad	Ltmp2426
	.quad	Ltmp2428
	.quad	Ltmp2435
	.quad	0
	.quad	0
	.quad	Ltmp2425
	.quad	Ltmp2426
	.quad	Ltmp2428
	.quad	Ltmp2429
	.quad	0
	.quad	0
	.quad	Ltmp2425
	.quad	Ltmp2426
	.quad	Ltmp2428
	.quad	Ltmp2429
	.quad	0
	.quad	0
	.quad	Ltmp2431
	.quad	Ltmp2432
	.quad	Ltmp2434
	.quad	Ltmp2435
	.quad	0
	.quad	0
	.quad	Ltmp2431
	.quad	Ltmp2432
	.quad	Ltmp2434
	.quad	Ltmp2435
	.quad	0
	.quad	0
	.quad	Ltmp2442
	.quad	Ltmp2443
	.quad	Ltmp2445
	.quad	Ltmp2452
	.quad	0
	.quad	0
	.quad	Ltmp2442
	.quad	Ltmp2443
	.quad	Ltmp2445
	.quad	Ltmp2446
	.quad	0
	.quad	0
	.quad	Ltmp2442
	.quad	Ltmp2443
	.quad	Ltmp2445
	.quad	Ltmp2446
	.quad	0
	.quad	0
	.quad	Ltmp2448
	.quad	Ltmp2449
	.quad	Ltmp2451
	.quad	Ltmp2452
	.quad	0
	.quad	0
	.quad	Ltmp2448
	.quad	Ltmp2449
	.quad	Ltmp2451
	.quad	Ltmp2452
	.quad	0
	.quad	0
	.quad	Ltmp2459
	.quad	Ltmp2460
	.quad	Ltmp2462
	.quad	Ltmp2469
	.quad	0
	.quad	0
	.quad	Ltmp2459
	.quad	Ltmp2460
	.quad	Ltmp2462
	.quad	Ltmp2463
	.quad	0
	.quad	0
	.quad	Ltmp2459
	.quad	Ltmp2460
	.quad	Ltmp2462
	.quad	Ltmp2463
	.quad	0
	.quad	0
	.quad	Ltmp2465
	.quad	Ltmp2466
	.quad	Ltmp2468
	.quad	Ltmp2469
	.quad	0
	.quad	0
	.quad	Ltmp2465
	.quad	Ltmp2466
	.quad	Ltmp2468
	.quad	Ltmp2469
	.quad	0
	.quad	0
	.quad	Ltmp2476
	.quad	Ltmp2477
	.quad	Ltmp2479
	.quad	Ltmp2486
	.quad	0
	.quad	0
	.quad	Ltmp2476
	.quad	Ltmp2477
	.quad	Ltmp2479
	.quad	Ltmp2480
	.quad	0
	.quad	0
	.quad	Ltmp2476
	.quad	Ltmp2477
	.quad	Ltmp2479
	.quad	Ltmp2480
	.quad	0
	.quad	0
	.quad	Ltmp2482
	.quad	Ltmp2483
	.quad	Ltmp2485
	.quad	Ltmp2486
	.quad	0
	.quad	0
	.quad	Ltmp2482
	.quad	Ltmp2483
	.quad	Ltmp2485
	.quad	Ltmp2486
	.quad	0
	.quad	0
	.quad	Ltmp2493
	.quad	Ltmp2494
	.quad	Ltmp2496
	.quad	Ltmp2503
	.quad	0
	.quad	0
	.quad	Ltmp2493
	.quad	Ltmp2494
	.quad	Ltmp2496
	.quad	Ltmp2497
	.quad	0
	.quad	0
	.quad	Ltmp2493
	.quad	Ltmp2494
	.quad	Ltmp2496
	.quad	Ltmp2497
	.quad	0
	.quad	0
	.quad	Ltmp2499
	.quad	Ltmp2500
	.quad	Ltmp2502
	.quad	Ltmp2503
	.quad	0
	.quad	0
	.quad	Ltmp2499
	.quad	Ltmp2500
	.quad	Ltmp2502
	.quad	Ltmp2503
	.quad	0
	.quad	0
	.quad	Ltmp2510
	.quad	Ltmp2511
	.quad	Ltmp2513
	.quad	Ltmp2520
	.quad	0
	.quad	0
	.quad	Ltmp2510
	.quad	Ltmp2511
	.quad	Ltmp2513
	.quad	Ltmp2514
	.quad	0
	.quad	0
	.quad	Ltmp2510
	.quad	Ltmp2511
	.quad	Ltmp2513
	.quad	Ltmp2514
	.quad	0
	.quad	0
	.quad	Ltmp2516
	.quad	Ltmp2517
	.quad	Ltmp2519
	.quad	Ltmp2520
	.quad	0
	.quad	0
	.quad	Ltmp2516
	.quad	Ltmp2517
	.quad	Ltmp2519
	.quad	Ltmp2520
	.quad	0
	.quad	0
	.quad	Ltmp2527
	.quad	Ltmp2528
	.quad	Ltmp2530
	.quad	Ltmp2537
	.quad	0
	.quad	0
	.quad	Ltmp2527
	.quad	Ltmp2528
	.quad	Ltmp2530
	.quad	Ltmp2531
	.quad	0
	.quad	0
	.quad	Ltmp2527
	.quad	Ltmp2528
	.quad	Ltmp2530
	.quad	Ltmp2531
	.quad	0
	.quad	0
	.quad	Ltmp2533
	.quad	Ltmp2534
	.quad	Ltmp2536
	.quad	Ltmp2537
	.quad	0
	.quad	0
	.quad	Ltmp2533
	.quad	Ltmp2534
	.quad	Ltmp2536
	.quad	Ltmp2537
	.quad	0
	.quad	0
	.quad	Ltmp2544
	.quad	Ltmp2545
	.quad	Ltmp2547
	.quad	Ltmp2554
	.quad	0
	.quad	0
	.quad	Ltmp2544
	.quad	Ltmp2545
	.quad	Ltmp2547
	.quad	Ltmp2548
	.quad	0
	.quad	0
	.quad	Ltmp2544
	.quad	Ltmp2545
	.quad	Ltmp2547
	.quad	Ltmp2548
	.quad	0
	.quad	0
	.quad	Ltmp2550
	.quad	Ltmp2551
	.quad	Ltmp2553
	.quad	Ltmp2554
	.quad	0
	.quad	0
	.quad	Ltmp2550
	.quad	Ltmp2551
	.quad	Ltmp2553
	.quad	Ltmp2554
	.quad	0
	.quad	0
	.quad	Ltmp2561
	.quad	Ltmp2562
	.quad	Ltmp2564
	.quad	Ltmp2571
	.quad	0
	.quad	0
	.quad	Ltmp2561
	.quad	Ltmp2562
	.quad	Ltmp2564
	.quad	Ltmp2565
	.quad	0
	.quad	0
	.quad	Ltmp2561
	.quad	Ltmp2562
	.quad	Ltmp2564
	.quad	Ltmp2565
	.quad	0
	.quad	0
	.quad	Ltmp2567
	.quad	Ltmp2568
	.quad	Ltmp2570
	.quad	Ltmp2571
	.quad	0
	.quad	0
	.quad	Ltmp2567
	.quad	Ltmp2568
	.quad	Ltmp2570
	.quad	Ltmp2571
	.quad	0
	.quad	0
	.quad	Ltmp2578
	.quad	Ltmp2579
	.quad	Ltmp2581
	.quad	Ltmp2588
	.quad	0
	.quad	0
	.quad	Ltmp2578
	.quad	Ltmp2579
	.quad	Ltmp2581
	.quad	Ltmp2582
	.quad	0
	.quad	0
	.quad	Ltmp2578
	.quad	Ltmp2579
	.quad	Ltmp2581
	.quad	Ltmp2582
	.quad	0
	.quad	0
	.quad	Ltmp2584
	.quad	Ltmp2585
	.quad	Ltmp2587
	.quad	Ltmp2588
	.quad	0
	.quad	0
	.quad	Ltmp2584
	.quad	Ltmp2585
	.quad	Ltmp2587
	.quad	Ltmp2588
	.quad	0
	.quad	0
	.section	__DWARF,__debug_macinfo,regular,debug
	.section	__DWARF,__debug_inlined,regular,debug
Lset1831 = Ldebug_inlined_end1-Ldebug_inlined_begin1
	.long	Lset1831
Ldebug_inlined_begin1:
	.short	2
	.byte	8
Ldebug_inlined_end1:

.subsections_via_symbols
