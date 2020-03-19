
ifndef LIBFFI_ASM
define LIBFFI_ASM

option casemap:none
.x64P
.xmm
option win64:7             ; 11-15 for RSP and 1-7 for RBP.
option frame:auto
option stackbase:rbp        ; RSP or RBP are supported options for the stackbase.
option literals:on
option vtable:on

;#define LIBFFI_ASM
;#include <fficonfig.h>
;#include <ffi.h>
;#include <ffi_cfi.h>
;#include "asmnames.h"

;#if defined(HAVE_AS_CFI_PSEUDO_OP)
        ;.cfi_sections   .debug_frame
;#endif

;#ifdef X86_WIN64
;#define ...) __VA_ARGS__
;#define arg0	rcx
;#define arg1	rdx
;#define arg2	r8
;#define arg3	r9
;#else
;#define ...)
;#define arg0	rdi
;#define arg1	rsi
;#define arg2	rdx
;#define arg3	rcx
;#endif

arg0  textequ  < rcx >
arg1  textequ  < rdx >
arg2  textequ  < r8 >
arg3  textequ  < r9 >

;/* This macro allows the safe creation of jump tables without an
;   actual table.  The entry points into the table are all 8 bytes.
;   The use of ORG asserts that we're at the correct location.  */
;/* ??? The clang assembler doesn't handle .org with symbolic expressions.  */
;#if defined(__clang__) || defined(__APPLE__) || (defined (__sun__) && defined(__svr4__))
;# define E(BASE, X)	align 8
;#else
;# define E(BASE, X)	align 8; ORG BASE + X * 8
;#endif

EORG macro BASE, XN
    align 8
    org BASE + XN * 8 
endm

;/* If these change, update src/mips/ffitarget.h. */
FFI_TYPE_VOID       equ 0    
FFI_TYPE_INT        equ 1
FFI_TYPE_FLOAT      equ 2
FFI_TYPE_DOUBLE     equ 3
FFI_TYPE_LONGDOUBLE equ 4
FFI_TYPE_UINT8      equ 5
FFI_TYPE_SINT8      equ 6
FFI_TYPE_UINT16     equ 7
FFI_TYPE_SINT16     equ 8
FFI_TYPE_UINT32     equ 9
FFI_TYPE_SINT32     equ 10
FFI_TYPE_UINT64     equ 11
FFI_TYPE_SINT64     equ 12
FFI_TYPE_STRUCT     equ 13
FFI_TYPE_POINTER    equ 14
FFI_TYPE_COMPLEX    equ 15

;/* This should always refer to the last type code (for sanity checks).  */
FFI_TYPE_LAST       equ FFI_TYPE_COMPLEX

FFI_TYPE_SMALL_STRUCT_1B equ 16
FFI_TYPE_SMALL_STRUCT_2B equ 17
FFI_TYPE_SMALL_STRUCT_4B equ 18
FFI_TYPE_MS_STRUCT       equ 19

FFI_TRAMPOLINE_SIZE equ 32

;/* 32 bytes of outgoing register stack space, 8 bytes of alignment,
;   16 bytes of result, 32 bytes of xmm registers.  */
ffi_clo_FS      equ 88
ffi_clo_OFF_R   equ 40
ffi_clo_OFF_X   equ 56

    .data?

    .data

    .const

        align size_t_size
        ffi_call_win64_tab isize_t offset ffi_call_win64_tab_0,  offset ffi_call_win64_tab_1,  offset ffi_call_win64_tab_2,  offset ffi_call_win64_tab_3,  offset ffi_call_win64_tab_4,  offset ffi_call_win64_tab_5, \
                                   offset ffi_call_win64_tab_6,  offset ffi_call_win64_tab_7,  offset ffi_call_win64_tab_8,  offset ffi_call_win64_tab_9,  offset ffi_call_win64_tab_10, offset ffi_call_win64_tab_11, \
                                   offset ffi_call_win64_tab_12, offset ffi_call_win64_tab_13, offset ffi_call_win64_tab_14, offset ffi_call_win64_tab_15, offset ffi_call_win64_tab_16, offset ffi_call_win64_tab_17, \
                                   offset ffi_call_win64_tab_18

    .code

    alignfieldproc size_t_size

    extern c abort:near
    extern c ffi_closure_win64_inner:near

;/* ffi_call_win64 (void *stack, struct win64_call_frame *frame, void *r10)

;   Bit o trickiness here -- FRAME is the base of the stack frame
;   for this function.  This has been allocated by ffi_call.  We also
;   deallocate some of the stack that has been alloca'd.  */

    public c ffi_call_win64 

    ; .safesh ffi_call_win64)
ffi_call_win64 proc c frame
    ;/* Set up the local stack frame and install it in rbp/rsp.  */
    mov         rax,            [rsp] ; 	movq	(%rsp), %rax
    mov         [arg1],          rbp ; movq	%rbp, (arg1)
    mov         [arg1 + 8],      rax;	movq	%rax, 8(arg1)
    mov         rbp,             arg1; movq	arg1, %rbp
    .pushreg    rbp
    .setframe   rbp,             0
    .endprolog
    mov         rsp,             arg0 ;	movq	arg0, %rsp

    mov         r10,             arg2 ; movq	arg2, %r10

    ;/* Load all slots into both general and xmm registers.  */
    mov         rcx,            [rsp] ;	movq	(%rsp), %rcx
    movsd       xmm0, qword ptr [rsp] ; movsd	(%rsp), %xmm0
    mov         rdx,            [rsp + 8] ;movq	8(%rsp), %rdx
    movsd       xmm1, qword ptr [rsp + 8];	movsd	8(%rsp), %xmm1
    mov         r8,             [rsp + 16] ; movq	16(%rsp), %r8
    movsd       xmm2, qword ptr [rsp + 16] ; movsd	16(%rsp), %xmm2
    mov         r9,             [rsp + 24] ; movq	24(%rsp), %r9
    movsd       xmm3, qword ptr [rsp + 24] ;movsd	24(%rsp), %xmm3

    call    qword ptr [rbp + 16] ; call	*16(%rbp)

    mov         ecx,            [rbp + 24] ; movl	24(%rbp), %ecx
    mov         r8,             [rbp + 32] ; movq	32(%rbp), %r8
    lea         r10,  qword ptr [ffi_call_win64_tab] ; leaq	0f(%rip), %r10
    cmp         ecx,             FFI_TYPE_SMALL_STRUCT_4B ; cmpl	$FFI_TYPE_SMALL_STRUCT_4B, %ecx
    lea         r10,  qword ptr [r10 + rcx * size_t_size] ; leaq	(%r10, %rcx, 8), %r10
    ja          L99 ; ja	99f
    jmp         r10 ; jmp	*%r10

;/* Below, we're space constrained most of the time.  Thus we eschew the
;   modern "mov, pop, ret" sequence (5 bytes) for "leave, ret" (2 bytes).  */
epilogueret macro
    leave
    ret
endm

    ffi_call_win64_tab_0 label size_t
    ;org 0h+FFI_TYPE_VOID*8
    ;EORG(0b, FFI_TYPE_VOID)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_1 label size_t
    ;org 0h+FFI_TYPE_INT*8
    ;EORG(0b, FFI_TYPE_INT)
    movsxd      rax,            eax ; movslq	%eax, %rax
    mov qword ptr [r8],         rax; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_2 label size_t
    ;org 0h+FFI_TYPE_FLOAT*8
    ;EORG(0b, FFI_TYPE_FLOAT)
    movss dword ptr [r8],       xmm0 ; movss	%xmm0, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_3 label size_t
    ;org 0h+FFI_TYPE_DOUBLE*8
    ;EORG(0b, FFI_TYPE_DOUBLE)
    movsd qword ptr[r8],        xmm0; movsd	%xmm0, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_4 label size_t
    ;org 0h+FFI_TYPE_LONGDOUBLE*8
    ;EORG(0b, FFI_TYPE_LONGDOUBLE)
    jmp     L99
    
    ffi_call_win64_tab_5 label size_t
    ;org 0h+FFI_TYPE_UINT8*8
    ;EORG(0b, FFI_TYPE_UINT8)
    movzx       eax,            al ;movzbl	%al, %eax
    mov qword ptr[r8],          rax; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_6 label size_t
    ;org 0h+FFI_TYPE_SINT8*8
    ;EORG(0b, FFI_TYPE_SINT8)
    movsx       rax,            al ; movsbq	%al, %rax
    mov qword ptr [r8],         rax ; movq	%rax, (%r8)
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_7 label size_t
    ;org 0h+FFI_TYPE_UINT16*8
    ;EORG(0b, FFI_TYPE_UINT16)
    movzx       eax,            ax ; movzwl	%ax, %eax
    mov qword ptr[r8],          rax; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_8 label size_t
    ;org 0h+FFI_TYPE_SINT16*8
    ;EORG(0b, FFI_TYPE_SINT16)
    movsx       rax,            ax; movswq	%ax, %rax
    mov qword ptr [r8],         rax ; movq	%rax, (%r8)
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_9 label size_t
    ;org 0h+FFI_TYPE_UINT32*8
    ;EORG(0b, FFI_TYPE_UINT32)
    mov         eax,            eax; movl	%eax, %eax
    mov qword ptr[r8],          rax ; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_10 label size_t
    ;org 0h+FFI_TYPE_SINT32*8
    ;EORG(0b, FFI_TYPE_SINT32)
    movsxd      rax,            eax; movslq	%eax, %rax
    mov qword ptr [r8],         rax; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_11 label size_t
    ;org 0h+FFI_TYPE_UINT64*8
    ;EORG(0b, FFI_TYPE_UINT64)
    ;L98 label near
    mov qword ptr [r8],         rax ; movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_12 label size_t
    ;org 0h+FFI_TYPE_SINT64*8
    ;EORG(0b, FFI_TYPE_SINT64)
    mov qword ptr [r8],         rax;movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_13 label size_t
    ;org 0h+FFI_TYPE_STRUCT*8
    ;EORG(0b, FFI_TYPE_STRUCT)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_14 label size_t
    ;org 0h+FFI_TYPE_POINTER*8
    ;EORG(0b, FFI_TYPE_POINTER)
    mov qword ptr [r8],         rax ;movq	%rax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_15 label size_t
    ;org 0h+FFI_TYPE_COMPLEX*8
    ;EORG(0b, FFI_TYPE_COMPLEX)
    jmp     L99
    ;epilogueret
    ;jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_16 label size_t
    ;org 0h+FFI_TYPE_SMALL_STRUCT_1B*8
    ;EORG(0b, FFI_TYPE_SMALL_STRUCT_1B)
    mov byte ptr [r8],          al ; movb	%al, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_17 label size_t
    ;org 0h+FFI_TYPE_SMALL_STRUCT_2B*8
    ;EORG(0b, FFI_TYPE_SMALL_STRUCT_2B)
    mov word ptr [r8],          ax ; movw	%ax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end
    
    ffi_call_win64_tab_18 label size_t
    ;org 0h+FFI_TYPE_SMALL_STRUCT_4B*8
    ;EORG(0b, FFI_TYPE_SMALL_STRUCT_4B)
    mov dword ptr [r8],        eax ; movl	%eax, (%r8)
    ;epilogueret
    jmp     ffi_call_win64_end

    L99 label near
    call    abort

    ffi_call_win64_end:    
    leave
    ret
ffi_call_win64 endp

    public c ffi_go_closure_win64

ffi_go_closure_win64 proc c
    ;/* Save all integer arguments into the incoming reg stack space.  */
    mov qword ptr [rsp + 8],        rcx; movq	%rcx, 8(%rsp)
    mov qword ptr [rsp + 16],       rdx; movq	%rdx, 16(%rsp)
    mov qword ptr [rsp + 24],       r8; movq	%r8, 24(%rsp)
    mov qword ptr [rsp + 32],       r9 ;movq	%r9, 32(%rsp)

    mov         rcx, qword ptr [r10 + 8]; movq	8(%r10), %rcx			/* load cif */
    mov         rdx, qword ptr [r10 + 16];  movq	16(%r10), %rdx			/* load fun */
    mov         r8,                 r10 ; movq	%r10, %r8			/* closure is user_data */
    ;jmp        ffi_closure_win64_2
    sub         rsp, ffi_clo_FS ;subq	$ffi_clo_FS, %rsp
    .allocstack ffi_clo_FS
    .endprolog

    ;/* Save all sse arguments into the stack frame.  */
    movsd qword ptr [ffi_clo_OFF_X + rsp],      xmm0	; movsd	%xmm0, ffi_clo_OFF_X(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 8 + rsp],      xmm1 ; movsd	%xmm1, ffi_clo_OFF_X+8(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 16 + rsp],     xmm2 ; movsd %xmm2, ffi_clo_OFF_X+16(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 24 + rsp],     xmm3 ; movsd %xmm3, ffi_clo_OFF_X+24(%rsp)

    lea         r9,         [ffi_clo_OFF_R + rsp] ; leaq	ffi_clo_OFF_R(%rsp), %r9
    call ffi_closure_win64_inner

    ;/* Load the result into both possible result registers.  */
    
    mov         rax,  qword ptr [ffi_clo_OFF_R + rsp] ;movq    ffi_clo_OFF_R(%rsp), %rax
    movsd       xmm0, qword ptr [rsp + ffi_clo_OFF_R] ;movsd   ffi_clo_OFF_R(%rsp), %xmm0

    add         rsp,        ffi_clo_FS ;addq	$ffi_clo_FS, %rsp
    ret
ffi_go_closure_win64 endp


    public c ffi_closure_win64

ffi_closure_win64 proc c frame
    ;/* Save all integer arguments into the incoming reg stack space.  */
    mov qword ptr [rsp + 8],        rcx; movq	%rcx, 8(%rsp)
    mov qword ptr [rsp + 16],       rdx;	movq	%rdx, 16(%rsp)
    mov qword ptr [rsp + 24],       r8; 	movq	%r8, 24(%rsp)
    mov qword ptr [rsp + 32],       r9;	movq	%r9, 32(%rsp)

    mov         rcx, qword ptr [FFI_TRAMPOLINE_SIZE + r10]	;movq	FFI_TRAMPOLINE_SIZ;EORG(%r10), %rcx		/* load cif */
    mov         rdx, qword ptr [FFI_TRAMPOLINE_SIZE + 8 + r10] ;	movq	FFI_TRAMPOLINE_SIZE+8(%r10), %rdx	/* load fun */
    mov         r8, qword ptr [FFI_TRAMPOLINE_SIZE + 16 + r10] ;movq	FFI_TRAMPOLINE_SIZE+16(%r10), %r8	/* load user_data */
    ;ffi_closure_win64_2 label near
    sub         rsp, ffi_clo_FS ;subq	$ffi_clo_FS, %rsp
    .allocstack ffi_clo_FS
    .endprolog

    ;/* Save all sse arguments into the stack frame.  */
    movsd qword ptr [ffi_clo_OFF_X + rsp],      xmm0	; movsd	%xmm0, ffi_clo_OFF_X(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 8 + rsp],      xmm1 ; movsd	%xmm1, ffi_clo_OFF_X+8(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 16 + rsp],     xmm2 ; movsd %xmm2, ffi_clo_OFF_X+16(%rsp)
    movsd qword ptr [ffi_clo_OFF_X + 24 + rsp],     xmm3 ; movsd %xmm3, ffi_clo_OFF_X+24(%rsp)

    lea         r9,         [ffi_clo_OFF_R + rsp] ; leaq	ffi_clo_OFF_R(%rsp), %r9
    call ffi_closure_win64_inner

    ;/* Load the result into both possible result registers.  */
    
    mov         rax,  qword ptr [ffi_clo_OFF_R + rsp] ;movq    ffi_clo_OFF_R(%rsp), %rax
    movsd       xmm0, qword ptr [rsp + ffi_clo_OFF_R] ;movsd   ffi_clo_OFF_R(%rsp), %xmm0

    add         rsp,        ffi_clo_FS ;addq	$ffi_clo_FS, %rsp
    ret
ffi_closure_win64 endp

;_text ends

endif ;LIBFFI_ASM

end
