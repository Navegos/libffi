;/* -----------------------------------------------------------------------
;   sysv.S - Copyright (c) 2017  Anthony Green
;          - Copyright (c) 2013  The Written Word, Inc.
;          - Copyright (c) 1996,1998,2001-2003,2005,2008,2010  Red Hat, Inc.
   
;   X86 Foreign Function Interface 

;   Permission is hereby granted, free of charge, to any person obtaining
;   a copy of this software and associated documentation files (the
;   ``Software''), to deal in the Software without restriction, including
;   without limitation the rights to use, copy, modify, merge, publish,
;   distribute, sublicense, and/or sell copies of the Software, and to
;   permit persons to whom the Software is furnished to do so, subject to
;   the following conditions:

;   The above copyright notice and this permission notice shall be included
;   in all copies or substantial portions of the Software.

;   THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY KIND,
;   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
;   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
;   NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
;   HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
;   WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
;   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
;   DEALINGS IN THE SOFTWARE.
;   ----------------------------------------------------------------------- */

ifndef LIBFFI_ASM
define LIBFFI_ASM

;/* This macro allows the safe creation of jump tables without an
;   actual table.  The entry points into the table are all 8 bytes.
;   The use of ORG asserts that we're at the correct location.  */
;/* ??? The clang assembler doesn't handle .org with symbolic expressions.  */
;#if defined(__clang__) || defined(__APPLE__) || (defined (__sun__) && defined(__svr4__))
;# define EORG(BASE, X)     align 8
;#else
;# define EORG(BASE, X)     align 8; ORG BASE + X * 8
;#endif

EORG macro BASE, XN
    align 8
    org BASE + XN * 8 
endm

option casemap:none
.686P
.xmm
.model flat
;option frame:auto
;option stackbase:ebp
option literals:on
option vtable:on

X86_RET_FLOAT       equ 0
X86_RET_DOUBLE      equ 1
X86_RET_LDOUBLE     equ 2
X86_RET_SINT8       equ 3
X86_RET_SINT16      equ 4
X86_RET_UINT8       equ 5
X86_RET_UINT16      equ 6
X86_RET_INT64       equ 7
X86_RET_INT32       equ 8
X86_RET_VOID        equ 9
X86_RET_STRUCTPOP   equ 10
X86_RET_STRUCTARG   equ 11
X86_RET_STRUCT_1B   equ 12
X86_RET_STRUCT_2B   equ 13
X86_RET_UNUSED14    equ 14
X86_RET_UNUSED15    equ 15

X86_RET_TYPE_MASK   equ 15
X86_RET_POP_SHIFT   equ 4

R_EAX       equ 0
R_EDX       equ 1
R_ECX       equ 2

;/* Macros to help setting up the closure_data structure.  */

closure_FS      equ 44
closure_CF      equ 0

raw_closure_S_FS        equ 44
raw_closure_T_FS        equ 40

FFI_TRAMPOLINE_SIZE     equ 16

    .data?

    .data

    .const

        align 4
        ffi_call_i386_tab isize_t offset ffi_call_i386_tab_0,  offset ffi_call_i386_tab_1,  offset ffi_call_i386_tab_2,  offset ffi_call_i386_tab_3,  offset ffi_call_i386_tab_4,  offset ffi_call_i386_tab_5, \
                                  offset ffi_call_i386_tab_6,  offset ffi_call_i386_tab_7,  offset ffi_call_i386_tab_8,  offset ffi_call_i386_tab_9,  offset ffi_call_i386_tab_10, offset ffi_call_i386_tab_11, \
                                  offset ffi_call_i386_tab_12, offset ffi_call_i386_tab_13, offset ffi_call_i386_tab_14, offset ffi_call_i386_tab_15

        align 4
        ffi_go_closure_EAX_tab isize_t offset ffi_go_closure_EAX_tab_0,  offset ffi_go_closure_EAX_tab_1,  offset ffi_go_closure_EAX_tab_2,  offset ffi_go_closure_EAX_tab_3,  offset ffi_go_closure_EAX_tab_4,  offset ffi_go_closure_EAX_tab_5, \
                                       offset ffi_go_closure_EAX_tab_6,  offset ffi_go_closure_EAX_tab_7,  offset ffi_go_closure_EAX_tab_8,  offset ffi_go_closure_EAX_tab_9,  offset ffi_go_closure_EAX_tab_10, offset ffi_go_closure_EAX_tab_11, \
                                       offset ffi_go_closure_EAX_tab_12, offset ffi_go_closure_EAX_tab_13, offset ffi_go_closure_EAX_tab_14, offset ffi_go_closure_EAX_tab_15

        align 4
        ffi_go_closure_ECX_tab isize_t offset ffi_go_closure_ECX_tab_0,  offset ffi_go_closure_ECX_tab_1,  offset ffi_go_closure_ECX_tab_2,  offset ffi_go_closure_ECX_tab_3,  offset ffi_go_closure_ECX_tab_4,  offset ffi_go_closure_ECX_tab_5, \
                                       offset ffi_go_closure_ECX_tab_6,  offset ffi_go_closure_ECX_tab_7,  offset ffi_go_closure_ECX_tab_8,  offset ffi_go_closure_ECX_tab_9,  offset ffi_go_closure_ECX_tab_10, offset ffi_go_closure_ECX_tab_11, \
                                       offset ffi_go_closure_ECX_tab_12, offset ffi_go_closure_ECX_tab_13, offset ffi_go_closure_ECX_tab_14, offset ffi_go_closure_ECX_tab_15

        align 4
        ffi_closure_i386_tab isize_t offset ffi_closure_i386_tab_0,  offset ffi_closure_i386_tab_1,  offset ffi_closure_i386_tab_2,  offset ffi_closure_i386_tab_3,  offset ffi_closure_i386_tab_4,  offset ffi_closure_i386_tab_5, \
                                     offset ffi_closure_i386_tab_6,  offset ffi_closure_i386_tab_7,  offset ffi_closure_i386_tab_8,  offset ffi_closure_i386_tab_9,  offset ffi_closure_i386_tab_10, offset ffi_closure_i386_tab_11, \
                                     offset ffi_closure_i386_tab_12, offset ffi_closure_i386_tab_13, offset ffi_closure_i386_tab_14, offset ffi_closure_i386_tab_15

        align 4
        ffi_go_closure_STDCALL_tab isize_t offset ffi_go_closure_STDCALL_tab_0,  offset ffi_go_closure_STDCALL_tab_1,  offset ffi_go_closure_STDCALL_tab_2,  offset ffi_go_closure_STDCALL_tab_3,  offset ffi_go_closure_STDCALL_tab_4,  offset ffi_go_closure_STDCALL_tab_5, \
                                           offset ffi_go_closure_STDCALL_tab_6,  offset ffi_go_closure_STDCALL_tab_7,  offset ffi_go_closure_STDCALL_tab_8,  offset ffi_go_closure_STDCALL_tab_9,  offset ffi_go_closure_STDCALL_tab_10, offset ffi_go_closure_STDCALL_tab_11, \
                                           offset ffi_go_closure_STDCALL_tab_12, offset ffi_go_closure_STDCALL_tab_13, offset ffi_go_closure_STDCALL_tab_14, offset ffi_go_closure_STDCALL_tab_15

        align 4
        ffi_closure_REGISTER_tab isize_t offset ffi_closure_REGISTER_tab_0,  offset ffi_closure_REGISTER_tab_1,  offset ffi_closure_REGISTER_tab_2,  offset ffi_closure_REGISTER_tab_3,  offset ffi_closure_REGISTER_tab_4,  offset ffi_closure_REGISTER_tab_5, \
                                         offset ffi_closure_REGISTER_tab_6,  offset ffi_closure_REGISTER_tab_7,  offset ffi_closure_REGISTER_tab_8,  offset ffi_closure_REGISTER_tab_9,  offset ffi_closure_REGISTER_tab_10, offset ffi_closure_REGISTER_tab_11, \
                                         offset ffi_closure_REGISTER_tab_12, offset ffi_closure_REGISTER_tab_13, offset ffi_closure_REGISTER_tab_14, offset ffi_closure_REGISTER_tab_15

        align 4
        ffi_closure_STDCALL_tab isize_t offset ffi_closure_STDCALL_tab_0,  offset ffi_closure_STDCALL_tab_1,  offset ffi_closure_STDCALL_tab_2,  offset ffi_closure_STDCALL_tab_3,  offset ffi_closure_STDCALL_tab_4,  offset ffi_closure_STDCALL_tab_5, \
                                        offset ffi_closure_STDCALL_tab_6,  offset ffi_closure_STDCALL_tab_7,  offset ffi_closure_STDCALL_tab_8,  offset ffi_closure_STDCALL_tab_9,  offset ffi_closure_STDCALL_tab_10, offset ffi_closure_STDCALL_tab_11, \
                                        offset ffi_closure_STDCALL_tab_12, offset ffi_closure_STDCALL_tab_13, offset ffi_closure_STDCALL_tab_14, offset ffi_closure_STDCALL_tab_15

        align 4
        ffi_closure_raw_SYSV_tab isize_t offset ffi_closure_raw_SYSV_tab_0,  offset ffi_closure_raw_SYSV_tab_1,  offset ffi_closure_raw_SYSV_tab_2,  offset ffi_closure_raw_SYSV_tab_3,  offset ffi_closure_raw_SYSV_tab_4,  offset ffi_closure_raw_SYSV_tab_5, \
                                         offset ffi_closure_raw_SYSV_tab_6,  offset ffi_closure_raw_SYSV_tab_7,  offset ffi_closure_raw_SYSV_tab_8,  offset ffi_closure_raw_SYSV_tab_9,  offset ffi_closure_raw_SYSV_tab_10, offset ffi_closure_raw_SYSV_tab_11, \
                                         offset ffi_closure_raw_SYSV_tab_12, offset ffi_closure_raw_SYSV_tab_13, offset ffi_closure_raw_SYSV_tab_14, offset ffi_closure_raw_SYSV_tab_15

        align 4
        ffi_closure_raw_THISCALL_tab isize_t offset ffi_closure_raw_THISCALL_tab_0,  offset ffi_closure_raw_THISCALL_tab_1,  offset ffi_closure_raw_THISCALL_tab_2,  offset ffi_closure_raw_THISCALL_tab_3,  offset ffi_closure_raw_THISCALL_tab_4,  offset ffi_closure_raw_THISCALL_tab_5, \
                                             offset ffi_closure_raw_THISCALL_tab_6,  offset ffi_closure_raw_THISCALL_tab_7,  offset ffi_closure_raw_THISCALL_tab_8,  offset ffi_closure_raw_THISCALL_tab_9,  offset ffi_closure_raw_THISCALL_tab_10, offset ffi_closure_raw_THISCALL_tab_11, \
                                             offset ffi_closure_raw_THISCALL_tab_12, offset ffi_closure_raw_THISCALL_tab_13, offset ffi_closure_raw_THISCALL_tab_14, offset ffi_closure_raw_THISCALL_tab_15

    .code

    alignfieldproc 4

    ;EXTRN     @ffi_closure_inner@8:proc
    extern fastcall ffi_closure_inner:proc :ptr :ptr

;/* This is declared as

;   void ffi_call_i386(struct call_frame *frame, char *argp)
;        __attribute__((fastcall));

;   Thus the arguments are present in

;        ecx: frame
;        edx: argp
;*/

    ;align 16
    ;public @ffi_call_i386@8
    ;@ffi_call_i386@8 proc
    public fastcall ffi_call_i386 :ptr :ptr
ffi_call_i386 proc fastcall :ptr :ptr
    mov         eax,            [esp]       ;/* move the return address */
    mov        [ecx],            ebp         ;/* store ebp into local frame */
    mov        [ecx + 4],        eax         ;/* store retaddr into local frame */

    ;/* New stack frame based off ebp.  This is a itty bit of unwind
    ;   trickery in that the CFA *has* changed.  There is no easy way
    ;   to describe it correctly on entry to the function.  Fortunately,
    ;   it doesn't matter too much since at all points we can correctly
    ;   unwind back to ffi_call.  Note that the location to which we
    ;   moved the return address is (the new) CFA-4, so from the
    ;   perspective of the unwind info, it hasn't moved.  */
    mov         ebp,            ecx

    mov         esp,            edx          ;/* set outgoing argument stack */
    mov         eax,           [20 + R_EAX * 4 + ebp]        ;/* set register arguments */
    mov         edx,           [20 + R_EDX * 4 + ebp]
    mov         ecx,           [20 + R_ECX * 4 + ebp]

    call     dword ptr [ebp + 8]

    mov         ecx,           [12 + ebp]     ;/* load return type code */
    mov        [ebp + 8],       ebx          ;/* preserve %ebx */

    and         ecx,            X86_RET_TYPE_MASK
    lea         ebx,           [ffi_call_i386_tab + ecx * size_t_size]
    mov         ecx,           [ebp + 16]                   ; /* load result address */
    jmp         ebx

    ;align 8
    ffi_call_i386_tab_0 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_FLOAT)
    fstp     dword ptr [ecx]
    jmp      ffi_call_i386_end

    ffi_call_i386_tab_1 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_DOUBLE)
    fstp     qword ptr [ecx]
    jmp      ffi_call_i386_end

    ffi_call_i386_tab_2 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_LDOUBLE)
    fstp     qword ptr [ecx]
    jmp      ffi_call_i386_end

    ffi_call_i386_tab_3 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_SINT8)
    movsx       eax,           al
    mov        [ecx],          eax
    jmp      ffi_call_i386_end

    ffi_call_i386_tab_4 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_SINT16)
    movsx       eax,           ax
    mov        [ecx],          eax
    jmp      ffi_call_i386_end
    
    ffi_call_i386_tab_5 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_UINT8)
    movzx       eax,           al
    mov        [ecx],          eax
    jmp      ffi_call_i386_end
    
    ffi_call_i386_tab_6 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_UINT16)
    movzx       eax,           ax
    mov        [ecx],          eax
    jmp      ffi_call_i386_end
    
    ffi_call_i386_tab_7 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_INT64)
    mov        [ecx + 4],      edx
    mov        [ecx],          eax
    jmp     ffi_call_i386_end
    
    ffi_call_i386_tab_8 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_INT32)
    mov        [ecx],          eax
    jmp      ffi_call_i386_end
    
    ffi_call_i386_tab_9 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_VOID)
    jmp      ffi_call_i386_end

    ffi_call_i386_tab_10 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_STRUCTPOP)
    jmp     ffi_call_i386_end
    
    ffi_call_i386_tab_11 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_STRUCTARG)
    jmp     ffi_call_i386_end
    
    ffi_call_i386_tab_12 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_STRUCT_1B)
    mov        [ecx],          al
    jmp     ffi_call_i386_end
    
    ffi_call_i386_tab_13 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_STRUCT_2B)
    mov        [ecx],          ax
    jmp     ffi_call_i386_end

    ;/* Fill out the table so that bad values are predictable.  */
    ffi_call_i386_tab_14 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_UNUSED14)
    jmp     ffi_call_i386_interrupt
    
    ffi_call_i386_tab_15 label size_t
    ;EORG(L(ffi_call_i386_tab), X86_RET_UNUSED15)
    jmp     ffi_call_i386_interrupt

    ffi_call_i386_end:
    mov         ebx,            [ebp + 8]
    mov         esp,            ebp
    pop         ebp
    ret

    ffi_call_i386_interrupt:
    int 3
ffi_call_i386 endp

;/* The inner helper is declared as

;   void ffi_closure_inner(struct closure_frame *frame, char *argp)
;    __attribute_((fastcall))

;   Thus the arguments are placed in

;    ecx:     frame
;    edx:     argp
;*/

    ;align 16
    public c ffi_go_closure_EAX
ffi_go_closure_EAX proc c
    sub         esp,        closure_FS
    mov        [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov        [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov        [esp + closure_CF + 16 + R_ECX * 4],      ecx
    mov         edx,       [eax + 4]                   ;/* copy cif */
    mov         ecx,       [eax + 8]                   ;/* copy fun */
    mov        [esp + closure_CF + 28],        edx
    mov        [esp + closure_CF + 32],        ecx
    mov        [esp + closure_CF + 36],        eax         ;/* closure is user_data */

    ;/* Entry point from preceeding Go closures.  */
    mov        ecx,         esp                          ;/* load closure_data */
    lea        edx,        [esp + closure_FS + 4]       ;/* load incoming stack */
    call     ffi_closure_inner
    and        eax,         X86_RET_TYPE_MASK
    lea        edx,        [ffi_go_closure_EAX_tab + eax * size_t_size]
    mov        eax,        [esp + closure_CF]           ;/* optimiztic load */
    jmp        edx

    ;align 8
    ;ffi_go_closure_EAX_tab:
    ffi_go_closure_EAX_tab_0 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_FLOAT)
    fld     dword ptr [esp + closure_CF]
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_1 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_DOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_2 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_LDOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_3 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_SINT8)
    movsx      eax,         al
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_4 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_SINT16)
    movsx      eax,         ax
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_5 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_UINT8)
    movzx      eax,         al
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_6 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_UINT16)
    movzx      eax,         ax
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_7 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_INT64)
    mov        edx,        [esp + closure_CF + 4]
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_8 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_INT32)
    nop
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_9 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_VOID)
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_10 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_STRUCTPOP)
    jmp     ffi_go_closure_EAX_endp
    
    ffi_go_closure_EAX_tab_11 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_STRUCTARG)
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_12 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_STRUCT_1B)
    movzx      eax,         al
    jmp     ffi_go_closure_EAX_end
    
    ffi_go_closure_EAX_tab_13 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_STRUCT_2B)
    movzx      eax,         ax
    jmp     ffi_go_closure_EAX_end

    ;/* Fill out the table so that bad values are predictable.  */    
    ffi_go_closure_EAX_tab_14 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_UNUSED14)
    jmp     ffi_go_closure_EAX_interrupt
    
    ffi_go_closure_EAX_tab_15 label size_t
    ;EORG(L(ffi_go_closure_EAX_tab), X86_RET_UNUSED15)
    jmp     ffi_go_closure_EAX_interrupt
    
    ffi_go_closure_EAX_end:
    add        esp,         closure_FS
    ret
    
    ffi_go_closure_EAX_endp:
    add        esp,         closure_FS
    ret     4

    ffi_go_closure_EAX_interrupt:
    int 3
ffi_go_closure_EAX endp

    ;align 16
    public c ffi_go_closure_ECX
ffi_go_closure_ECX proc c
    sub         esp,        closure_FS
    mov        [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov        [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov        [esp + closure_CF + 16 + R_ECX * 4],      ecx
    mov         edx,        [ecx + 4]                   ;/* copy cif */
    mov         eax,        [ecx + 8]                   ;/* copy fun */
    mov        [esp + closure_CF + 28],        edx
    mov        [esp + closure_CF + 32],        eax
    mov        [esp + closure_CF + 36],        ecx      ;/* closure is user_data */
    
    ;/* Entry point from preceeding Go closures.  */
    mov        ecx,        esp                          ;/* load closure_data */
    lea        edx,        [esp + closure_FS + 4]       ;/* load incoming stack */
    call     ffi_closure_inner
    and        eax,        X86_RET_TYPE_MASK
    lea        edx,        [ffi_go_closure_ECX_tab + eax * size_t_size]
    mov        eax,        [esp + closure_CF]           ;/* optimiztic load */
    jmp        edx

    ;align 8
    ;ffi_go_closure_ECX_tab:
    ffi_go_closure_ECX_tab_0 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_FLOAT)
    fld     dword ptr [esp + closure_CF]
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_1 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_DOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_2 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_LDOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_3 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_SINT8)
    movsx      eax,         al
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_4 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_SINT16)
    movsx      eax,         ax
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_5 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_UINT8)
    movzx      eax,         al
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_6 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_UINT16)
    movzx      eax,         ax
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_7 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_INT64)
    mov        edx,        [esp + closure_CF + 4]
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_8 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_INT32)
    nop
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_9 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_VOID)
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_10 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_STRUCTPOP)
    jmp     ffi_go_closure_ECX_endp
    
    ffi_go_closure_ECX_tab_11 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_STRUCTARG)
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_12 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_STRUCT_1B)
    movzx      eax,         al
    jmp     ffi_go_closure_ECX_end
    
    ffi_go_closure_ECX_tab_13 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_STRUCT_2B)
    movzx      eax,         ax
    jmp     ffi_go_closure_ECX_end

    ;/* Fill out the table so that bad values are predictable.  */    
    ffi_go_closure_ECX_tab_14 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_UNUSED14)
    jmp     ffi_go_closure_ECX_interrupt
    
    ffi_go_closure_ECX_tab_15 label size_t
    ;EORG(L(ffi_go_closure_ECX_tab), X86_RET_UNUSED15)
    jmp     ffi_go_closure_ECX_interrupt
    
    ffi_go_closure_ECX_end:
    add        esp,         closure_FS
    ret
    
    ffi_go_closure_ECX_endp:
    add        esp,         closure_FS
    ret     4

    ffi_go_closure_ECX_interrupt:
    int 3
ffi_go_closure_ECX endp

;/* The closure entry points are reached from the ffi_closure trampoline.
;   On entry, %eax contains the address of the ffi_closure.  */

    ;align 16
    public c ffi_closure_i386
ffi_closure_i386 proc c
    sub        esp,        closure_FS
    mov       [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov       [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov       [esp + closure_CF + 16 + R_ECX * 4],      ecx
    mov        edx,        [eax + FFI_TRAMPOLINE_SIZE]      ;/* copy cif */
    mov        ecx,        [eax + FFI_TRAMPOLINE_SIZE + 4]    ;/* copy fun */
    mov        eax,        [eax + FFI_TRAMPOLINE_SIZE + 8]    ;/* copy user_data */
    mov       [esp + closure_CF + 28],        edx
    mov       [esp + closure_CF + 32],        ecx
    mov       [esp + closure_CF + 36],        eax

    ;/* Entry point from preceeding Go closures.  */
    mov        ecx,        esp                    ;/* load closure_data */
    lea        edx,        [esp + closure_FS + 4]     ;/* load incoming stack */
    call     ffi_closure_inner
    and        eax,        X86_RET_TYPE_MASK
    lea        edx,        [ffi_closure_i386_tab + eax * size_t_size]
    mov        eax,        [esp + closure_CF]       ;/* optimiztic load */
    jmp        edx

    ;align 8
    ;ffi_closure_i386_tab:
    ffi_closure_i386_tab_0 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_FLOAT)
    fld     dword ptr [esp + closure_CF]
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_1 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_DOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_2 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_LDOUBLE)
    fld     qword ptr [esp + closure_CF]
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_3 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_SINT8)
    movsx      eax,         al
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_4 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_SINT16)
    movsx      eax,         ax
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_5 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_UINT8)
    movzx      eax,         al
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_6 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_UINT16)
    movzx      eax,         ax
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_7 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_INT64)
    mov        edx,        [esp + closure_CF + 4]
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_8 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_INT32)
    nop
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_9 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_VOID)
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_10 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_STRUCTPOP)
    jmp     ffi_closure_i386_endp
    
    ffi_closure_i386_tab_11 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_STRUCTARG)
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_12 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_STRUCT_1B)
    movzx      eax,         al
    jmp     ffi_closure_i386_end
    
    ffi_closure_i386_tab_13 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_STRUCT_2B)
    movzx      eax,         ax
    jmp     ffi_closure_i386_end

    ;/* Fill out the table so that bad values are predictable.  */    
    ffi_closure_i386_tab_14 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_UNUSED14)
    jmp     ffi_closure_i386_interrupt
    
    ffi_closure_i386_tab_15 label size_t
    ;EORG(L(ffi_closure_i386_tab), X86_RET_UNUSED15)
    jmp     ffi_closure_i386_interrupt
    
    ffi_closure_i386_end:
    add        esp,         closure_FS
    ret
    
    ffi_closure_i386_endp:
    add        esp,         closure_FS
    ret     4

    ffi_closure_i386_interrupt:
    int 3
ffi_closure_i386 endp

    ;align 16
    public c ffi_go_closure_STDCALL
ffi_go_closure_STDCALL proc c
    sub        esp,         closure_FS
    mov       [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov       [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov       [esp + closure_CF + 16 + R_ECX * 4],      ecx
    mov        edx,         [ecx + 4]                   ;/* copy cif */
    mov        eax,         [ecx + 8]                   ;/* copy fun */
    mov       [esp + closure_CF + 28],      edx
    mov       [esp + closure_CF + 32],      eax
    mov       [esp + closure_CF + 36],      ecx         ;/* closure is user_data */
    
    ;/* Entry point from preceeding Go closure.  */
    mov       ecx,        esp                    ;/* load closure_data */
    lea       edx,        [esp + closure_FS + 4]     ;/* load incoming stack */
    call     ffi_closure_inner

    mov       ecx,        eax
    shr       ecx,        X86_RET_POP_SHIFT          ;/* isolate pop count */
    lea       ecx,       [esp + closure_FS + ecx]       ;/* compute popped esp */
    mov       edx,       [esp + closure_FS]           ;/* move return address */
    mov      [ecx],       edx

    ;/* From this point on, the value of %esp upon return is %ecx+4,
    ;   and we've copied the return address to %ecx to make return easy.
    ;   There's no point in representing this in the unwind info, as
    ;   there is always a window between the mov and the ret which
    ;   will be wrong from one point of view or another.  */

    and       eax,         X86_RET_TYPE_MASK
    lea       edx,        [ffi_go_closure_STDCALL_tab + eax * size_t_size]
    mov       eax,        [esp + closure_CF]       ;/* optimiztic load */
    jmp       edx

    ;align 8
    ffi_go_closure_STDCALL_tab_0 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_FLOAT)
    fld    dword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_1 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_DOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_2 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_LDOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_3 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_SINT8)
    movsx     eax,          al
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_4 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_SINT16)
    movsx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_5 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_UINT8)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_6 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_UINT16)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_7 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_INT64)
    mov       edx,         [esp + closure_CF + 4]
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_8 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_INT32)
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_9 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_VOID)
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_10 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_STRUCTPOP)
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_11 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_STRUCTARG)
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_12 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_STRUCT_1B)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end
    
    ffi_go_closure_STDCALL_tab_13 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_STRUCT_2B)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_go_closure_STDCALL_end

    ;/* Fill out the table so that bad values are predictable.  */
    ffi_go_closure_STDCALL_tab_14 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_UNUSED14)
    jmp     ffi_go_closure_STDCALL_interrupt

    ffi_go_closure_STDCALL_tab_15 label size_t
    ;EORG(L(ffi_go_closure_STDCALL_tab), X86_RET_UNUSED15)
    jmp     ffi_go_closure_STDCALL_interrupt
    
    ffi_go_closure_STDCALL_end:
    ret
    
    ffi_go_closure_STDCALL_interrupt:
    int 3
ffi_go_closure_STDCALL endp

;/* For REGISTER, we have no available parameter registers, and so we
;   enter here having pushed the closure onto the stack.  */

    ;align 16
    public c ffi_closure_REGISTER
ffi_closure_REGISTER proc c
    sub        esp,         closure_FS-4
    mov       [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov       [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov       [esp + closure_CF + 16 + R_ECX * 4],      ecx
    mov        ecx, [esp + closure_FS - 4]              ;/* load retaddr */
    mov        eax, [esp + closure_FS]                  ;/* load closure */
    mov       [esp + closure_FS], ecx                   ;/* move retaddr */
    
    ;/* Entry point from ffi_closure_REGISTER.  */
    mov       edx,        [eax + FFI_TRAMPOLINE_SIZE]      ;/* copy cif */
    mov       ecx,        [eax + FFI_TRAMPOLINE_SIZE + 4]    ;/* copy fun */
    mov       eax,        [eax + FFI_TRAMPOLINE_SIZE + 8]    ;/* copy user_data */
    mov      [esp + closure_CF + 28],        edx
    mov      [esp + closure_CF + 32],        ecx
    mov      [esp + closure_CF + 36],        eax

    ;/* Entry point from preceeding Go closure.  */
    mov       ecx,        esp                    ;/* load closure_data */
    lea       edx,        [esp + closure_FS + 4]     ;/* load incoming stack */
    call     ffi_closure_inner

    mov       ecx,        eax
    shr       ecx,        X86_RET_POP_SHIFT          ;/* isolate pop count */
    lea       ecx,       [esp + closure_FS + ecx]       ;/* compute popped esp */
    mov       edx,       [esp + closure_FS]           ;/* move return address */
    mov      [ecx],       edx

    ;/* From this point on, the value of %esp upon return is %ecx+4,
    ;   and we've copied the return address to %ecx to make return easy.
    ;   There's no point in representing this in the unwind info, as
    ;   there is always a window between the mov and the ret which
    ;   will be wrong from one point of view or another.  */

    and       eax,         X86_RET_TYPE_MASK
    lea       edx,        [ffi_closure_REGISTER_tab + eax * size_t_size]
    mov       eax,        [esp + closure_CF]       ;/* optimiztic load */
    jmp       edx

    ;align 8
    ffi_closure_REGISTER_tab_0 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_FLOAT)
    fld    dword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_1 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_DOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_2 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_LDOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_3 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_SINT8)
    movsx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_4 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_SINT16)
    movsx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_5 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_UINT8)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_6 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_UINT16)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_7 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_INT64)
    mov       edx,         [esp + closure_CF + 4]
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_8 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_INT32)
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_9 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_VOID)
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_10 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_STRUCTPOP)
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_11 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_STRUCTARG)
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_12 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_STRUCT_1B)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end
    
    ffi_closure_REGISTER_tab_13 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_STRUCT_2B)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_REGISTER_end

    ;/* Fill out the table so that bad values are predictable.  */
    ffi_closure_REGISTER_tab_14 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_UNUSED14)
    jmp     ffi_closure_REGISTER_interrupt

    ffi_closure_REGISTER_tab_15 label size_t
    ;EORG(L(ffi_closure_REGISTER_tab), X86_RET_UNUSED15)
    jmp     ffi_closure_REGISTER_interrupt
    
    ffi_closure_REGISTER_end:
    ret
    
    ffi_closure_REGISTER_interrupt:
    int 3
ffi_closure_REGISTER endp

;/* For STDCALL (and others), we need to pop N bytes of arguments off
;   the stack following the closure.  The amount needing to be popped
;   is returned to us from ffi_closure_inner.  */

    ;align 16
    public c ffi_closure_STDCALL
ffi_closure_STDCALL proc c
    sub       esp,         closure_FS
    mov      [esp + closure_CF + 16 + R_EAX * 4],      eax
    mov      [esp + closure_CF + 16 + R_EDX * 4],      edx
    mov      [esp + closure_CF + 16 + R_ECX * 4],      ecx

    ;/* Entry point from ffi_closure_REGISTER.  */
    mov       edx,        [eax + FFI_TRAMPOLINE_SIZE]      ;/* copy cif */
    mov       ecx,        [eax + FFI_TRAMPOLINE_SIZE + 4]    ;/* copy fun */
    mov       eax,        [eax + FFI_TRAMPOLINE_SIZE + 8]    ;/* copy user_data */
    mov      [esp + closure_CF + 28],        edx
    mov      [esp + closure_CF + 32],        ecx
    mov      [esp + closure_CF + 36],        eax

    ;/* Entry point from preceeding Go closure.  */
    mov       ecx,        esp                    ;/* load closure_data */
    lea       edx,        [esp + closure_FS + 4]     ;/* load incoming stack */
    call     ffi_closure_inner

    mov       ecx,        eax
    shr       ecx,        X86_RET_POP_SHIFT          ;/* isolate pop count */
    lea       ecx,       [esp + closure_FS + ecx]       ;/* compute popped esp */
    mov       edx,       [esp + closure_FS]           ;/* move return address */
    mov      [ecx],       edx

    ;/* From this point on, the value of %esp upon return is %ecx+4,
    ;   and we've copied the return address to %ecx to make return easy.
    ;   There's no point in representing this in the unwind info, as
    ;   there is always a window between the mov and the ret which
    ;   will be wrong from one point of view or another.  */

    and       eax,         X86_RET_TYPE_MASK
    lea       edx,        [ffi_closure_STDCALL_tab + eax * size_t_size]
    mov       eax,        [esp + closure_CF]       ;/* optimiztic load */
    jmp       edx

    ;align 8
    ffi_closure_STDCALL_tab_0 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_FLOAT)
    fld    dword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_1 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_DOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_2 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_LDOUBLE)
    fld    qword ptr [esp + closure_CF]
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_3 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_SINT8)
    movsx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_4 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_SINT16)
    movsx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_5 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_UINT8)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_6 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_UINT16)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_7 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_INT64)
    mov       edx,         [esp + closure_CF + 4]
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_8 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_INT32)
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_9 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_VOID)
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_10 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_STRUCTPOP)
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_11 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_STRUCTARG)
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_12 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_STRUCT_1B)
    movzx     eax,          al
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end
    
    ffi_closure_STDCALL_tab_13 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_STRUCT_2B)
    movzx     eax,          ax
    mov       esp,          ecx
    jmp     ffi_closure_STDCALL_end

    ;/* Fill out the table so that bad values are predictable.  */
    ffi_closure_STDCALL_tab_14 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_UNUSED14)
    jmp     ffi_closure_STDCALL_interrupt

    ffi_closure_STDCALL_tab_15 label size_t
    ;EORG(L(ffi_closure_STDCALL_tab), X86_RET_UNUSED15)
    jmp     ffi_closure_STDCALL_interrupt
    
    ffi_closure_STDCALL_end:
    ret
    
    ffi_closure_STDCALL_interrupt:
    int 3
ffi_closure_STDCALL endp

;#if !FFI_NO_RAW_API

    ;align 16
    public c ffi_closure_raw_SYSV
ffi_closure_raw_SYSV proc c
    sub       esp,        raw_closure_S_FS
    mov      [esp + raw_closure_S_FS - 4],       ebx

    mov       edx,          [eax + FFI_TRAMPOLINE_SIZE + 8]            ;/* load cl->user_data */
    mov      [esp + 12],     edx
    lea       edx,          [esp + raw_closure_S_FS + 4]               ;/* load raw_args */
    mov      [esp + 8],      edx
    lea       edx,          [esp + 16]                                 ;/* load &res */
    mov      [esp + 4],      edx
    mov       ebx,          [eax + FFI_TRAMPOLINE_SIZE]                ;/* load cl->cif */
    mov      [esp],          ebx
    call    dword ptr [eax + FFI_TRAMPOLINE_SIZE + 4]                 ;/* call cl->fun */

    mov       eax,          [ebx+20]                                   ;/* load cif->flags */
    and       eax,           X86_RET_TYPE_MASK

    lea       ecx,          [ffi_closure_raw_SYSV_tab + eax * size_t_size]
    mov       ebx,          [esp + raw_closure_S_FS - 4]

    mov       eax,          [esp + 16]                                  ;/* Optimistic load */
    jmp     dword ptr [ecx]

    ;align 8
    ffi_closure_raw_SYSV_tab_0 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_FLOAT)
    fld     dword ptr [esp + 16]
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_1 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_DOUBLE)
    fld     qword ptr [esp + 16]
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_2 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_LDOUBLE)
    fld     qword ptr [esp + 16]
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_3 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_SINT8)
    movsx     eax,           al
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_4 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_SINT16)
    movsx     eax,           ax
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_5 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_UINT8)
    movzx     eax,           al
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_6 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_UINT16)
    movzx     eax,           ax
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_7 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_INT64)
    mov       edx,          [esp + 16 + 4]
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_8 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_INT32)
    nop
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_9 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_VOID)
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_10 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_STRUCTPOP)
    jmp     ffi_closure_raw_SYSV_endp
    
    ffi_closure_raw_SYSV_tab_11 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_STRUCTARG)
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_12 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_STRUCT_1B)
    movzx     eax,          al
    jmp     ffi_closure_raw_SYSV_end
    
    ffi_closure_raw_SYSV_tab_13 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_STRUCT_2B)
    movzx     eax,          ax
    jmp     ffi_closure_raw_SYSV_end

    ;/* Fill out the table so that bad values are predictable.  */    
    ffi_closure_raw_SYSV_tab_14 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_UNUSED14)
    jmp     ffi_closure_raw_SYSV_interrupt
    
    ffi_closure_raw_SYSV_tab_15 label size_t
    ;EORG(L(ffi_closure_raw_SYSV_tab), X86_RET_UNUSED15)
    jmp     ffi_closure_raw_SYSV_interrupt
    
    ffi_closure_raw_SYSV_end:
    add       esp,          raw_closure_S_FS
    ret
    
    ffi_closure_raw_SYSV_endp:
    add       esp,          raw_closure_S_FS
    ret     4

    ffi_closure_raw_SYSV_interrupt:
    int 3
ffi_closure_raw_SYSV endp

    ;align 16
    public c ffi_closure_raw_THISCALL
ffi_closure_raw_THISCALL proc c
    ;/* Rearrange the stack such that %ecx is the first argument.
    ;   This means moving the return address.  */
    pop       edx
    push      ecx
    push      edx
    sub       esp,          raw_closure_T_FS
    mov      [esp + raw_closure_T_FS - 4],          ebx

    mov       edx,           [eax + FFI_TRAMPOLINE_SIZE + 8]        ;/* load cl->user_data */
    mov      [esp + 12],      edx
    lea       edx,           [esp + raw_closure_T_FS + 4]           ;/* load raw_args */
    mov      [esp + 8],       edx
    lea       edx,           [esp + 16]                             ;/* load &res */
    mov      [esp + 4],       edx
    mov       ebx,           [eax + FFI_TRAMPOLINE_SIZE]            ;/* load cl->cif */
    mov      [esp],           ebx
    call     dword ptr [eax + FFI_TRAMPOLINE_SIZE + 4]              ;/* call cl->fun */

    mov       eax,            [ebx + 20]                            ;/* load cif->flags */
    and       eax,             X86_RET_TYPE_MASK
    lea       ecx,            [ffi_closure_raw_THISCALL_tab + eax * size_t_size]
    mov       ebx,            [esp + raw_closure_T_FS - 4]
    mov       eax,            [esp + 16]                            ;/* Optimistic load */
    jmp     dword ptr [ecx]

    ;align 4
    ffi_closure_raw_THISCALL_tab_0 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_FLOAT)
    fld     dword ptr [esp + 16]
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_1 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_DOUBLE)
    fld     qword ptr [esp + 16]
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_2 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_LDOUBLE)
    fld     qword ptr [esp + 16]
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_3 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_SINT8)
    movsx     eax,            al
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_4 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_SINT16)
    movsx     eax,            ax
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_5 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_UINT8)
    movzx     eax,            al
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_6 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_UINT16)
    movzx     eax,            ax
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_7 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_INT64)
    mov       edx,           [esp + 16 + 4]
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_8 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_INT32)
    nop
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_9 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_VOID)
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_10 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_STRUCTPOP)
    jmp     ffi_closure_raw_THISCALL_endp
    
    ffi_closure_raw_THISCALL_tab_11 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_STRUCTARG)
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_12 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_STRUCT_1B)
    movzx     eax,            al
    jmp     ffi_closure_raw_THISCALL_end
    
    ffi_closure_raw_THISCALL_tab_13 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_STRUCT_2B)
    movzx     eax,            ax
    jmp     ffi_closure_raw_THISCALL_end

    ;/* Fill out the table so that bad values are predictable.  */    
    ffi_closure_raw_THISCALL_tab_14 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_UNUSED14)
    jmp     ffi_closure_raw_THISCALL_interrupt
    
    ffi_closure_raw_THISCALL_tab_15 label size_t
    ;EORG(L(ffi_closure_raw_THISCALL_tab), X86_RET_UNUSED15)
    jmp     ffi_closure_raw_THISCALL_interrupt
    
    ffi_closure_raw_THISCALL_end:
    add       esp,            raw_closure_T_FS
    ;/* Remove the extra %ecx argument we pushed.  */
    ret     4
    
    ffi_closure_raw_THISCALL_endp:
    add       esp,            raw_closure_T_FS
    ret     8

    ffi_closure_raw_THISCALL_interrupt:
    int 3
ffi_closure_raw_THISCALL endp

;#endif /* !FFI_NO_RAW_API */

endif ;LIBFFI_ASM

end
