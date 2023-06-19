sub esi, 1
mov edx, esi
mov esi, 0
call quickSort
ret

partition:
        push    r12
        push    rbp
        push    rbx
        mov     rbx, rdi
        mov     r9d, esi
        mov     ebp, edx
        lea     ecx, [rdx+1]
        movsx   rax, esi
        lea     r12, [rdi+rax*8]
        mov     rdi, QWORD PTR [r12]
        lea     r10d, [rsi+1]
        movsx   r10, r10d
        jmp     .L2
.L9:
        cmp     ecx, edx
        jle     .L7
        mov     QWORD PTR [rbx+r10*8], rsi
        mov     QWORD PTR [r8], r11
.L3:
        add     r10, 1
.L2:
        mov     r11, QWORD PTR [rbx+r10*8]
        mov     edx, r10d
        cmp     r11, rdi
        jge     .L8
        cmp     ebp, r10d
        jne     .L3
.L8:
        movsx   rax, ecx
        lea     rax, [rbx-8+rax*8]
.L5:
        sub     ecx, 1
        mov     r8, rax
        mov     rsi, QWORD PTR [rax]
        sub     rax, 8
        cmp     r9d, ecx
        je      .L9
        cmp     rsi, rdi
        jg      .L5
        jmp     .L9
.L7:
        mov     rax, QWORD PTR [r12]
        mov     QWORD PTR [r12], rsi
        mov     QWORD PTR [r8], rax
        mov     eax, ecx
        pop     rbx
        pop     rbp
        pop     r12
        ret
quickSort:
        cmp     esi, edx
        jl      .L18
        ret
.L18:
        push    r13
        push    r12
        push    rbp
        push    rbx
        sub     rsp, 8
        mov     r12, rdi
        mov     r13d, esi
        mov     ebx, edx
        call    partition
        mov     ebp, eax
        lea     edx, [rax-1]
        mov     esi, r13d
        mov     rdi, r12
        call    quickSort
        lea     esi, [rbp+1]
        mov     edx, ebx
        mov     rdi, r12
        call    quickSort
        add     rsp, 8
        pop     rbx
        pop     rbp
        pop     r12
        pop     r13
        ret
