.code

syscall_handler proc
mov r10, rcx
mov eax, 000h ; syscall number will be dynamically set by syscall::setup
syscall
ret
syscall_handler endp

end