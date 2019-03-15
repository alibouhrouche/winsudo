format PE GUI 4.0
include 'win32ax.inc'
include 'cmd.inc'

_fm     db '%s',0
_fmt    db '%s %s',0
_hheap   dd ?

SEE_MASK_DEFAULT                = 0x00000000
SEE_MASK_CLASSNAME              = 0x00000001
SEE_MASK_CLASSKEY               = 0x00000003
SEE_MASK_IDLIST                 = 0x00000004
SEE_MASK_INVOKEIDLIST           = 0x0000000C
SEE_MASK_ICON                   = 0x00000010
SEE_MASK_HOTKEY                 = 0x00000020
SEE_MASK_NOCLOSEPROCESS         = 0x00000040
SEE_MASK_CONNECTNETDRV          = 0x00000080
SEE_MASK_NOASYNC                = 0x00000100
SEE_MASK_FLAG_DDEWAIT           = 0x00000100
SEE_MASK_DOENVSUBST             = 0x00000200
SEE_MASK_FLAG_NO_UI             = 0x00000400
SEE_MASK_UNICODE                = 0x00004000
SEE_MASK_NO_CONSOLE             = 0x00008000
SEE_MASK_ASYNCOK                = 0x00100000
SEE_MASK_HMONITOR               = 0x00200000
SEE_MASK_NOZONECHECKS           = 0x00800000
SEE_MASK_NOQUERYCLASSSTORE      = 0x01000000
SEE_MASK_WAITFORINPUTIDLE       = 0x02000000
SEE_MASK_FLAG_LOG_USAGE         = 0x04000000

struc SHELLEXECUTEINFO {
  .:
  .cbSize       dd ?
  .fMask        dd ? 
  .hwnd         dd ? 
  .lpVerb       dd ? 
  .lpFile       dd ? 
  .lpParameters dd ? 
  .lpDirectory  dd ? 
  .nShow        dd ? 
  .hInstApp     dd ? 
  .lpIDList     dd ? 
  .lpClass      dd ? 
  .hkeyClass    dd ? 
  .dwHotKey     dd ? 
  label .hIcon dword 
  .hMonitor     dd ? 
  .hProcess     dd ? 
  .. = $ - . 

  ; Requests the OS to run the executable elevated.
  ; Returns TRUE if successful, or FALSE otherwise.
  ; If FALSE then return error information in edx
  macro .RunElevated \{
    \local ..okay
    invoke RtlZeroMemory,.,..
    invoke  GetProcessHeap
    mov     [_hheap],eax
    invoke  HeapAlloc,[_hheap],HEAP_ZERO_MEMORY,1000h
    mov     [.lpFile],eax
    invoke  HeapAlloc,[_hheap],HEAP_ZERO_MEMORY,1000h
    mov     [.lpParameters],eax
    call    GetMainArgs
    mov     esi,[_argv]
    mov     ebx,[_argc]
    add     esi,4
    dec     ebx
    cmp     ebx,0
    jz      ..okay
    cinvoke wsprintf,[.lpFile],_fm,dword[esi]
    add     esi,4
    dec     ebx
    cmp     ebx,0
    jz      run
    @@:
        cinvoke wsprintf,[.lpParameters],_fmt,[.lpParameters],dword[esi]
        add     esi,4
        dec     ebx
        cmp     ebx,0
        jnz     @b
    run:
    mov [.cbSize],..
    mov [.hwnd],0
    mov [.fMask],SEE_MASK_FLAG_DDEWAIT or SEE_MASK_FLAG_NO_UI
    mov [.lpVerb],_runas
    mov [.nShow],SW_SHOWNORMAL
    invoke ShellExecuteEx,.
    test eax,eax
    jnz ..okay
    invoke GetLastError
    mov edx, eax
    xor eax, eax
    ..okay:
    invoke  HeapFree,[_hheap],0,[_argv]
    invoke  HeapFree,[_hheap],0,[.lpFile]
    invoke  HeapFree,[_hheap],0,[.lpParameters]
  \}
}

  _runas   db 'runas',0
  ;_notepad db 'notepad.exe',0
  ;_test    db 'w32.semiono.asm',0

  align 4

  sei SHELLEXECUTEINFO

start:

        sei.RunElevated

        invoke  ExitProcess,0

.end start