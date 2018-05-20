#######################################################################
# library: example library with Call Frame Information
#
# Compile using:
#     gcc -Wl,-soname,library-i386.so -shared -fPIC \
#         -o library-i386.so library-i386.S
#
         .text
.globl library_function
         .type   library_function, @function
library_function:
         .cfi_startproc
         push    %ebp
         .cfi_def_cfa_offset 8
         .cfi_offset %ebp, -8
         mov     $0x0, %ebp
         sub     $0x80000000,%esp
         .cfi_adjust_cfa_offset  0x80000000
         int     $0x03
         add     $0x80000000,%esp
         .cfi_adjust_cfa_offset  -0x80000000
         pop     %ebp
         ret
         .cfi_endproc
         .size   library_function, .-library_function
         .section        .note.GNU-stack,"",@progbits

