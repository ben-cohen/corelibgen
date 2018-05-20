#######################################################################
# library: example library with Call Frame Information
#
# Compile using:
#     gcc -Wl,-soname,library.x86_64.so -shared -fPIC \
#         -o library.x86_64.so library.x86_64.S
#
         .text
.globl library_function
         .type   library_function, @function
library_function:
         .cfi_startproc
         pushq    %rbp
         .cfi_def_cfa_offset 8
         .cfi_offset %rbp, -8
         movq     $0x0, %rbp
         subq     $0x12345678,%rsp
         .cfi_adjust_cfa_offset  0x12345678
         int     $0x03
         addq     $0x12345678,%rsp
         .cfi_adjust_cfa_offset  -0x12345678
         popq     %rbp
         ret
         .cfi_endproc
         .size   library_function, .-library_function
         .section        .note.GNU-stack,"",@progbits

