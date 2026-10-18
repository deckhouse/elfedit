.text
.byte 0
.globl spec_group
.set spec_group, 1
.section .merge,"MS",@progbits,1
.asciz "original"
.section .note.test,"G",@note,spec_group,comdat
.balign 4
.long 8, 4, 1
.asciz "example"
.long 42
