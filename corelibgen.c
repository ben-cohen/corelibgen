/**********************************************************************
 * corelibgen: Generate stub libraries with CFI for ELF corefiles
 *
 * Copyright (C) 2010-2013 Ben Cohen / Kognitio Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Compile using:
 *     gcc -o corelibgen corelibgen.c -Wall
 * Run using:
 *     corelibgen -f <target-dir> <core-file>
 *     gdb --ex 'set solib-search-path <target-dir>/lib' \
 *         --ex 'set sysroot <target-dir>' \
 *         --ex 'file <exec-file>' \
 *         --ex 'core <core-file>'
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

#include <elf.h>

int debug = 0;

void check(bool cond, char *msg)
{
     if (!cond)
     {
         fprintf(stderr, "%s", msg);
         exit(1);
     }
}

void *xmalloc(int size)
{
     void *ret = malloc(size);

     check(ret != NULL, "malloc() failed");
     return ret;
}


void readat(int fd, void *buf, size_t count, size_t offset)
{
     size_t ret;
     size_t bytes_read = 0;

     ret = lseek(fd, offset, SEEK_SET);
     check(offset == ret, "lseek() failed\n");

     while (bytes_read < count)
     {
         ret = read(fd, buf + bytes_read, count - bytes_read);
         check(ret > 0, "read() failed\n");
         bytes_read += ret;
     }
}

bool memreadat(char *segment, int segsz, void *buf, size_t count,
                size_t offset)
{
     if (count + offset > segsz)
         return false;
     memcpy(buf, segment + offset, count);
     return true;
}


/* We create a stub library.  This is more complicated than the minimal
  * ELF library, but GDB is a little fussy. */
void CreateStubLibrary32(char *libname, 
                         Elf32_Half machine,
                         uint32_t eh_frame_offset,
                         char *eh_frame,
                         uint32_t eh_frame_len,
                         Elf32_Addr LoadOffset)
{
     int libfd;
     int nSecs = 3;
     Elf32_Ehdr ElfHeader;
     Elf32_Phdr ProgHeader;
     Elf32_Shdr SecHeader[nSecs];
     int EHSize = sizeof(Elf32_Ehdr);
     int PHSize = sizeof(Elf32_Phdr);
     int SHSize = sizeof(Elf32_Shdr);
     char *eh_frame_str = ".eh_frame";
     char *shstrtab_str = ".shstrtab";
     int eh_frame_strlen = strlen(eh_frame_str) + 1;
     int shstrtab_strlen = strlen(shstrtab_str) + 1;
     uint32_t shstrtab_offset = eh_frame_offset + eh_frame_len;
     uint32_t shstrtab_len = eh_frame_strlen + shstrtab_strlen;
     uint32_t EH_offset = shstrtab_offset + shstrtab_len;
     int rc;

     printf("Creating stub library %s\n", libname);
     libfd = open(libname, O_WRONLY|O_CREAT, 0555);
     if (libfd < 0)
     {
         printf("Failed to open file\n");
         return;
     }

     /* Write the ELF header */
     memset(&ElfHeader, 0, EHSize);

     ElfHeader.e_ident[0] = ELFMAG0;
     ElfHeader.e_ident[1] = ELFMAG1;
     ElfHeader.e_ident[2] = ELFMAG2;
     ElfHeader.e_ident[3] = ELFMAG3;
     ElfHeader.e_ident[4] = ELFCLASS32;
     ElfHeader.e_ident[5] = ELFDATA2LSB;
     ElfHeader.e_ident[6] = EV_CURRENT;
     ElfHeader.e_type = ET_DYN;
     ElfHeader.e_machine = machine;
     ElfHeader.e_version = EV_CURRENT;
     ElfHeader.e_entry = 0;
     ElfHeader.e_phoff = EHSize;
     ElfHeader.e_shoff = EH_offset;
     ElfHeader.e_flags = 0;
     ElfHeader.e_ehsize = EHSize;
     ElfHeader.e_phentsize = PHSize;
     ElfHeader.e_phnum = 1;
     ElfHeader.e_shentsize = SHSize;
     ElfHeader.e_shnum = nSecs;
     ElfHeader.e_shstrndx = 2;

     rc = write(libfd, &ElfHeader, EHSize);
     if (rc != EHSize)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the program header */
     memset(&ProgHeader, 0, PHSize);

     ProgHeader.p_type = PT_LOAD;
     ProgHeader.p_offset = 0;
     ProgHeader.p_vaddr = LoadOffset;
     ProgHeader.p_paddr = LoadOffset;
     ProgHeader.p_filesz = EH_offset;
     ProgHeader.p_memsz = ProgHeader.p_filesz;
     ProgHeader.p_flags = PF_X | PF_R;
     ProgHeader.p_align = 0x1000;

     rc = write(libfd, &ProgHeader, PHSize * 1);
     if (rc != PHSize * 1)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the .eh_frame section at its original location */
     check(eh_frame_offset > EHSize + PHSize * 1,
           "eh_frame_offset too small\n");
     rc = lseek(libfd, eh_frame_offset, SEEK_SET);
     if (rc != eh_frame_offset)
     {
         printf("Failed to seek\n");
         close(libfd);
         return;
     }
     rc = write(libfd, eh_frame, eh_frame_len);
     if (rc != eh_frame_len)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the section string table, .shstrtab */
     rc = write(libfd, shstrtab_str, shstrtab_strlen);
     if (rc != shstrtab_strlen)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }
     rc = write(libfd, eh_frame_str, eh_frame_strlen);
     if (rc != eh_frame_strlen)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the section headers */
     memset(&SecHeader, 0, SHSize * nSecs);

     SecHeader[0].sh_name = shstrtab_strlen - 1;
     SecHeader[0].sh_type = SHT_NULL;          /* First one: empty */

     SecHeader[1].sh_name = shstrtab_strlen;  /* Third one: .eh_frame */
     SecHeader[1].sh_type = SHT_PROGBITS;
     SecHeader[1].sh_flags = SHF_ALLOC;
     SecHeader[1].sh_addr = eh_frame_offset + LoadOffset;
     SecHeader[1].sh_offset = eh_frame_offset;
     SecHeader[1].sh_size = eh_frame_len;
     SecHeader[1].sh_link = 0;
     SecHeader[1].sh_info = 0;
     SecHeader[1].sh_addralign = 4;
     SecHeader[1].sh_entsize = 0;

     SecHeader[2].sh_name = 0;              /* Second one: .shstrtab */
     SecHeader[2].sh_type = SHT_STRTAB;
     SecHeader[2].sh_flags = 0;
     SecHeader[2].sh_addr = 0;
     SecHeader[2].sh_offset = shstrtab_offset;
     SecHeader[2].sh_size = shstrtab_len;
     SecHeader[2].sh_link = 0;
     SecHeader[2].sh_info = 0;
     SecHeader[2].sh_addralign = 1;
     SecHeader[2].sh_entsize = 0;

     rc = write(libfd, &SecHeader, SHSize * nSecs);
     if (rc != SHSize * nSecs)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     close(libfd);
}

void CreateStubLibrary64(char *libname,
                         Elf64_Half machine,
                         uint64_t eh_frame_offset,
                         char *eh_frame,
                         uint64_t eh_frame_len,
                         Elf64_Addr LoadOffset)
{
     int libfd;
     int nSecs = 3;
     Elf64_Ehdr ElfHeader;
     Elf64_Phdr ProgHeader;
     Elf64_Shdr SecHeader[nSecs];
     int EHSize = sizeof(Elf64_Ehdr);
     int PHSize = sizeof(Elf64_Phdr);
     int SHSize = sizeof(Elf64_Shdr);
     char *eh_frame_str = ".eh_frame";
     char *shstrtab_str = ".shstrtab";
     int eh_frame_strlen = strlen(eh_frame_str) + 1;
     int shstrtab_strlen = strlen(shstrtab_str) + 1;
     uint64_t shstrtab_offset = eh_frame_offset + eh_frame_len;
     uint64_t shstrtab_len = eh_frame_strlen + shstrtab_strlen;
     uint64_t EH_offset = shstrtab_offset + shstrtab_len;
     int rc;

     printf("Creating stub library %s\n", libname);
     libfd = open(libname, O_WRONLY|O_CREAT, 0555);
     if (libfd < 0)
     {
         printf("Failed to open file\n");
         return;
     }

     /* Write the ELF header */
     memset(&ElfHeader, 0, EHSize);

     ElfHeader.e_ident[0] = ELFMAG0;
     ElfHeader.e_ident[1] = ELFMAG1;
     ElfHeader.e_ident[2] = ELFMAG2;
     ElfHeader.e_ident[3] = ELFMAG3;
     ElfHeader.e_ident[4] = ELFCLASS64;
     ElfHeader.e_ident[5] = ELFDATA2LSB;
     ElfHeader.e_ident[6] = EV_CURRENT;
     ElfHeader.e_type = ET_DYN;
     ElfHeader.e_machine = machine;
     ElfHeader.e_version = EV_CURRENT;
     ElfHeader.e_entry = 0;
     ElfHeader.e_phoff = EHSize;
     ElfHeader.e_shoff = EH_offset;
     ElfHeader.e_flags = 0;
     ElfHeader.e_ehsize = EHSize;
     ElfHeader.e_phentsize = PHSize;
     ElfHeader.e_phnum = 1;
     ElfHeader.e_shentsize = SHSize;
     ElfHeader.e_shnum = nSecs;
     ElfHeader.e_shstrndx = 2;

     rc = write(libfd, &ElfHeader, EHSize);
     if (rc != EHSize)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the program header */
     memset(&ProgHeader, 0, PHSize);

     ProgHeader.p_type = PT_LOAD;
     ProgHeader.p_offset = 0;
     ProgHeader.p_vaddr = LoadOffset;
     ProgHeader.p_paddr = LoadOffset;
     ProgHeader.p_filesz = EH_offset;
     ProgHeader.p_memsz = ProgHeader.p_filesz;
     ProgHeader.p_flags = PF_X | PF_R;
     ProgHeader.p_align = 0x1000;

     rc = write(libfd, &ProgHeader, PHSize * 1);
     if (rc != PHSize * 1)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the .eh_frame section at its original location */
     check(eh_frame_offset > EHSize + PHSize * 1,
           "eh_frame_offset too small\n");
     rc = lseek(libfd, eh_frame_offset, SEEK_SET);
     if (rc != eh_frame_offset)
     {
         printf("Failed to seek\n");
         close(libfd);
         return;
     }
     rc = write(libfd, eh_frame, eh_frame_len);
     if (rc != eh_frame_len)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the section string table, .shstrtab */
     rc = write(libfd, shstrtab_str, shstrtab_strlen);
     if (rc != shstrtab_strlen)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }
     rc = write(libfd, eh_frame_str, eh_frame_strlen);
     if (rc != eh_frame_strlen)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     /* Write the section headers */
     memset(&SecHeader, 0, SHSize * nSecs);

     SecHeader[0].sh_name = shstrtab_strlen - 1;
     SecHeader[0].sh_type = SHT_NULL;          /* First one: empty */

     SecHeader[1].sh_name = shstrtab_strlen;  /* Third one: .eh_frame */
     SecHeader[1].sh_type = SHT_PROGBITS;
     SecHeader[1].sh_flags = SHF_ALLOC;
     SecHeader[1].sh_addr = eh_frame_offset + LoadOffset;
     SecHeader[1].sh_offset = eh_frame_offset;
     SecHeader[1].sh_size = eh_frame_len;
     SecHeader[1].sh_link = 0;
     SecHeader[1].sh_info = 0;
     SecHeader[1].sh_addralign = 4;
     SecHeader[1].sh_entsize = 0;

     SecHeader[2].sh_name = 0;              /* Second one: .shstrtab */
     SecHeader[2].sh_type = SHT_STRTAB;
     SecHeader[2].sh_flags = 0;
     SecHeader[2].sh_addr = 0;
     SecHeader[2].sh_offset = shstrtab_offset;
     SecHeader[2].sh_size = shstrtab_len;
     SecHeader[2].sh_link = 0;
     SecHeader[2].sh_info = 0;
     SecHeader[2].sh_addralign = 1;
     SecHeader[2].sh_entsize = 0;

     rc = write(libfd, &SecHeader, SHSize * nSecs);
     if (rc != SHSize * nSecs)
     {
         printf("Failed to write to file\n");
         close(libfd);
         return;
     }

     close(libfd);
}

void ProcessEhFrameHdr32(char *segment, int size, Elf32_Half machine,
                         char *eh_frame_hdr, Elf32_Xword ehsize,
                         char *libname, Elf32_Addr LoadOffset)
{
     signed int eh_frame_ptr;
     int fde_count;
     char *eh_frame;
     int32_t eh_frame_len;
     char *eh_frame_end;
     int fdes_counted;

     if (debug)
     {
         printf("Object eh_frame_hdr:\n");
         printf("    version:            %d\n", eh_frame_hdr[0]);
         printf("    eh_frame_ptr_enc:   %d\n", eh_frame_hdr[1]);
         printf("    fde_count_enc:      %d\n", eh_frame_hdr[2]);
         printf("    table_enc:          %d\n", eh_frame_hdr[3]);
     }
     if (eh_frame_hdr[0] != 1)
     {
         if (debug)
             printf("Bad eh_frame_hdr version\n");
         return;
     }

     /* XXX I can't be bothered to implement them all unless
      * necessary */
     check((eh_frame_hdr[1] & 0xF0) == 0x10,
           "eh_frame_ptr not relative to pc\n");
     check((eh_frame_hdr[1] & 0x0F) == 0x0b,
           "eh_frame_ptr not signed int\n");
     check(eh_frame_hdr[2] == 0x03, "fde_count_enc not unsigned int\n");
     eh_frame_ptr = ((int *)eh_frame_hdr)[1];
     fde_count = ((int *)eh_frame_hdr)[2];
     if (fde_count == 0)
     {
         if (debug)
             printf("No fde search table\n");
         return;
     }

     eh_frame = eh_frame_hdr + eh_frame_ptr + 4;
     if (debug)
     {
         printf("    eh_frame_ptr:       %d\n", eh_frame_ptr);
         printf("    eh_frame:           %" PRIxPTR "\n", eh_frame - segment);
         printf("    fde_count:          %d\n", fde_count);
     }
     check(eh_frame <= segment + size, "eh_frame not in segment\n");

     /* Frame length is that of all the FDEs plus a zero int at the
      * end */
     fdes_counted = 0;
     eh_frame_end = eh_frame;
     while (((int *)eh_frame_end)[0] != 0 && fdes_counted < fde_count)
     {
         if (((int *)eh_frame_end)[1] != 0)
         {
             fdes_counted ++;
             if (debug)
             {
                 printf("    FDE:                %d at %" PRIxPTR "\n",
                        ((int *)eh_frame_end)[0],
                        eh_frame_end - segment);
             }
         }
         else
         {
             if (debug)
             {
                 printf("    CIE:                %d at %" PRIxPTR "\n",
                        ((int *)eh_frame_end)[0],
                        eh_frame_end - segment);
             }
         }
         eh_frame_end += ((int *)eh_frame_end)[0] + 4;
         check(eh_frame_end <= segment + size,
               "eh_frame not in segment\n");
     }
     eh_frame_end += 4;
     check(eh_frame_end <= segment + size, "eh_frame not in segment\n");

     eh_frame_len = eh_frame_end - eh_frame;

     if (debug)
     {
         printf("    eh_frame_end:       %" PRIxPTR "\n",
                eh_frame_end - segment);
         printf("    eh_frame_len:       %" PRId32 "\n", eh_frame_len);
         printf("    fdes_counted:       %d\n", fdes_counted);
     }

     if (strncmp(libname, "ld-linux.so", 11) != 0)
     {
         CreateStubLibrary32(libname, machine, eh_frame - segment, eh_frame,
                             eh_frame_len, LoadOffset);
     }
     else
     {
         if (debug)
         {
             printf("Not creating stub library for %s\n", libname);
         }
     }
}

void ProcessEhFrameHdr64(char *segment, int size, Elf64_Half machine,
                         char *eh_frame_hdr, Elf64_Xword ehsize,
                         char *libname, Elf64_Addr LoadOffset)
{
     signed int eh_frame_ptr;
     int fde_count;
     char *eh_frame;
     uint64_t eh_frame_len;
     char *eh_frame_end;
     int fdes_counted;

     if (debug)
     {
         printf("Object eh_frame_hdr:\n");
         printf("    version:            %d\n", eh_frame_hdr[0]);
         printf("    eh_frame_ptr_enc:   %d\n", eh_frame_hdr[1]);
         printf("    fde_count_enc:      %d\n", eh_frame_hdr[2]);
         printf("    table_enc:          %d\n", eh_frame_hdr[3]);
     }
     if (eh_frame_hdr[0] != 1)
     {
         if (debug)
             printf("Bad eh_frame_hdr version\n");
         return;
     }

     /* XXX I can't be bothered to implement them all unless
      * necessary */
     check((eh_frame_hdr[1] & 0xF0) == 0x10,
           "eh_frame_ptr not relative to pc\n");
     check((eh_frame_hdr[1] & 0x0F) == 0x0b,
           "eh_frame_ptr not signed int\n");
     check(eh_frame_hdr[2] == 0x03, "fde_count_enc not unsigned int\n");
     eh_frame_ptr = ((int *)eh_frame_hdr)[1];
     fde_count = ((int *)eh_frame_hdr)[2];
     if (fde_count == 0)
     {
         if (debug)
             printf("No fde search table\n");
         return;
     }

     eh_frame = eh_frame_hdr + eh_frame_ptr + 4;
     if (debug)
     {
         printf("    eh_frame_ptr:       %d\n", eh_frame_ptr);
         printf("    eh_frame:           %" PRIxPTR "\n", eh_frame - segment);
         printf("    fde_count:          %d\n", fde_count);
     }
     check(eh_frame <= segment + size, "eh_frame not in segment\n");

     /* Frame length is that of all the FDEs plus a zero int at the
      * end */
     fdes_counted = 0;
     eh_frame_end = eh_frame;
     while (((int *)eh_frame_end)[0] != 0 && fdes_counted < fde_count)
     {
         if (((int *)eh_frame_end)[1] != 0)
         {
             fdes_counted ++;
             if (debug)
             {
                 printf("    FDE:                %d at %" PRIxPTR "\n",
                        ((int *)eh_frame_end)[0],
                        eh_frame_end - segment);
             }
         }
         else
         {
             if (debug)
             {
                 printf("    CIE:                %d at %" PRIxPTR "\n",
                        ((int *)eh_frame_end)[0],
                        eh_frame_end - segment);
             }
         }
         eh_frame_end += ((int *)eh_frame_end)[0] + 4;
         check(eh_frame_end <= segment + size,
               "eh_frame not in segment\n");
     }
     eh_frame_end += 4;
     check(eh_frame_end <= segment + size, "eh_frame not in segment\n");

     eh_frame_len = eh_frame_end - eh_frame;

     if (debug)
     {
         printf("    eh_frame_end:       %" PRIxPTR "\n",
                eh_frame_end - segment);
         printf("    eh_frame_len:       %" PRId64 "\n", eh_frame_len);
         printf("    fdes_counted:       %d\n", fdes_counted);
     }

     if (strncmp(libname, "ld-linux.so", 11) != 0)
     {
         CreateStubLibrary64(libname, machine, eh_frame - segment, eh_frame,
                             eh_frame_len, LoadOffset);
     }
     else
     {
         if (debug)
         {
             printf("Not creating stub library for %s\n", libname);
         }
     }
}

void ProcessObject32(char *segment,
                     Elf32_Xword size,
                     char *libname,
                     Elf32_Half machine)
{
     Elf32_Ehdr ElfHeader;
     Elf32_Off PHOffset;
     Elf32_Half PHCount;
     Elf32_Phdr ProgHeader;
     bool ret;
     int i;
     Elf32_Addr LoadOffset = 0;
     Elf32_Off EhFrameOffset = 0;
     Elf32_Xword EhFrameSize = 0;

     ret = memreadat(segment, size, (void *)&ElfHeader,
                     sizeof(ElfHeader), 0);
     if (!ret)
         return;
     if (debug)
     {
         printf("Object ELF Header:\n");
         printf("    e_ident:        %.16s\n", ElfHeader.e_ident);
         printf("    e_type:         %d\n", ElfHeader.e_type);
         printf("    e_machine:      %d\n", ElfHeader.e_machine);
         printf("    e_version:      %d\n", ElfHeader.e_version);
         printf("    e_entry:        %d\n", ElfHeader.e_entry);
         printf("    e_phoff:        %d\n", ElfHeader.e_phoff);
         printf("    e_shoff:        %d\n", ElfHeader.e_shoff);
         printf("    e_flags:        %d\n", ElfHeader.e_flags);
         printf("    e_ehsize:       %d\n", ElfHeader.e_ehsize);
         printf("    e_phentsize:    %d\n", ElfHeader.e_phentsize);
         printf("    e_phnum:        %d\n", ElfHeader.e_phnum);
         printf("    e_shentsize:    %d\n", ElfHeader.e_shentsize);
         printf("    e_shnum:        %d\n", ElfHeader.e_shnum);
         printf("    e_shstrndx:     %d\n", ElfHeader.e_shstrndx);
     }
     if (memcmp(ELFMAG, ElfHeader.e_ident, SELFMAG) != 0)
     {
         if (debug)
             printf("Bad ELF header magic number\n");
         return;
     }
     if (ElfHeader.e_type != ET_DYN)
     {
         if (debug)
             printf("Not a shared object\n");
         return;
     }
     //check(ElfHeader.e_machine == EM_386, "Bad ELF architecture\n");
     check(ElfHeader.e_version == EV_CURRENT, "Bad ELF version\n");
     check(ElfHeader.e_phoff >= ElfHeader.e_ehsize,
           "Bad program header offset\n");
     check(ElfHeader.e_phentsize == sizeof(ProgHeader),
           "Bad program header size\n");
     PHOffset = ElfHeader.e_phoff;
     PHCount = ElfHeader.e_phnum;

     for (i = 0; i < PHCount; i ++)
     {
         /* Get the i-th program header; we are interested in the
          * eh_frame_hdr section */
         ret = memreadat(segment,
                         size,
                         &ProgHeader,
                         sizeof(ProgHeader),
                         PHOffset + i * sizeof(ProgHeader));
         if (!ret)
             return;
         if (debug)
         {
             printf("Object Program Header:\n");
             printf("    p_type:         %d\n", ProgHeader.p_type);
             printf("    p_offset:       %d\n", ProgHeader.p_offset);
             printf("    p_vaddr:        %d\n", ProgHeader.p_vaddr);
             printf("    p_paddr:        %d\n", ProgHeader.p_paddr);
             printf("    p_filesz:       %d\n", ProgHeader.p_filesz);
             printf("    p_memsz:        %d\n", ProgHeader.p_memsz);
             printf("    p_flags:        %d\n", ProgHeader.p_flags);
             printf("    p_align:        %d\n", ProgHeader.p_align);
         }

         if (ProgHeader.p_type == PT_LOAD && ProgHeader.p_offset == 0)
         {
             LoadOffset = ProgHeader.p_vaddr;
             if (debug)
             {
                 printf("Found load offset 0x%x\n", LoadOffset);
             }
         }

         if (ProgHeader.p_type == PT_GNU_EH_FRAME)
         {
             check(EhFrameSize == 0,
                   "Multiple PT_GNU_EH_FRAME program sections\n");

             EhFrameOffset = ProgHeader.p_offset;
             EhFrameSize   = ProgHeader.p_filesz;
         }
     }

     if (EhFrameSize > 0)
     {
         char *ehsegment = xmalloc(EhFrameSize);
         ret = memreadat(segment, size, ehsegment,
                         EhFrameSize,
                         EhFrameOffset);
         if (ret)
             ProcessEhFrameHdr32(segment,
                                 size,
                                 machine,
                                 segment + EhFrameOffset,
                                 EhFrameSize,
                                 libname,
                                 LoadOffset);
         free(ehsegment);
     }
}

void ProcessObject64(char *segment,
                     Elf64_Xword size,
                     char *libname,
                     Elf64_Half machine)
{
     Elf64_Ehdr ElfHeader;
     Elf64_Off PHOffset;
     Elf64_Half PHCount;
     Elf64_Phdr ProgHeader;
     bool ret;
     int i;
     Elf64_Addr LoadOffset = 0;
     Elf64_Off EhFrameOffset = 0;
     Elf64_Xword EhFrameSize = 0;

     ret = memreadat(segment, size, (void *)&ElfHeader,
                     sizeof(ElfHeader), 0);
     if (!ret)
         return;
     if (debug)
     {
         printf("Object ELF Header:\n");
         printf("    e_ident:        %.16s\n", ElfHeader.e_ident);
         printf("    e_type:         %d\n", ElfHeader.e_type);
         printf("    e_machine:      %d\n", ElfHeader.e_machine);
         printf("    e_version:      %d\n", ElfHeader.e_version);
         printf("    e_entry:        %" PRIxPTR "\n", ElfHeader.e_entry);
         printf("    e_phoff:        %" PRIxPTR "\n", ElfHeader.e_phoff);
         printf("    e_shoff:        %" PRIxPTR "\n", ElfHeader.e_shoff);
         printf("    e_flags:        %d\n", ElfHeader.e_flags);
         printf("    e_ehsize:       %d\n", ElfHeader.e_ehsize);
         printf("    e_phentsize:    %d\n", ElfHeader.e_phentsize);
         printf("    e_phnum:        %d\n", ElfHeader.e_phnum);
         printf("    e_shentsize:    %d\n", ElfHeader.e_shentsize);
         printf("    e_shnum:        %d\n", ElfHeader.e_shnum);
         printf("    e_shstrndx:     %d\n", ElfHeader.e_shstrndx);
     }
     if (memcmp(ELFMAG, ElfHeader.e_ident, SELFMAG) != 0)
     {
         if (debug)
             printf("Bad ELF header magic number\n");
         return;
     }
     if (ElfHeader.e_type != ET_DYN)
     {
         if (debug)
             printf("Not a shared object\n");
         return;
     }
     //check(ElfHeader.e_machine == EM_X86_64, "Bad ELF architecture\n");
     check(ElfHeader.e_version == EV_CURRENT, "Bad ELF version\n");
     check(ElfHeader.e_phoff >= ElfHeader.e_ehsize,
           "Bad program header offset\n");
     check(ElfHeader.e_phentsize == sizeof(ProgHeader),
           "Bad program header size\n");
     PHOffset = ElfHeader.e_phoff;
     PHCount = ElfHeader.e_phnum;

     for (i = 0; i < PHCount; i ++)
     {
         /* Get the i-th program header; we are interested in the
          * eh_frame_hdr section */
         ret = memreadat(segment,
                         size,
                         &ProgHeader,
                         sizeof(ProgHeader),
                         PHOffset + i * sizeof(ProgHeader));
         if (!ret)
             return;
         if (debug)
         {
             printf("Object Program Header:\n");
             printf("    p_type:         %d\n", ProgHeader.p_type);
             printf("    p_offset:       %" PRId64 "\n", ProgHeader.p_offset);
             printf("    p_vaddr:        %" PRIxPTR "\n", ProgHeader.p_vaddr);
             printf("    p_paddr:        %" PRIxPTR "\n", ProgHeader.p_paddr);
             printf("    p_filesz:       %" PRId64 "\n", ProgHeader.p_filesz);
             printf("    p_memsz:        %" PRId64 "\n", ProgHeader.p_memsz);
             printf("    p_flags:        %d\n", ProgHeader.p_flags);
             printf("    p_align:        %" PRId64 "\n", ProgHeader.p_align);
         }

         if (ProgHeader.p_type == PT_LOAD && ProgHeader.p_offset == 0)
         {
             LoadOffset = ProgHeader.p_vaddr;
             if (debug)
             {
                 printf("Found load offset 0x%" PRId64 "\n", LoadOffset);
             }
         }

         if (ProgHeader.p_type == PT_GNU_EH_FRAME)
         {
             check(EhFrameSize == 0,
                   "Multiple PT_GNU_EH_FRAME program sections\n");

             EhFrameOffset = ProgHeader.p_offset;
             EhFrameSize   = ProgHeader.p_filesz;
         }
     }

     if (EhFrameSize > 0)
     {
         char *ehsegment = xmalloc(EhFrameSize);
         ret = memreadat(segment, size, ehsegment,
                         EhFrameSize,
                         EhFrameOffset);
         if (ret)
             ProcessEhFrameHdr64(segment,
                                 size,
                                 machine,
                                 segment + EhFrameOffset,
                                 EhFrameSize,
                                 libname,
                                 LoadOffset);
         free(ehsegment);
     }
}

char *GuessLibName(char *segment, int size)
{
     char *first_GLIBC;
     char *this_string;
     char *prev_string;
     int  retries;

     first_GLIBC = (char *)memmem(segment, size, "\0GLIBC_", 7);
     if (first_GLIBC == NULL)
         return NULL;
     this_string = first_GLIBC;

     for (retries = 0; retries < 15; retries ++)
     {
         for (prev_string = this_string - 1;
              prev_string > segment && *prev_string != '\0';
              prev_string --)
         {
             if (!isgraph(*prev_string))
                 return NULL;
             /* arbitrary max len */
             if (this_string - prev_string > 128)
                 return NULL;
         }

         if (memcmp(prev_string + 1, "lib", 3) == 0 ||
             memcmp(prev_string + 1, "ld-linux.so", 11) == 0)
         {
             char *ret = xmalloc(this_string - prev_string);
             memcpy(ret, prev_string + 1, this_string - prev_string);
             return ret;
         }

         this_string = prev_string;
     }

     return NULL;
}

void extract_cfi_32(int corefd)
{
     Elf32_Ehdr ElfHeader;
     Elf32_Off PHOffset;
     Elf32_Half PHCount;
     Elf32_Phdr ProgHeader;
     int i;

     /* Get the corefile ELF header */
     readat(corefd, (void *)&ElfHeader, sizeof(ElfHeader), 0);
     if (debug)
     {
         printf("Corefile ELF Header:\n");
         printf("    e_ident:        %.16s\n", ElfHeader.e_ident);
         printf("    e_type:         %d\n", ElfHeader.e_type);
         printf("    e_machine:      %d\n", ElfHeader.e_machine);
         printf("    e_version:      %d\n", ElfHeader.e_version);
         printf("    e_entry:        %d\n", ElfHeader.e_entry);
         printf("    e_phoff:        %d\n", ElfHeader.e_phoff);
         printf("    e_shoff:        %d\n", ElfHeader.e_shoff);
         printf("    e_flags:        %d\n", ElfHeader.e_flags);
         printf("    e_ehsize:       %d\n", ElfHeader.e_ehsize);
         printf("    e_phentsize:    %d\n", ElfHeader.e_phentsize);
         printf("    e_phnum:        %d\n", ElfHeader.e_phnum);
         printf("    e_shentsize:    %d\n", ElfHeader.e_shentsize);
         printf("    e_shnum:        %d\n", ElfHeader.e_shnum);
         printf("    e_shstrndx:     %d\n", ElfHeader.e_shstrndx);
     }
     check(memcmp(ELFMAG, ElfHeader.e_ident, SELFMAG) == 0,
           "Bad ELF header magic number\n");
     check(ElfHeader.e_type == ET_CORE, "Bad ELF object file type\n");
     // check(ElfHeader.e_machine == EM_386, "Bad ELF architecture\n");
     check(ElfHeader.e_version == EV_CURRENT, "Bad ELF version\n");
     check(ElfHeader.e_phoff >= ElfHeader.e_ehsize,
           "Bad program header offset\n");
     check(ElfHeader.e_phentsize == sizeof(ProgHeader),
           "Bad program header size\n");
     PHOffset = ElfHeader.e_phoff;
     PHCount = ElfHeader.e_phnum;

     for (i = 0; i < PHCount; i ++)
     {
         /* Get the i-th program header; we are interested in loadXX
          * sections */
         readat(corefd,
                &ProgHeader,
                sizeof(ProgHeader),
                PHOffset + i * sizeof(ProgHeader));
         if (debug)
         {
             printf("Corefile Program Header:\n");
             printf("    p_type:         %d\n", ProgHeader.p_type);
             printf("    p_offset:       %d\n", ProgHeader.p_offset);
             printf("    p_vaddr:        %d\n", ProgHeader.p_vaddr);
             printf("    p_paddr:        %d\n", ProgHeader.p_paddr);
             printf("    p_filesz:       %d\n", ProgHeader.p_filesz);
             printf("    p_memsz:        %d\n", ProgHeader.p_memsz);
             printf("    p_flags:        %d\n", ProgHeader.p_flags);
             printf("    p_align:        %d\n", ProgHeader.p_align);
         }
         if (ProgHeader.p_type == PT_LOAD)
         {
             char *segment = xmalloc(ProgHeader.p_filesz);

             /* Read the section.  If it starts with an ELF header then
              * it's (almost certainly) the start of an object */
             readat(corefd, segment, ProgHeader.p_filesz,
                    ProgHeader.p_offset);
             if (memcmp(ELFMAG, segment, SELFMAG) == 0)
             {
                 char *libname = GuessLibName(segment,
                                              ProgHeader.p_filesz);
                 if (libname == NULL)
                 {
                     libname = xmalloc(40);
                     snprintf(libname, 40, "libunknown_%d", i);
                 }
                 if (debug)
                 {
                     printf("Guessed library name %s\n", libname);
                 }
                 ProcessObject32(segment,
                                 ProgHeader.p_filesz,
                                 libname,
                                 ElfHeader.e_machine);
                 free(libname);
             }
             free(segment);
         }
     }
}

void extract_cfi_64(int corefd)
{
     Elf64_Ehdr ElfHeader;
     Elf64_Off PHOffset;
     Elf64_Half PHCount;
     Elf64_Phdr ProgHeader;
     int i;

     /* Get the corefile ELF header */
     readat(corefd, (void *)&ElfHeader, sizeof(ElfHeader), 0);
     if (debug)
     {
         printf("Corefile ELF Header:\n");
         printf("    e_ident:        %.16s\n", ElfHeader.e_ident);
         printf("    e_type:         %d\n", ElfHeader.e_type);
         printf("    e_machine:      %d\n", ElfHeader.e_machine);
         printf("    e_version:      %d\n", ElfHeader.e_version);
         printf("    e_entry:        %" PRIxPTR "\n", ElfHeader.e_entry);
         printf("    e_phoff:        %" PRIxPTR "\n", ElfHeader.e_phoff);
         printf("    e_shoff:        %" PRIxPTR "\n", ElfHeader.e_shoff);
         printf("    e_flags:        %d\n", ElfHeader.e_flags);
         printf("    e_ehsize:       %d\n", ElfHeader.e_ehsize);
         printf("    e_phentsize:    %d\n", ElfHeader.e_phentsize);
         printf("    e_phnum:        %d\n", ElfHeader.e_phnum);
         printf("    e_shentsize:    %d\n", ElfHeader.e_shentsize);
         printf("    e_shnum:        %d\n", ElfHeader.e_shnum);
         printf("    e_shstrndx:     %d\n", ElfHeader.e_shstrndx);
     }
     check(memcmp(ELFMAG, ElfHeader.e_ident, SELFMAG) == 0,
           "Bad ELF header magic number\n");
     check(ElfHeader.e_type == ET_CORE, "Bad ELF object file type\n");
     // check(ElfHeader.e_machine == EM_X86_64, "Bad ELF architecture\n");
     check(ElfHeader.e_version == EV_CURRENT, "Bad ELF version\n");
     check(ElfHeader.e_phoff >= ElfHeader.e_ehsize,
           "Bad program header offset\n");
     check(ElfHeader.e_phentsize == sizeof(ProgHeader),
           "Bad program header size\n");
     PHOffset = ElfHeader.e_phoff;
     PHCount = ElfHeader.e_phnum;

     for (i = 0; i < PHCount; i ++)
     {
         /* Get the i-th program header; we are interested in loadXX
          * sections */
         readat(corefd,
                &ProgHeader,
                sizeof(ProgHeader),
                PHOffset + i * sizeof(ProgHeader));
         if (debug)
         {
             printf("Corefile Program Header:\n");
             printf("    p_type:         %d\n", ProgHeader.p_type);
             printf("    p_offset:       %" PRId64 "\n", ProgHeader.p_offset);
             printf("    p_vaddr:        %" PRIxPTR "\n", ProgHeader.p_vaddr);
             printf("    p_paddr:        %" PRIxPTR "\n", ProgHeader.p_paddr);
             printf("    p_filesz:       %" PRId64 "\n", ProgHeader.p_filesz);
             printf("    p_memsz:        %" PRId64 "\n", ProgHeader.p_memsz);
             printf("    p_flags:        %" PRId32 "\n", ProgHeader.p_flags);
             printf("    p_align:        %" PRId64 "\n", ProgHeader.p_align);
         }
         if (ProgHeader.p_type == PT_LOAD)
         {
             char *segment = xmalloc(ProgHeader.p_filesz);

             /* Read the section.  If it starts with an ELF header then
              * it's (almost certainly) the start of an object */
             readat(corefd, segment, ProgHeader.p_filesz,
                    ProgHeader.p_offset);
             if (memcmp(ELFMAG, segment, SELFMAG) == 0)
             {
                 char *libname = GuessLibName(segment,
                                              ProgHeader.p_filesz);
                 if (libname == NULL)
                 {
                     libname = xmalloc(40);
                     snprintf(libname, 40, "libunknown_%d", i);
                 }
                 if (debug)
                 {
                     printf("Guessed library name %s\n", libname);
                 }
                 ProcessObject64(segment,
                                 ProgHeader.p_filesz,
                                 libname,
                                 ElfHeader.e_machine);
                 free(libname);
             }
             free(segment);
         }
     }
}

void extract_cfi(char *corefile)
{
     int corefd;
     unsigned char Elf_Magic[EI_NIDENT];

     /* Open the corefile for reading */
     corefd = open(corefile, O_RDONLY);
     check(corefd > 0, "open() failed\n");

     /* Get the start of the corefile ELF header.  The first few elements,
      * including the machine architecture, are common to the 32 and 64-bit
      * structs so we can infer which we need to use. */
     readat(corefd, (void *)&Elf_Magic, sizeof(Elf_Magic), 0);
     if (debug)
     {
         printf("Corefile ELF Header Magic:  %.16s\n", Elf_Magic);
     }
     check(memcmp(ELFMAG, Elf_Magic, SELFMAG) == 0,
           "Bad ELF header magic number\n");
     switch (Elf_Magic[4])
     {
         case ELFCLASS32:
             printf("Found 32-bit core file\n");
             extract_cfi_32(corefd);
             break;
         case ELFCLASS64:
             printf("Found 64-bit core file\n");
             extract_cfi_64(corefd);
             break;
         default:
             check(false, "Bad ELF architecture\n");
     }

     close(corefd);
}


int main(int argc, char **argv)
{
     char *corefile;
     int c;
     char *cfi_dir = NULL;
     int show_help = 0;

     while((c = getopt(argc, argv, "h?vdf:")) > 0)
     {
         switch (c)
         {
         case 'd':
             debug = 1;
             break;

         case 'f':
             cfi_dir = optarg;
             break;

         case '?':
         case 'h':
             show_help = 1;
             break;

         default:
             fprintf(stderr, "invalid argument %c.\n", c);
             exit(1);
             break;
         }
     }

     if (show_help)
     {
         printf("Usage: corelibgen [options] corefile\n\n"
                "where options are:\n\n"
                "-f <dir>	: "
                    "Create CFI stub libraries in sysroot <dir>.\n"
                "-d		: Output debugging information.\n"
                "-h or -?	: Show help.\n"
               );
         exit(0);
     }

     check(argc - optind == 1, "invalid number of arguments.\n");

     corefile = realpath(argv[optind], NULL);
     check(corefile != NULL, "unable to obtain path of core file.\n");

     if (cfi_dir)
     {
         int res;
         char *cfi_lib_dir = xmalloc(strlen(cfi_dir) + 5);
         struct stat stat_buf;

         sprintf(cfi_lib_dir, "%s/lib", cfi_dir);

         res = stat(cfi_lib_dir, &stat_buf);
         if (res != 0 && errno == ENOENT)
         {
             res = mkdir(cfi_lib_dir, 0755);
             check(res == 0, "unable to make directory.\n");
         }
         else
         {
             check(res == 0, "unable to stat.\n");
         }

         res = chdir(cfi_lib_dir);
         check(res == 0, "unable to change to specified directory.\n");
         free(cfi_lib_dir);

         extract_cfi(corefile);
     }
     exit(0);
}

