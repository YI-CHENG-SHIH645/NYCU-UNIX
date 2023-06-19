#include "sprintstatf.h"
#include "uthash.h"
#include <capstone/capstone.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define errquit(m)                                                             \
  {                                                                            \
    perror(m);                                                                 \
    _exit(-1);                                                                 \
  }

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)                                              \
  fprintf(stdout, "[DEBUG INFO] " fmt "\n", ##args)
#else
#define DEBUG_PRINT(fmt, args...)                                              \
  do {                                                                         \
  } while (0)
#endif

typedef struct bps {
  unsigned long long int addr;
  long int orig_code;
  UT_hash_handle hh;
} bps_hashmap;

typedef struct memory_segment {
  unsigned long long int start;
  unsigned long long int end;
  char permission[5]; // rwxp + '\0'
} MemSeg;

int by_addr(const bps_hashmap *a, const bps_hashmap *b) {
  return a->addr < b->addr ? -1 : (a->addr == b->addr ? 0 : 1);
}

void trace_memory(pid_t child, unsigned long long addr) {
  for (int i = 0; i < 9; ++i) {
    printf("addr : 0x%llx / addr+%d : 0x%llx / ", addr, i, addr + i);
    long int byte_code = ptrace(PTRACE_PEEKTEXT, child, addr + i, 0);
    for (int j = 0; j < 8; ++j)
      printf("%2.2x ", ((unsigned char *)&byte_code)[j]);
    printf("\n");
  }
}

void add_breakpoint(const pid_t child, bps_hashmap **bps,
                    const unsigned long long int bp_addr) {
  long int code = ptrace(PTRACE_PEEKTEXT, child, bp_addr, 0);
  if ((code & 0xFF) == 0xCC)
    return;

  if (ptrace(PTRACE_POKETEXT, child, bp_addr,
             ((code & 0xFFFFFFFFFFFFFF00) | 0xCC)) != 0)
    errquit("ptrace@parent");
  bps_hashmap *s;
  HASH_FIND_INT(*bps, &bp_addr, s);
  if (!s) {
    s = (bps_hashmap *)malloc(sizeof *s);
    s->addr = bp_addr;
    s->orig_code = code;
    HASH_ADD_INT(*bps, addr, s);
    printf("** set a breakpoint at 0x%llx\n", bp_addr);
  }
}

void release_breakpoint(pid_t child, bps_hashmap **bps,
                        bps_hashmap **next_insn_s, bps_hashmap *tgt_bp) {
  if (ptrace(PTRACE_POKETEXT, child, tgt_bp->addr, tgt_bp->orig_code) != 0)
    errquit("ptrace@parent");
  *next_insn_s = tgt_bp;
}

void addback_breakpoint(pid_t child, bps_hashmap **bps,
                        bps_hashmap *next_insn_s) {
  add_breakpoint(child, bps, next_insn_s->addr);
  bps_hashmap *s = NULL;
  unsigned long long int v;
  for (int i = 1; i < 8; ++i) {
    v = next_insn_s->addr + i;
    HASH_FIND_INT(*bps, &v, s);
    if (s) {
      add_breakpoint(child, bps, next_insn_s->addr + i);
      break;
    }
  }
}

void disassemble(const unsigned long long int tgt_addr, const uint8_t *code,
                 const size_t code_size, const Elf64_Shdr *text_shdr) {
  if ((text_shdr->sh_addr <= tgt_addr) &&
      (tgt_addr < (text_shdr->sh_addr + text_shdr->sh_size))) {
    csh cshandle = 0;
    cs_insn *insn;
    size_t count;
    uint8_t bytes[16];
    unsigned long long int offset =
        text_shdr->sh_offset + (tgt_addr - text_shdr->sh_addr);
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
      errquit("cs_open");
    if ((count = cs_disasm(cshandle, code + offset, code_size, tgt_addr, 5,
                           &insn)) > 0) {
      for (int i = 0; i < (int)count; ++i) {
        if ((text_shdr->sh_addr <= insn[i].address) &&
            (insn[i].address < (text_shdr->sh_addr + text_shdr->sh_size))) {
          memcpy(bytes, insn[i].bytes, insn[i].size);
          fprintf(stderr, "\t0x%lx: ", insn[i].address);
          for (int j = 0; j < insn[i].size; ++j)
            fprintf(stderr, "%2.2x ", bytes[j]);
          for (int z = 0; z < 8 - insn[i].size; ++z)
            fprintf(stderr, "   ");
          fprintf(stderr, " %s \t %s\n", insn[i].mnemonic, insn[i].op_str);
        } else {
          printf("** the address is out of the range of the text section.\n");
          break;
        }
      }
    }
    cs_free(insn, count);
    cs_close(&cshandle);
  } else {
    printf("** the address is out of the range of the text section.\n");
  }
}

int wait_peek_poke(pid_t child, bps_hashmap **bps, bps_hashmap **next_insn_s,
                   const uint8_t *code, size_t code_size,
                   Elf64_Shdr *text_shdr) {
  int wait_status;
  if (waitpid(child, &wait_status, 0) < 0)
    errquit("waitpid");
  if (WIFEXITED(wait_status)) {
    if (WIFSIGNALED(wait_status))
      printf("** the target program terminated by signal (code %d)\n",
             WTERMSIG(wait_status));
    else
      printf("** the target program terminated.\n");
    return -1;
  } else if (WIFSTOPPED(wait_status)) {
    if (WSTOPSIG(wait_status) == SIGTRAP) {

      struct user_regs_struct regs;
      ptrace(PTRACE_GETREGS, child, 0, &regs);
      --regs.rip;
      bps_hashmap *s = NULL;
      HASH_FIND_INT(*bps, &regs.rip, s);
      if (!(*next_insn_s) && s)
        release_breakpoint(child, bps, next_insn_s, s);
      else
        ++regs.rip;
      if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
        errquit("ptrace@parent");

    } else {
      printf("** the target program stopped by signal (code %d)\n",
             WTERMSIG(wait_status));
      return -1;
    }
  }

  return 0;
}

int main(int argc, char **argv, char **envp) {

  if (argc < 2) {
    fprintf(stderr, "usage: %s program \n", argv[0]);
    return -1;
  }

  struct stat st;
  // ---------------- print target file stat ----------------
  {
    char *outbuf = (char *)malloc(2048 * sizeof(char));
    char *fmt = "st_atime (decimal) = \"%a\"\n"
                "st_atime (string)  = \"%A\"\n"
                "st_ctime (decimal) = \"%c\"\n"
                "st_ctime (string)  = \"%C\"\n"
                "st_gid   (decimal) = \"%g\"\n"
                "st_gid   (string)  = \"%G\"\n"
                "st_ino             = \"%i\"\n"
                "st_mtime (decimal) = \"%m\"\n"
                "st_mtime (string)  = \"%M\"\n"
                "st_nlink           = \"%n\"\n"
                "st_mode  (octal)   = \"%p\"\n"
                "st_mode  (string)  = \"%P\"\n"
                "st_size            = \"%s\"\n"
                "st_uid             = \"%u\"\n"
                "st_uid             = \"%U\"\n";
    if (lstat(argv[1], &st) != 0)
      errquit("lstat");
    sprintstatf(outbuf, fmt, &st);
    char *tok = strtok(outbuf, "\n");
    DEBUG_PRINT("%s", tok);
    while (tok = strtok(NULL, "\n"))
      DEBUG_PRINT("%s", tok);
    free(outbuf);
    DEBUG_PRINT("----------------");
  }
  // ---------------- end of print target file stat ----------------

  // ---------------- read program as elf ----------------
  Elf64_Ehdr *ehdr;
  Elf64_Shdr *text_shdr;

  {
    FILE *elf_fptr;
    char *elf_mmap;
    if ((elf_fptr = fopen(argv[1], "r")) == NULL)
      errquit("fopen");
    if ((elf_mmap = mmap(0, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE, fileno(elf_fptr), 0)) == NULL)
      errquit("mmap");

    ehdr = (Elf64_Ehdr *)elf_mmap;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(elf_mmap + ehdr->e_shoff);
    Elf64_Shdr *strtab = shdr + ehdr->e_shstrndx;
    char *strtab_p = elf_mmap + strtab->sh_offset;
    for (int i = 0; i < ehdr->e_shnum; ++i) {
      if (strcmp(strtab_p + shdr[i].sh_name, ".text") == 0) {
        text_shdr = shdr + i;
      }
    }

    fclose(elf_fptr);

    DEBUG_PRINT("elf_mmap             : %16p", elf_mmap);
    DEBUG_PRINT("ehdr                 : %16p", ehdr);
    DEBUG_PRINT("ehdr->e_shoff        : %16lx", ehdr->e_shoff);
    DEBUG_PRINT("shdr                 : %16p", shdr);
    DEBUG_PRINT("ehdr->e_shstrndx     : %16x", ehdr->e_shstrndx);
    DEBUG_PRINT("strtab               : %16p", strtab);
    DEBUG_PRINT("strtab->sh_offset    : %16lx", strtab->sh_offset);
    DEBUG_PRINT("strtab_p             : %16p", strtab_p);
    DEBUG_PRINT("ehdr->e_shnum        : %16x", ehdr->e_shnum);
    DEBUG_PRINT("text_shdr            : %16p", text_shdr);
    DEBUG_PRINT("text_shdr->sh_size   : %16lx", text_shdr->sh_size);
    DEBUG_PRINT("text_shdr->sh_entsize: %16lx", text_shdr->sh_entsize);
    DEBUG_PRINT("text_shdr->sh_offset : %16lx", text_shdr->sh_offset);
    DEBUG_PRINT("text_shdr->sh_addr   : %16lx", text_shdr->sh_addr);
    DEBUG_PRINT("----------------");
  }
  // ---------------- end of read program as elf -------------------

  pid_t child;
  if ((child = fork()) == -1)
    errquit("fork");

  if (child == 0) {
    // child process
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execve(argv[1], argv + 1, envp);
    errquit("execve");
  } else {
    // parent process

    // for disassembling
    uint8_t *code = (char *)ehdr;
    size_t code_size = text_shdr->sh_size;

    if (waitpid(child, 0, 0) < 0)
      errquit("waitpid");
    printf("** program '%s' loaded. entry point 0x%lx\n", argv[1],
           ehdr->e_entry);
    disassemble(ehdr->e_entry, code, code_size, text_shdr);

    // rip address -> orig code bytes
    bps_hashmap *breakpoints = NULL;
    bps_hashmap *next_insn_s = NULL;

    // for dropping anchor
    // snapshot general purpose registers
    struct user_regs_struct anchor_regs;
    // store the snapshoted memory contents
    MemSeg mem_seg[2];
    unsigned char *heap = NULL;
    unsigned long long heap_size = 0;
    unsigned char *stack = NULL;
    unsigned long long stack_size = 0;

    // for reading command
    char *cmd = NULL;
    size_t len = 0;
    ssize_t nread;

    struct user_regs_struct regs;
    bps_hashmap *s;

    while (printf("(sdb) ") && ((nread = getline(&cmd, &len, stdin)) != -1)) {
      if (strcmp(cmd, "\n") == 0)
        continue;
      cmd[strlen(cmd) - 1] = '\0';
      char *tok = strtok(cmd, " ");

      // (sdb) si
      // child is waiting for next command
      // the next instruction must be executable (no CC)
      // if next_insn_s is set, then si -> inject CC command
      // e.x. : 0x401000 -> 0x401004
      if (strcmp(tok, "si") == 0) {
        next_insn_s = NULL;
        if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
          errquit("ptrace@parent");
        if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                           text_shdr) == -1)
          break;
        if (next_insn_s) {
          // single step the released instruction
          if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
            errquit("ptrace@parent");
          if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                             text_shdr) == -1)
            break;
          addback_breakpoint(child, &breakpoints, next_insn_s);
          next_insn_s = NULL;
        }

        // e.x. : 0x401004 is a break point -> release
        ptrace(PTRACE_GETREGS, child, 0, &regs);
        s = NULL;
        HASH_FIND_INT(breakpoints, &regs.rip, s);
        if (s) {
          if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
            errquit("ptrace@parent");
          if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                             text_shdr) == -1)
            break;
          printf("** hit a breakpoint at 0x%llx\n", s->addr);
          disassemble(s->addr, code, code_size, text_shdr);
        } else {
          disassemble(regs.rip, code, code_size, text_shdr);
        }
      }
      // (sdb) cont
      else if (strcmp(tok, "c") == 0 || strcmp(tok, "cont") == 0) {
        next_insn_s = NULL;
        if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
          errquit("ptrace@parent");
        if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                           text_shdr) == -1)
          break;
        if (next_insn_s) {
          // single step the released instruction
          if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
            errquit("ptrace@parent");
          if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                             text_shdr) == -1)
            break;
          addback_breakpoint(child, &breakpoints, next_insn_s);
          next_insn_s = NULL;
        }
        if (ptrace(PTRACE_CONT, child, 0, 0) < 0)
          errquit("ptrace@parent");
        if (wait_peek_poke(child, &breakpoints, &next_insn_s, code, code_size,
                           text_shdr) == -1)
          break;
        if (next_insn_s) {
          ptrace(PTRACE_GETREGS, child, NULL, &regs);
          printf("** hit a breakpoint at 0x%llx\n", regs.rip);
          disassemble(regs.rip, code, code_size, text_shdr);
        }
      }
      // (sdb) break virt_address
      else if (strcmp(tok, "break") == 0) {
        add_breakpoint(child, &breakpoints,
                       strtoull(strtok(NULL, " "), NULL, 16));
      }
      // (sdb) anchor
      else if (strcmp(tok, "anchor") == 0) {
        if (heap)
          free(heap);
        heap = NULL;
        heap_size = 0;
        if (stack)
          free(stack);
        stack = NULL;
        stack_size = 0;

        char maps_filename[50];
        sprintf(maps_filename, "/proc/%d/maps", child);
        FILE *maps_fptr = fopen(maps_filename, "r");
        if (!maps_fptr)
          errquit("fopen maps file error");

        // parse memory maps file
        int m = 0;
        char permission[5], file_path[100];
        unsigned long long start, end;
        while (fscanf(maps_fptr, "%llx-%llx %s %*x %*x:%*x %*d", &start, &end,
                      permission) == 3) {
          fgets(file_path, 100, maps_fptr);
          if (permission[1] == 'w') {
            mem_seg[m].start = start;
            mem_seg[m].end = end;
            memcpy(mem_seg[m].permission, permission, 5);
            ++m;
          }
        }
        fclose(maps_fptr);

        // first for heap, second for stack
        if (m != 2)
          errquit("# of writable mem segment > 2");

        // save general purpose registers
        ptrace(PTRACE_GETREGS, child, 0, &anchor_regs);

        // save heap memory contents
        heap_size = mem_seg[0].end - mem_seg[0].start;
        heap = (unsigned char *)malloc(heap_size);
        for (int i = 0; i < heap_size; i += 8) {
          long int byte_code =
              ptrace(PTRACE_PEEKTEXT, child, mem_seg[0].start + i, 0);
          memcpy(heap + i, (unsigned char *)&byte_code, 8);
        }

        // save stack memory contents
        stack_size = mem_seg[1].end - anchor_regs.rsp;
        stack = (unsigned char *)malloc(stack_size);
        for (int i = 0; i < stack_size; i += 8) {
          long int byte_code =
              ptrace(PTRACE_PEEKTEXT, child, anchor_regs.rsp + i, 0);
          memcpy(stack + i, (unsigned char *)&byte_code, 8);
        }
        printf("** dropped an anchor\n");
      }
      // (sdb) timetravel
      else if (strcmp(tok, "timetravel") == 0) {

        // restore general purpose registers
        ptrace(PTRACE_SETREGS, child, 0, &anchor_regs);

        // restore heap memory contents
        for (int i = 0; i < heap_size; i += 8)
          if (ptrace(PTRACE_POKETEXT, child, mem_seg[0].start + i,
                     *(long *)(heap + i)) != 0)
            errquit("ptrace@parent");
        free(heap);
        heap = NULL;
        heap_size = 0;

        // restore stack memory contents
        for (int i = 0; i < stack_size; i += 8)
          if (ptrace(PTRACE_POKETEXT, child, anchor_regs.rsp + i,
                     *(long *)(stack + i)) != 0)
            errquit("ptrace@parent");
        free(stack);
        stack = NULL;
        stack_size = 0;

        // add back the break points with address > anchor point
        HASH_SORT(breakpoints, by_addr);
        for (s = breakpoints; s != NULL; s = (bps_hashmap *)(s->hh.next)) {
          if (s->addr > anchor_regs.rip) {
            if (ptrace(PTRACE_POKETEXT, child, s->addr,
                       ((s->orig_code & 0xFFFFFFFFFFFFFF00) | 0xCC)) != 0)
              errquit("ptrace@parent");
          }
        }

        printf("** go back to the anchor point\n");
        disassemble(anchor_regs.rip, code, code_size, text_shdr);
      } else if (strcmp(tok, "mem") == 0) {
        if (tok = strtok(NULL, " ")) {
          trace_memory(child, strtoull(tok, NULL, 16));
        } else {
          struct user_regs_struct regs;
          ptrace(PTRACE_GETREGS, child, NULL, &regs);
          trace_memory(child, regs.rip);
        }
      } else {
        fprintf(stderr, "** Undefined command\n");
      }
    }

    if (heap) {
      free(heap);
      heap = NULL;
      heap_size = 0;
    }
    if (stack) {
      free(stack);
      stack = NULL;
      stack_size = 0;
    }
    munmap((void *)ehdr, st.st_size);
  }

  return 0;
}
