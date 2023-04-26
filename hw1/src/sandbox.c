#define _GNU_SOURCE
#include <elf.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef DEBUG
  #define DEBUG_PRINT(fmt, args...) \
    fprintf(stdout, "[DEBUG INFO] " fmt "\n", ##args)
#else
  #define DEBUG_PRINT(fmt, args...) do {} while(0)
#endif

typedef int (*__libc_start_main_ptr) (int (*) (int, char **, char **),
                                      int,
                                      char **,
                                      void (*) (void),
                                      void (*) (void),
                                      void (*) (void),
                                      void (*));
typedef int (*open_fptr) (const char *, int, ...);
typedef ssize_t (*read_fptr) (int __fd, void *__buf, size_t __nbytes);
typedef int (*write_fptr)(int, const void *, size_t);

int logger_fd;
FILE *config_fptr;
char *hostname;
int hijacked_open(const char *pathname, int flags, mode_t mode);
ssize_t hijacked_read(int fd, void *buf, size_t count);
ssize_t hijacked_write(int fd, void *buf, size_t count);
int hijacked_connect(int sockfd,
                     const struct sockaddr *addr, 
                     socklen_t addrlen);
int hijacked_getaddrinfo(const char *restrict node,
                         const char *restrict service,
                         const struct addrinfo *restrict hints,
                         struct addrinfo **restrict res);
int hijacked_system(const char *command);

int hijacked_open(const char *pathname, int flags, mode_t mode)
{
  // printf("The open flags is : %d\n", flags);

  // if pathname in blacklist
  // set error no and return -1
  // else call the original open(pathname, flags)
  // if you define `real_path[strlen(pathname)]`,
  // the flags will be overwritten, which is unbelievable
  char real_path[100];
  realpath(pathname, real_path);

  // printf("The open flags is : %d\n", flags);
  
  fseek(config_fptr, 0, SEEK_SET);
  char config_row[200], s[300];
  int ret;
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "BEGIN open-blacklist"));
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "END open-blacklist")) {
    config_row[strcspn(config_row, "\n")] = 0;
    if(strstr(real_path, config_row)) {
      errno = EACCES;
      ret = -1;
      sprintf(s, "[logger] open(%s, %d, %d) = %d\n", real_path, flags, mode, ret);
      write(logger_fd, s, strlen(s));
      return ret;
    }
  }
  
  // open_fptr real_open = dlsym(RTLD_NEXT, "open");
  // if(open == real_open) {
  //   DEBUG_PRINT("open and real_open is the same!");
  // }
  DEBUG_PRINT("I'm gonna calling open(%p) in hijacked_open(%p)", open, hijacked_open);
  ret = open(real_path, flags, mode);
  sprintf(s, "[logger] open(%s, %d, %d) = %d\n", real_path, flags, mode, ret);
  write(logger_fd, s, strlen(s));
  return ret;
}

ssize_t hijacked_read(int fd, void *buf, size_t count)
{
  fseek(config_fptr, 0, SEEK_SET);
  char config_row[200], s[100];
  
  // read_fptr real_read = dlsym(RTLD_DEFAULT, "read");
  // if(read == real_read) {
  //   DEBUG_PRINT("read and real_read is the same!");
  // }

  DEBUG_PRINT("I'm gonna calling read(%p) in hijacked_read(%p)", read, hijacked_read);
  ssize_t ret = read(fd, buf, count);
  if(ret == -1) {
    fprintf(stderr, "read failed, errno = %d, strerr = %s   fd %d\n", errno, strerror(errno), fd);
    _exit(1);
  }
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "BEGIN read-blacklist"));
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "END read-blacklist")) {
    if(strstr(buf, config_row)) {
      errno = EIO;
      ret = -1;
      sprintf(s, "[logger] read(%d, %p, %lu) = %ld\n", fd, buf, count, ret);
      write(logger_fd, s, strlen(s));
      close(fd);
      return ret;
    }
  }

  sprintf(s, "[logger] read(%d, %p, %lu) = %ld\n", fd, buf, count, ret);
  write(logger_fd, s, strlen(s));

  char file_name[100];
  sprintf(file_name, "%d-%d-read.log", getpid(), fd);

  // int file_fd;
  // if((file_fd = open(file_name, O_CREAT | O_APPEND, S_IRUSR | S_IWUSR) == -1)) {
  //   fprintf(stderr, "fopen read.log failed, errno = %d, strerr = %s\n", errno, strerror(errno));
  //   _exit(1);
  // }
  // write(file_fd, buf, (size_t)ret);
  // close(file_fd);

  FILE *file_fptr;
  if((file_fptr = fopen(file_name, "a+")) == NULL) {
    fprintf(stderr, "fopen read.log failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }
  fwrite(buf, 1, ret, file_fptr);
  fclose(file_fptr);

  return ret;
}

ssize_t hijacked_write(int fd, void *buf, size_t count)
{
  // printf("\n\n%d call write with fd: %d\n\n", getpid(), fd);
  char s[100];
  ssize_t ret = write(fd, buf, count);
  sprintf(s, "[logger] write(%d, %p, %lu) = %lu\n", fd, buf, count, ret);
  write(logger_fd, s, strlen(s));

  char file_name[100];
  sprintf(file_name, "%d-%d-write.log", getpid(), fd);
  FILE *file_fptr;
  if((file_fptr = fopen(file_name, "a+")) == NULL) {
    fprintf(stderr, "fopen write.log failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }
  fwrite(buf, 1, (size_t)ret, file_fptr);
  fclose(file_fptr);

  return ret;
}

int hijacked_connect(int sockfd,
                     const struct sockaddr *addr,
                     socklen_t addrlen)
{
  struct sockaddr_in *sa = (struct sockaddr_in *)addr;
  char *ip = inet_ntoa(sa->sin_addr);
  uint16_t port = ntohs(sa->sin_port);
  char *hostname_www = strstr(hostname, "//") + 2;
  DEBUG_PRINT("Hostname : %s // Hostname www : %s", hostname, hostname_www);

  fseek(config_fptr, 0, SEEK_SET);
  char config_row[200], s[100];
  char blocked_hostname[100];
  uint16_t blocked_port;

  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "BEGIN connect-blacklist"));
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "END connect-blacklist")) {
    sscanf(config_row, "%[^:]:%hu", blocked_hostname, &blocked_port);
    if((strcmp(hostname_www, blocked_hostname) == 0) && (port == blocked_port)) {
      errno = ECONNREFUSED;
      sprintf(s, "[logger] connect(%d, %s, %u) = -1\n", sockfd, ip, addrlen);
      write(logger_fd, s, strlen(s));
      return -1;
    }
  }

  int ret = connect(sockfd, addr, addrlen);
  sprintf(s, "[logger] connect(%d, %s, %u) = %d\n", sockfd, ip, addrlen, ret);
  write(logger_fd, s, strlen(s));
  return ret;
}

int hijacked_getaddrinfo(const char *restrict node,
                         const char *restrict service,
                         const struct addrinfo *restrict hints,
                         struct addrinfo **restrict res)
{
  fseek(config_fptr, 0, SEEK_SET);
  char config_row[200], s[100];

  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "BEGIN getaddrinfo-blacklist"));
  while(fgets(config_row, sizeof(config_row), config_fptr) && !strstr(config_row, "END getaddrinfo-blacklist")) {
    config_row[strcspn(config_row, "\n")] = 0;
    if(strcmp(node, config_row) == 0) {
      sprintf(s, "[logger] getaddrinfo(%s, %s, %p, %p) = -2\n", node, service, hints, res);
      write(logger_fd, s, strlen(s));
      return EAI_NONAME;
    }
  }

  int ret = getaddrinfo(node, service, hints, res);
  sprintf(s, "[logger] getaddrinfo(%s, %s, %p, %p) = %d\n", node, service, hints, res, ret);
  write(logger_fd, s, strlen(s));
  return ret;
}

int hijacked_system(const char *command)
{
  char cpy_cmd[strlen(command)];
  strcpy(cpy_cmd, command);
  strtok(cpy_cmd, " ");
  char s[100];
  hostname = strtok(NULL, " ");

  sprintf(s, "[logger] system(%s)\n", command);
  write(logger_fd, s, strlen(s));
  int ret = system(command);
  return ret;
}

// hijack the process’s entry point
int __libc_start_main(int (*main) (int, char **, char **),
                      int argc,
                      char ** ubp_av,
                      void (*init) (void),
                      void (*fini) (void),
                      void (*rtld_fini) (void),
                      void (*stack_end))
{
  // retrieve ELF
  char elf_path[100];
  struct stat st;
  realpath("/proc/self/exe", elf_path);
  DEBUG_PRINT("  %-15s : %s", "elf_path", elf_path);

  if (stat(elf_path, &st) != 0) {
    perror("stat");
    return 1;
  }
  DEBUG_PRINT("  %-15s : %lu", "st.st_size", st.st_size);
  
  FILE *elf_fptr;
  if((elf_fptr = fopen(elf_path, "r")) == NULL) {
    fprintf(stderr, "fopen elf failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }
  DEBUG_PRINT("  %-15s : %d", "elf_fd", fileno(elf_fptr));
  
  char *elf_mmap;
  if((elf_mmap = mmap(0, st.st_size,
                      PROT_READ|PROT_WRITE|PROT_EXEC,
                      MAP_PRIVATE,
                      fileno(elf_fptr), 0)) == NULL)
  {
    fprintf(stderr, "elf mmap failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }
  
  // retrieve base addr
  FILE *maps_fptr;
  if((maps_fptr = fopen("/proc/self/maps", "r")) == NULL) {
    fprintf(stderr, "fopen maps failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }

  char maps_row[256];
  uint64_t base_addr;
  while(fgets(maps_row, sizeof(maps_row), maps_fptr)) {
    if(strstr(maps_row, elf_path)) {
      char *elf_path_end = strchr(maps_row, '-');
      *elf_path_end = '\0';
      base_addr = strtoul(maps_row, NULL, 16);
      break;
    }
  }
  DEBUG_PRINT("  %-15s : 0x%016lx", "base addr", base_addr);
  fclose(maps_fptr);

  // retrieve ELF header
  // fread(&ehdr, 1, sizeof(Elf64_Ehdr), elf_fptr);
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_mmap;
  DEBUG_PRINT("  %-15s : 0x%016lx", "ehdr->e_shoff", ehdr->e_shoff);
  DEBUG_PRINT("  %-15s : %d", "# shdr entries", ehdr->e_shnum);
  // Elf64_Shdr shdr[ehdr.e_shnum];
  // fseek(elf_fptr, ehdr.e_shoff, SEEK_SET);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(elf_mmap + ehdr->e_shoff);
  // for(int i=0; i<ehdr->e_shnum; ++i) {
  //   fread(shdr+i, 1, sizeof(Elf64_Shdr), elf_fptr);
  // }

  Elf64_Shdr *strtab = shdr + ehdr->e_shstrndx;
  char *strtab_p = elf_mmap + strtab->sh_offset;
  char *strtab_p_for_symtab;

  Elf64_Shdr *rela_shdr, *symtab_shdr;
  Elf64_Rela *rela; Elf64_Sym *symtab;
  // find .rela.plt section and .dynsym section
  for(int i=0; i<ehdr->e_shnum; ++i) {
    if(shdr[i].sh_type == SHT_RELA && strcmp(strtab_p+shdr[i].sh_name, ".rela.plt") == 0) {
      rela_shdr = shdr+i;
      rela = (Elf64_Rela *)(elf_mmap + rela_shdr->sh_offset);
    } else if(shdr[i].sh_type == SHT_DYNSYM && strcmp(strtab_p+shdr[i].sh_name, ".dynsym") == 0) {
      symtab_shdr = shdr+i;
      symtab = (Elf64_Sym *)(elf_mmap + symtab_shdr->sh_offset);
      strtab_p_for_symtab = elf_mmap + shdr[symtab_shdr->sh_link].sh_offset;
    }
  }

  unsigned long mp_start = ((base_addr + rela->r_offset) >> 12) << 12;
  unsigned long mp_len = base_addr + (rela+(rela_shdr->sh_size/rela_shdr->sh_entsize-1))->r_offset - mp_start;
  if(mprotect((void*)mp_start, mp_len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
    fprintf(stderr, "mprotect failed, errno = %d, strerr = %s\n",\
            errno, strerror(errno));
    exit(1);
  }

  for(int j=0; j<(rela_shdr->sh_size / sizeof(Elf64_Rela)); ++j) {
    if(ELF64_R_TYPE((rela+j)->r_info) != R_X86_64_RELATIVE64) {
      uint32_t sym_index = ELF64_R_SYM((rela+j)->r_info);
      char *rela_entry_name = strtab_p_for_symtab + (symtab + sym_index)->st_name;
      if(strcmp(rela_entry_name, "open") == 0) {
        // you need to do mprotect first since /usr/bin/cat is Full Relo
        DEBUG_PRINT("open addr before : %p", open);
        *(int(**)(const char *, int, mode_t))(base_addr + (rela+j)->r_offset) = hijacked_open;
        DEBUG_PRINT("The real open has been changed to hijacked_open");
        DEBUG_PRINT("open addr after : %p", open);
      }
      else if(strcmp(rela_entry_name, "read") == 0) {
        DEBUG_PRINT("read addr before : %p", read);
        *(ssize_t(**)(int, void *, size_t))(base_addr + (rela+j)->r_offset) = hijacked_read;
        DEBUG_PRINT("The real read has been changed to hijacked_read");
        DEBUG_PRINT("read addr after : %p", read);
      }
      else if(strcmp(rela_entry_name, "write") == 0) {
        *(ssize_t(**)(int, void *, size_t))(base_addr + (rela+j)->r_offset) = hijacked_write;
        DEBUG_PRINT("The real write has been changed to hijacked_write");
      }
      else if(strcmp(rela_entry_name, "connect") == 0) {
        *(int(**)(int, const struct sockaddr *, socklen_t))(base_addr + (rela+j)->r_offset) = hijacked_connect;
        DEBUG_PRINT("The real connect has been changed to hijacked_connect");
      }
      else if(strcmp(rela_entry_name, "getaddrinfo") == 0) {
        *(int(**)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict))(base_addr + (rela+j)->r_offset) = hijacked_getaddrinfo;
        DEBUG_PRINT("The real getaddrinfo has been changed to hijacked_getaddrinfo");
      }
      else if(strcmp(rela_entry_name, "system") == 0) {
        *(int(**)(const char *))(base_addr + (rela+j)->r_offset) = hijacked_system;
        DEBUG_PRINT("The real system has been changed to hijacked_system");
      }
    }
  }
  DEBUG_PRINT(" < ------------ Done hijacking ------------ > ");

  fflush(stdout);
  fclose(elf_fptr);
  munmap(elf_mmap, st.st_size);

  if((config_fptr = fopen(getenv("SANDBOX_CONFIG"), "r")) == NULL) {
    fprintf(stderr, "fopen config.txt failed, errno = %d, strerr = %s\n", errno, strerror(errno));
    _exit(1);
  }
  logger_fd = strtol(getenv("LOGGER_FD"), NULL, 10);
  hostname = ubp_av[1];

  // find the real __libc_start_main
  __libc_start_main_ptr orig_main = (__libc_start_main_ptr)dlsym(RTLD_NEXT, "__libc_start_main");
  int main_ret = orig_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
  fclose(config_fptr);

  return main_ret;
}
