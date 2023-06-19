#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <math.h>

#define errquit(m)	{ perror(m); _exit(-1); }
#define LEN 11

void convertToCharArray(int c, char arr[]) {
    for (int i = 0; i < LEN; i++) {
        arr[i] = (c & (1 << (LEN - 1 - i))) ? '1' : '0';
    }
}

int main(int argc, char ** argv, char ** envp)
{
  pid_t child;
  child = fork();
  // printf("\n\n >>> pid now is : %d <<< \n\n", child);
  if(child == 0) {
    // printf("\n\n *** I'm child process and I'm going to call PTRACE_TRACEME *** \n\n");
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    // printf("\n\n *** I'm child process and I'm going to run %s *** \n\n", argv[1]);
    execve(argv[1], argv+1, envp);
    errquit("execve")
  }
  else {
    int wait_status, counter = 0, magic = 0;
    char char_array[LEN]= { '0' };
    unsigned long long int magic_addr;
    unsigned long long int rip_reset;
    unsigned long long int get_flag_ret;
    struct user_regs_struct regs;

    // printf("\n\n *** I'm parent process and I'm going to wait for child : %d *** \n\n", child);
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

    for(int i=0; i<4; ++i) {
      if(ptrace(PTRACE_CONT, child, NULL, NULL) < 0) errquit("PTRACE_CONT");
      if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
      if(i == 1) {
        magic_addr = ptrace(PTRACE_PEEKUSER, child,
                            (unsigned char *)&regs.rax - (unsigned char *)&regs,
                            NULL);
        // printf("magic_addr : %llx\n", magic_addr);
      }
      if(i == 3) {
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        // printf("rip_reset : %llx\n", regs.rip);
      }
    }
    
    do
    {
      // printf("try magic : %s\n", char_array);
      if(ptrace(PTRACE_CONT, child, NULL, NULL) < 0) errquit("PTRACE_CONT");
      if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

      get_flag_ret = ptrace(PTRACE_PEEKUSER, child,
                            (unsigned char *)&regs.rax - (unsigned char *)&regs,
                            NULL);
      // printf("oracle get flag return value : %d\n", (int)get_flag_ret);
      
      if(ptrace(PTRACE_CONT, child, NULL, NULL) < 0) errquit("PTRACE_CONT");
      if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
      
      if(get_flag_ret != 0) {
        ptrace(PTRACE_SETREGS, child, NULL, &regs);
        
        // PTRACE_POKEDATA magic add 1
        if(++magic == (int)pow(2, LEN)) break;
        convertToCharArray(magic, char_array);
        for (int i = 0; i < LEN-7; ++i) {
            ptrace(PTRACE_POKEDATA, child, magic_addr+i, *(long *)(char_array+i));
        }
      }
      else break;
    } while(1);

    if(ptrace(PTRACE_CONT, child, NULL, NULL) < 0) errquit("PTRACE_CONT");
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
  }

  return 0;
}
