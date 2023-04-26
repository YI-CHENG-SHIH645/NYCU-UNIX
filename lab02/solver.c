#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>

struct dirent *readdir(DIR *dirp);
int stat(const char *restrict pathname,
         struct stat *restrict statbuf);

void traverse(const char *dir, const char * tgt) {
  DIR *dir_handle = opendir(dir);
  if(!dir_handle) {
    fprintf(stderr, "opendir failed, errno = %d, strerr = %s\n",\
            errno, strerror(errno));
    exit(1);
  }

  struct dirent * entry;  // do not attempt to free it
  static bool found = false;
  // char line[40960];
  char path[500];
  // char *path = malloc(200);
  while(!found && (entry = readdir(dir_handle))) {
    if(!strcmp(entry->d_name, ".") ||
       !strcmp(entry->d_name, "..")) continue;
    strcpy(path, dir);
    strcat(path, "/");
    strcat(path, entry->d_name);
    // fprintf(stderr, "%s\n", path);
    struct stat st;
    if(lstat(path, &st) == -1) {
      fprintf(stderr, "stat file failed, the path is like \n'%s',\
                       \nerrno = %d, strerr = %s\n",\
              path, errno, strerror(errno));
      exit(1);
    }
    if(S_ISLNK(st.st_mode)) {
      continue;
    }
    else if(S_ISDIR(st.st_mode)) {
      traverse(path, tgt);
    }
    else if(S_ISREG(st.st_mode)) {
      FILE *stream;
      if((stream = fopen(path, "r")) == NULL) {
        fprintf(stderr, "open file failed, errno = %d, strerr = %s\n",\
                errno, strerror(errno));
        exit(1);
      }

      // while((fgets(line, 2048, stream)) != NULL) {
      //   line[strcspn(line, "\n")] = 0;
      //   if(strstr(line, tgt) != NULL) {
      //     printf("%s\n", path);
      //     found = true;
      //     break;
      //   }
      // }

      fseek(stream, 0L, SEEK_END);
      long sz = ftell(stream);
      fseek(stream, 0L, SEEK_SET);
      char *buf = malloc(sz+1);
      // char buf[9];
      fread(buf, sz, 1, stream);
      buf[sz] = 0;
      fprintf(stderr, "%s\n", buf); 
      if(strstr(buf, tgt) != NULL) {
        // fprintf(stderr, "%s,  %s\n", buf, tgt);
        printf("%s\n", path);
        found = true;
        break;
      }
      free(buf);
      fclose(stream);
    }
  }
  // free(path);
  closedir(dir_handle);
}

int main(int argc, char * argv[]) {
  if(argc != 3) {
    // printf("Usage : ./solver `dir_path` `magic_number_to_find`\n");
    exit(1);
  }
  
  traverse(argv[1], argv[2]);

  fprintf(stderr, "%s", argv[2]);
  fprintf(stderr, "end searching!\n");
  return 0;
}
