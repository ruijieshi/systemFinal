#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct process_file {
    int fd;
    bool isdir;
    struct file *file;
    struct dir *dir;
    struct list_elem elem;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
int process_add_dir (struct dir *d);
int process_add_file (struct file *f);
struct process_file* process_get_file (int fd);

#endif /* userprog/process.h */
