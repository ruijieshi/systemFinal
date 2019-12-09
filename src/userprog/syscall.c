#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
//#include "vm/page.h"

static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);

static bool sys_chdir (const char* dir);
static bool sys_mkdir (const char* dir);
static bool sys_readdir (int handle, char* name);
static bool sys_isdir (int handle);
static int sys_inumber (int handle);
void validate_user_ptr(const void *ptr);
int user_to_kernel_ptr(const void *vaddr);
void check_valid_ptr (const void *vaddr);
void check_valid_string (const void* str);


static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);

/* Serializes file system operations. */
static struct lock fs_lock;

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&fs_lock);
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
    typedef int syscall_function (int, int, int);

    /* A system call. */
    struct syscall
    {
        size_t arg_cnt;           /* Number of arguments. */
        syscall_function *func;   /* Implementation. */
    };

    /* Table of system calls. */
    static const struct syscall syscall_table[] =
            {
                    {0, (syscall_function *) sys_halt},
                    {1, (syscall_function *) sys_exit},
                    {1, (syscall_function *) sys_exec},
                    {1, (syscall_function *) sys_wait},
                    {2, (syscall_function *) sys_create},
                    {1, (syscall_function *) sys_remove},
                    {1, (syscall_function *) sys_open},
                    {1, (syscall_function *) sys_filesize},
                    {3, (syscall_function *) sys_read},
                    {3, (syscall_function *) sys_write},
                    {2, (syscall_function *) sys_seek},
                    {1, (syscall_function *) sys_tell},
                    {1, (syscall_function *) sys_close},
                    {},
                    {},
                    {1, (syscall_function *) sys_chdir},
                    {1, (syscall_function *) sys_mkdir},
                    {2, (syscall_function *) sys_readdir},
                    {1, (syscall_function *) sys_isdir},
                    {1, (syscall_function *) sys_inumber},
            };

    const struct syscall *sc;
    unsigned call_nr;
    int args[3];

    /* Get the system call. */
    copy_in (&call_nr, f->esp, sizeof call_nr);
    if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
        thread_exit ();
    sc = syscall_table + call_nr;

    /* Get the system call arguments. */
    ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
    memset (args, 0, sizeof args);
    copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

    /* Execute the system call,
       and set the return value. */
    f->eax = sc->func (args[0], args[1], args[2]);
}

static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
    int eax;
    asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
    return eax != 0;
}

static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
    int eax;
    asm ("movl $1f, %%eax; movb %b2, %0; 1:"
    : "=m" (*udst), "=&a" (eax) : "q" (byte));
    return eax != 0;
}

static bool
verify_user (const void *uaddr)
{
    return (uaddr < PHYS_BASE 
            && uaddr >= ((void *) 0x08048000)
            && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

static void
copy_in (void *dst_, const void *usrc_, size_t size)
{
    uint8_t *dst = dst_;
    const uint8_t *usrc = usrc_;

    while (size > 0) {
        if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) {
            thread_exit();
        }
        size--;
        dst++;
        usrc++;
    }
}

static char *
copy_in_string (const char *us)
{
    char *ks;
    size_t i;

    ks = palloc_get_page (0);
    if (ks == NULL)
        thread_exit ();

    for (i = 0; i < PGSIZE; i++)
    {
        if (us >= (char *) PHYS_BASE || !get_user (ks + i, us++))
        {
            palloc_free_page (ks);
            thread_exit ();
        }

        if (ks[i] == '\0') {
            return ks;
        }
    }

    ks[PGSIZE - 1] = '\0';
    return ks;
}

/* Halt system call. */
static int
sys_halt (void)
{
    shutdown_power_off ();
}

/* Exit system call. */
static int
sys_exit (int exit_code)
{
    thread_current ()->wait_status->exit_code = exit_code;
    thread_exit ();
    NOT_REACHED ();
}

/* Exec system call. */
static int
sys_exec (const char *ufile)
{
    tid_t tid;
    char *cur_file = copy_in_string (ufile);

    lock_acquire (&fs_lock);
    tid = process_execute (cur_file);
    lock_release (&fs_lock);

    palloc_free_page (cur_file);

    return tid;
}

/* Wait system call. */
static int
sys_wait (tid_t child)
{
    return process_wait (child);
}

/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size)
{
    char *cur_file = copy_in_string (ufile);
    bool ok;

    lock_acquire (&fs_lock);
    ok = filesys_create (cur_file, initial_size, false);
    lock_release (&fs_lock);

    palloc_free_page (cur_file);

    return ok;
}

/* Remove system call. */
static int
sys_remove (const char *ufile)
{
    char *cur_file = copy_in_string (ufile);
    bool ok;

    lock_acquire (&fs_lock);
    ok = filesys_remove (cur_file);
    lock_release (&fs_lock);

    palloc_free_page (cur_file);

    return ok;
}

/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
{
    struct list_elem elem;      /* List element. */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
    bool is_directory;                 /* Is directory */
};

/* Open system call. */
static int
sys_open (const char *ufile)
{
    char *cur_file = copy_in_string (ufile);
    struct file_descriptor *fd;
    int handle = -1;

    fd = malloc (sizeof *fd);

    if (fd != NULL)
    {
        lock_acquire (&fs_lock);
        fd->file = filesys_open (cur_file);

        if (fd->file != NULL)
        {
            /* if it's directory */
            if (inode_is_dir(file_get_inode(fd->file)))
                fd->is_directory = true;
            else
                fd->is_directory = false;

            struct thread *cur_thread = thread_current ();
            handle = fd->handle = cur_thread->next_handle++;
            list_push_front (&cur_thread->fds, &fd->elem);
        }
        else
            free (fd);
        lock_release (&fs_lock);
    }

    palloc_free_page (cur_file);
    return handle;
}

/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
    struct thread *cur_thread = thread_current ();
    struct list_elem *e;

    for (e = list_begin (&cur_thread->fds); e != list_end (&cur_thread->fds);
         e = list_next (e))
    {
        struct file_descriptor *fd;
        fd = list_entry (e, struct file_descriptor, elem);
        if (fd->handle == handle)
            return fd;
    }

    thread_exit ();
}

/* Filesize system call. */
static int
sys_filesize (int handle)
{
    struct file_descriptor *fd = lookup_fd (handle);
    int size;

    lock_acquire (&fs_lock);
    size = file_length (fd->file);
    lock_release (&fs_lock);

    return size;
}

/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size)
{
    uint8_t *udst = udst_;
    struct file_descriptor *fd;
    int bytes_read = 0;

    /* Handle keyboard reads. */
    if (handle == STDIN_FILENO)
    {
        for (bytes_read = 0; (size_t) bytes_read < size; bytes_read++)
            if (udst >= (uint8_t *) PHYS_BASE || !put_user (udst++, input_getc ()))
                thread_exit ();
        return bytes_read;
    }

    /* Handle all other reads. */
    fd = lookup_fd (handle);
    lock_acquire (&fs_lock);
    while (size > 0)
    {
        /* How much to read into this page? */
        size_t page_left = PGSIZE - pg_ofs (udst);
        size_t read_amt = size < page_left ? size : page_left;
        off_t retval;

        /* Check that touching this page is okay. */
        if (!verify_user (udst))
        {
            lock_release (&fs_lock);
            thread_exit ();
        }

        /* Read from file into page. */
        retval = file_read (fd->file, udst, read_amt);
        if (retval < 0)
        {
            if (bytes_read == 0)
                bytes_read = -1;
            break;
        }
        bytes_read += retval;

        /* If it was a short read we're done. */
        if (retval != (off_t) read_amt)
            break;

        /* Advance. */
        udst += retval;
        size -= retval;
    }
    lock_release (&fs_lock);

    return bytes_read;
}

/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size)
{
    uint8_t *usrc = usrc_;
    struct file_descriptor *fd = NULL;
    int bytes_written = 0;

    /* Lookup up file descriptor. */
    if (handle != STDOUT_FILENO)
        fd = lookup_fd (handle);

    /* if it's directory */
    if (fd != NULL && fd->is_directory)
        return -1;

    lock_acquire (&fs_lock);
    while (size > 0)
    {
        /* How much bytes to write to this page? */
        size_t page_left = PGSIZE - pg_ofs (usrc);
        size_t write_amt = size < page_left ? size : page_left;
        off_t retval;

        /* Check that we can touch this user page. */
        if (!verify_user (usrc))
        {
            lock_release (&fs_lock);
            thread_exit ();
        }

        /* Do the write. */
        if (handle == STDOUT_FILENO)
        {
            putbuf (usrc, write_amt);
            retval = write_amt;
        }
        else
            retval = file_write (fd->file, usrc, write_amt);
        if (retval < 0)
        {
            if (bytes_written == 0)
                bytes_written = -1;
            break;
        }
        bytes_written += retval;

        /* If it was a short write we're done. */
        if (retval != (off_t) write_amt)
            break;

        /* Advance. */
        usrc += retval;
        size -= retval;
    }
    lock_release (&fs_lock);

    return bytes_written;
}

/* Seek system call. */
static int
sys_seek (int handle, unsigned position)
{
    struct file_descriptor *fd = lookup_fd (handle);

    lock_acquire (&fs_lock);
    if ((off_t) position >= 0) {
        file_seek (fd->file, position);
    }
    lock_release (&fs_lock);

    return 0;
}

/* Tell system call. */
static int
sys_tell (int handle)
{
    struct file_descriptor *fd = lookup_fd (handle);
    unsigned position;

    lock_acquire (&fs_lock);
    position = file_tell (fd->file);
    lock_release (&fs_lock);

    return position;
}

/* Close system call. */
static int
sys_close (int handle)
{
    struct file_descriptor *fd = lookup_fd (handle);
    lock_acquire (&fs_lock);
    file_close (fd->file);
    lock_release (&fs_lock);
    list_remove (&fd->elem);
    free (fd);
    return 0;
}

/* On thread exit, close all open files. */
void
syscall_exit (void)
{
    struct thread *cur_thread = thread_current ();
    struct list_elem *e, *next;

    for (e = list_begin (&cur_thread->fds); e != list_end (&cur_thread->fds); e = next)
    {
        struct file_descriptor *fd;
        fd = list_entry (e, struct file_descriptor, elem);
        next = list_next (e);
        lock_acquire (&fs_lock);
        file_close (fd->file);
        lock_release (&fs_lock);
        free (fd);
    }
}

void validate_user_ptr(const void *user_ptr) {
    if (!is_user_vaddr(user_ptr) || user_ptr  < ((void *) 0x08048000))
        sys_exit(-1);

    void *valid_ptr = pagedir_get_page(thread_current()->pagedir, user_ptr);

    if (valid_ptr == NULL)
    {
        sys_exit(-1);
    }
}

static bool sys_chdir (const char* dir)
{
    return filesys_chdir(dir);
}

static bool sys_mkdir (const char* dir)
{
    return filesys_create(dir, 0, true);
}

static bool sys_readdir (int handle, char* name)
{

    struct file_descriptor *fd;

    /* not able to find the handle */
    /* is not directory */
    if (!(fd = lookup_fd (handle)) || !fd->is_directory)
        return false;

    /* cannot read the directory */
    if (!dir_readdir((struct dir *)fd->file, name))
    {
        return false;
    }

    return true;
}

static bool sys_isdir (int handle)
{

    struct file_descriptor *fd;

    if (!(fd = lookup_fd (handle))) {
        return -1;
    }

    return fd->is_directory;
}

static int sys_inumber (int handle)
{
    struct file_descriptor *fd;
    block_sector_t inumber;

    if (!(fd = lookup_fd (handle))) {
        return -1;
    }

    if (fd->is_directory) {
        inumber = inode_get_inumber(dir_get_inode((struct dir *) fd->file));
    } else {
        inumber = inode_get_inumber(file_get_inode(fd->file));
    }

    return inumber;
}
