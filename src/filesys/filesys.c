#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "threads/malloc.h"

#define ASCII_SLASH 47

/* Partition that contains the file system. */
struct block *fs_device;
struct dir* get_contain_directory (const char* path);
char* get_file_name (const char* path);

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  filesys_cache_init();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  filesys_cache_write_to_disk(true);
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool isdir)
{
    block_sector_t inode_sector = 0;
    struct dir *directory = get_contain_directory(name);
    char* file_name = get_file_name(name);
    bool success = false;
    if (strcmp(file_name, ".") != 0 && strcmp(file_name, "..") != 0)
    {
        success = (directory != NULL
                   && free_map_allocate (1, &inode_sector)
                   && inode_create (inode_sector, initial_size, isdir)
                   && dir_add (directory, file_name, inode_sector));
    }
    if (!success && inode_sector != 0)
      free_map_release (inode_sector, 1);
    dir_close (directory);
    free(file_name);
    return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
    if (strlen(name) == 0)
    {
        return NULL;
    }
    struct dir* directory = get_contain_directory(name);
    char* file_name = get_file_name(name);
    struct inode *inode = NULL;

    if (directory != NULL)
    {
        if (strcmp(file_name, "..") == 0)
        {
            if (!dir_get_parent(directory, &inode))
            {
                free(file_name);
                return NULL;
            }
        }
        else if ((dir_is_root(directory) && strlen(file_name) == 0) ||
                 strcmp(file_name, ".") == 0)
        {
            free(file_name);
            return (struct file *) directory;
        }
        else
        {
            dir_lookup (directory, file_name, &inode);
        }
    }

    dir_close (directory);
    free(file_name);

    if (!inode)
    {
        return NULL;
    }

    if (inode_is_dir(inode))
    {
        return (struct file *) dir_open(inode);
    }
    return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
    struct dir* directory = get_contain_directory(name);
    char* file_name = get_file_name(name);
    bool success = directory != NULL && dir_remove (directory, file_name);
    dir_close (directory);
    free(file_name);

    return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

struct dir* get_contain_directory (const char* path)
{
    char s[strlen(path) + 1];
    memcpy(s, path, strlen(path) + 1);

    char *save_ptr, *next_token = NULL, *token = strtok_r(s, "/", &save_ptr);
    struct dir* directory;
    if (s[0] == ASCII_SLASH || !thread_current()->cwd)
    {
        directory = dir_open_root();
    }
    else
    {
        directory = dir_reopen(thread_current()->cwd);
    }

    if (token)
    {
        next_token = strtok_r(NULL, "/", &save_ptr);
    }
    while (next_token != NULL)
    {
        if (strcmp(token, ".") != 0)
        {
            struct inode *inode;
            if (strcmp(token, "..") == 0)
            {
                if (!dir_get_parent(directory, &inode))
                {
                    return NULL;
                }
            }
            else
            {
                if (!dir_lookup(directory, token, &inode))
                {
                    return NULL;
                }
            }
            if (inode_is_dir(inode))
            {
                dir_close(directory);
                directory = dir_open(inode);
            }
            else
            {
                inode_close(inode);
            }
        }
        token = next_token;
        next_token = strtok_r(NULL, "/", &save_ptr);
    }
    return directory;
}

bool filesys_chdir (const char* name)
{
    struct dir* directory = get_contain_directory(name);
    char* file_name = get_file_name(name);
    struct inode *inode = NULL;

    if (directory != NULL)
    {
        if (strcmp(file_name, "..") == 0)
        {
            if (!dir_get_parent(directory, &inode))
            {
                free(file_name);
                return false;
            }
        }
        else if ((dir_is_root(directory) && strlen(file_name) == 0) ||
                 strcmp(file_name, ".") == 0)
        {
            thread_current()->cwd = directory;
            free(file_name);
            return true;
        }
        else
        {
            dir_lookup (directory, file_name, &inode);
        }
    }

    dir_close (directory);
    free(file_name);

    directory = dir_open (inode);
    if (directory)
    {
        dir_close(thread_current()->cwd);
        thread_current()->cwd = directory;
        return true;
    }
    return false;
}

char* get_file_name (const char* path)
{
    char s[strlen(path) + 1];
    memcpy(s, path, strlen(path) + 1);

    char *token, *save_ptr, *prev_token = "";
    for (token = strtok_r(s, "/", &save_ptr); token != NULL;
         token = strtok_r (NULL, "/", &save_ptr))
    {

        prev_token = token;
    }
    char *file_name = malloc(strlen(prev_token) + 1);
    memcpy(file_name, prev_token, strlen(prev_token) + 1);
    return file_name;
}