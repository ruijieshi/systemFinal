#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/thread.h"


struct cache_entry* cache_block (block_sector_t sector)
{
    struct cache_entry *cache;
    struct list_elem *elem;
    for (elem = list_begin(&filesys_cache); elem != list_end(&filesys_cache);
         elem = list_next(elem))
    {
        cache = list_entry(elem, struct cache_entry, elem);
        if (cache->sector == sector)
        {
            return cache;
        }
    }
    return NULL;
}

void filesys_cache_init (void)
{
    list_init(&filesys_cache);
    lock_init(&filesys_cache_lock);
    filesys_cache_size = 0;
    thread_create("filesys_cache_writeback", 0, thread_back_write, NULL);
}

struct cache_entry* filesys_cache_block_clean (block_sector_t sector,
                                               bool dirty)
{
    struct cache_entry *cache;
    if (filesys_cache_size < MAX_CACHE_SIZE)
    {
        filesys_cache_size++;
        cache = malloc(sizeof(struct cache_entry));
        if (!cache)
        {
            return NULL;
        }
        cache->open_cnt = 0;
        list_push_back(&filesys_cache, &cache->elem);
    }
    else
    {
        bool loop = true;
        while (loop)
        {
            struct list_elem *e;
            for (e = list_begin(&filesys_cache); e != list_end(&filesys_cache);
                 e = list_next(e))
            {
                cache = list_entry(e, struct cache_entry, elem);
                if (cache->open_cnt > 0)
                {
                    continue;
                }
                if (cache->accessed)
                {
                    cache->accessed = false;
                }
                else
                {
                    if (cache->dirty)
                    {
                        block_write(fs_device, cache->sector, &cache->block);
                    }
                    loop = false;
                    break;
                }
            }
        }
    }
    cache->open_cnt++;
    cache->sector = sector;
    block_read(fs_device, cache->sector, &cache->block);
    cache->dirty = dirty;
    cache->accessed = true;
    return cache;
}

struct cache_entry* filesys_cache_block_get (block_sector_t sector,
                                             bool dirty)
{
    lock_acquire(&filesys_cache_lock);
    struct cache_entry *cache = cache_block(sector);
    if (cache)
    {
        cache->open_cnt++;
        cache->dirty |= dirty;
        cache->accessed = true;
        lock_release(&filesys_cache_lock);
        return cache;
    }
    cache = filesys_cache_block_clean(sector, dirty);
    if (!cache)
    {
        PANIC("Please note there is not enough memory for cache!");
    }
    lock_release(&filesys_cache_lock);
    return cache;
}

void filesys_cache_write_to_disk (bool halt)
{
    lock_acquire(&filesys_cache_lock);
    struct list_elem *next, *e = list_begin(&filesys_cache);
    while (e != list_end(&filesys_cache))
    {
        next = list_next(e);
        struct cache_entry *cache = list_entry(e, struct cache_entry, elem);
        if (cache->dirty)
        {
            block_write (fs_device, cache->sector, &cache->block);
            cache->dirty = false;
        }
        if (halt)
        {
            list_remove(&cache->elem);
            free(cache);
        }
        e = next;
    }
    lock_release(&filesys_cache_lock);
}

void thread_forward_read (void *aux)
{
    block_sector_t sector = * (block_sector_t *) aux;
    lock_acquire(&filesys_cache_lock);
    struct cache_entry *cache = cache_block(sector);
    if (!cache)
    {
        filesys_cache_block_clean(sector, false);
    }
    lock_release(&filesys_cache_lock);
    free(aux);
}

void spawn_thread_read_ahead (block_sector_t sector)
{
    block_sector_t *arg = malloc(sizeof(block_sector_t));
    if (arg)
    {
        *arg = sector + 1;
        thread_create("filesys_cache_readahead", 0, thread_forward_read,
                      arg);
    }
}

void thread_back_write (void *aux UNUSED)
{
    while (true)
    {
        timer_sleep(WRITE_CACHE);
        filesys_cache_write_to_disk(false);
    }
}
