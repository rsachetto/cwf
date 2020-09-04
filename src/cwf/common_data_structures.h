#ifndef __COMMOM_DATA_STRUCTURES_H
#define __COMMOM_DATA_STRUCTURES_H

typedef char *char_array;
typedef char **string_array;

typedef struct string_hash_entry_t {
    char *key;
    char *value;
} string_hash_entry;

typedef struct string_hash_entry_t *string_hash;

#endif /* __COMMOM_DATA_STRUCTURES_H */
