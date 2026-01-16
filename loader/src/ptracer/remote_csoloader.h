#ifndef REMOTE_CSOLOADER_H
#define REMOTE_CSOLOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utils.h"

bool remote_csoloader_load_and_resolve_entry(int pid, struct user_regs_struct *regs,
                                             uintptr_t libc_return_addr, struct maps *local_map,
                                             struct maps *remote_map, const char *libc_path,
                                             const char *lib_path, uintptr_t *out_base,
                                             size_t *out_total_size, uintptr_t *out_entry);

#endif
