/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "py/bc.h"
#include "py/gc.h"
#include "py/objarray.h"
#include "py/objfun.h"
#include "py/objgenerator.h"
#include "py/objlist.h"
#include "py/objstr.h"
#include "py/objtype.h"
#include "py/runtime.h"

#include "version.h"

#if MICROPY_PY_TREZORUTILS

#include "embed/extmod/trezorobj.h"

#include <string.h>
#include "common.h"

/// def consteq(sec: bytes, pub: bytes) -> bool:
///     """
///     Compares the private information in `sec` with public, user-provided
///     information in `pub`.  Runs in constant time, corresponding to a length
///     of `pub`.  Can access memory behind valid length of `sec`, caller is
///     expected to avoid any invalid memory access.
///     """
STATIC mp_obj_t mod_trezorutils_consteq(mp_obj_t sec, mp_obj_t pub) {
  mp_buffer_info_t secbuf = {0};
  mp_get_buffer_raise(sec, &secbuf, MP_BUFFER_READ);
  mp_buffer_info_t pubbuf = {0};
  mp_get_buffer_raise(pub, &pubbuf, MP_BUFFER_READ);

  size_t diff = secbuf.len - pubbuf.len;
  for (size_t i = 0; i < pubbuf.len; i++) {
    const uint8_t *s = (uint8_t *)secbuf.buf;
    const uint8_t *p = (uint8_t *)pubbuf.buf;
    diff |= s[i] - p[i];
  }

  if (diff == 0) {
    return mp_const_true;
  } else {
    return mp_const_false;
  }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorutils_consteq_obj,
                                 mod_trezorutils_consteq);

#define WORDS_PER_BLOCK ((MICROPY_BYTES_PER_GC_BLOCK) / BYTES_PER_WORD)
#define BYTES_PER_BLOCK (MICROPY_BYTES_PER_GC_BLOCK)

// ATB = allocation table byte
// 0b00 = FREE -- free block
// 0b01 = HEAD -- head of a chain of blocks
// 0b10 = TAIL -- in the tail of a chain of blocks
// 0b11 = MARK -- marked head block

#define AT_FREE (0)
#define AT_HEAD (1)
#define AT_TAIL (2)
#define AT_MARK (3)

#define BLOCKS_PER_ATB (4)
#define ATB_MASK_0 (0x03)
#define ATB_MASK_1 (0x0c)
#define ATB_MASK_2 (0x30)
#define ATB_MASK_3 (0xc0)

#define ATB_0_IS_FREE(a) (((a)&ATB_MASK_0) == 0)
#define ATB_1_IS_FREE(a) (((a)&ATB_MASK_1) == 0)
#define ATB_2_IS_FREE(a) (((a)&ATB_MASK_2) == 0)
#define ATB_3_IS_FREE(a) (((a)&ATB_MASK_3) == 0)

#define BLOCK_SHIFT(block) (2 * ((block) & (BLOCKS_PER_ATB - 1)))
#define ATB_GET_KIND(block)                                         \
  ((MP_STATE_MEM(gc_alloc_table_start)[(block) / BLOCKS_PER_ATB] >> \
    BLOCK_SHIFT(block)) &                                           \
   3)
#define ATB_ANY_TO_FREE(block)                                        \
  do {                                                                \
    MP_STATE_MEM(gc_alloc_table_start)                                \
    [(block) / BLOCKS_PER_ATB] &= (~(AT_MARK << BLOCK_SHIFT(block))); \
  } while (0)
#define ATB_FREE_TO_HEAD(block)                                    \
  do {                                                             \
    MP_STATE_MEM(gc_alloc_table_start)                             \
    [(block) / BLOCKS_PER_ATB] |= (AT_HEAD << BLOCK_SHIFT(block)); \
  } while (0)
#define ATB_FREE_TO_TAIL(block)                                    \
  do {                                                             \
    MP_STATE_MEM(gc_alloc_table_start)                             \
    [(block) / BLOCKS_PER_ATB] |= (AT_TAIL << BLOCK_SHIFT(block)); \
  } while (0)
#define ATB_HEAD_TO_MARK(block)                                    \
  do {                                                             \
    MP_STATE_MEM(gc_alloc_table_start)                             \
    [(block) / BLOCKS_PER_ATB] |= (AT_MARK << BLOCK_SHIFT(block)); \
  } while (0)
#define ATB_MARK_TO_HEAD(block)                                       \
  do {                                                                \
    MP_STATE_MEM(gc_alloc_table_start)                                \
    [(block) / BLOCKS_PER_ATB] &= (~(AT_TAIL << BLOCK_SHIFT(block))); \
  } while (0)

#define BLOCK_FROM_PTR(ptr) \
  (((byte *)(ptr)-MP_STATE_MEM(gc_pool_start)) / BYTES_PER_BLOCK)
#define PTR_FROM_BLOCK(block) \
  (((block)*BYTES_PER_BLOCK + (uintptr_t)MP_STATE_MEM(gc_pool_start)))
#define ATB_FROM_BLOCK(bl) ((bl) / BLOCKS_PER_ATB)

// ptr should be of type void*
#define VERIFY_PTR(ptr)                                                       \
  (((uintptr_t)(ptr) & (BYTES_PER_BLOCK - 1)) ==                              \
       0 /* must be aligned on a block */                                     \
   && ptr >= (void *)MP_STATE_MEM(                                            \
                 gc_pool_start) /* must be above start of pool */             \
   && ptr < (void *)MP_STATE_MEM(gc_pool_end) /* must be below end of pool */ \
  )

size_t find_allocated_size(void const *const ptr) {
  if (!ptr) {
    return 0;
  }

  if (!VERIFY_PTR(ptr)) {
    // printf("failed to verify ptr: %p\n", ptr);
    return 0;
  }

  size_t block = BLOCK_FROM_PTR(ptr);
  if (ATB_GET_KIND(block) == AT_TAIL) {
    return 0;
  }
  size_t n = 0;
  do {
    ++n;
  } while (ATB_GET_KIND(block + n) == AT_TAIL);
  return n;
}

void dump_value(FILE *out, mp_const_obj_t value);

void mark(void const *const ptr) {
  if (!VERIFY_PTR(ptr)) return;
  size_t block = BLOCK_FROM_PTR(ptr);
  if (ATB_GET_KIND(block) == AT_HEAD) {
    ATB_HEAD_TO_MARK(block);
  }
}

bool is_short(mp_const_obj_t value) {
  return value == NULL || value == MP_OBJ_NULL || mp_obj_is_qstr(value) ||
         mp_obj_is_small_int(value) || !VERIFY_PTR(value);
}

static void print_type(FILE *out, const char *typename, const char *shortval,
                       const void *ptr, bool end) {
  static char unescaped[1000];
  size_t size = 0;
  if (!is_short(ptr)) {
    size = find_allocated_size(ptr);
  }
  fprintf(out, "{\"type\": \"%s\", \"alloc\": %ld, \"ptr\": \"%p\"", typename,
          size, ptr);
  if (shortval) {
    assert(strlen(shortval) < 1000);
    char *c = unescaped;
    while (*shortval) {
      if (*shortval == '\\' || *shortval == '"') *c++ = '\\';
      *c++ = *shortval++;
    }
    *c = 0;
    fprintf(out, ", \"shortval\": \"%s\"", unescaped);
  } else {
    fprintf(out, ", \"shortval\": null");
  }
  if (end) fprintf(out, "}");
}

static void print_repr(FILE *out, const char *strbuf, size_t buflen) {
  fprintf(out, "\"");
  for (size_t i = 0; i < buflen; ++i) {
    if (strbuf[i] == '\\')
      fprintf(out, "\\\\");
    else if (strbuf[i] == '"')
      fprintf(out, "\\\"");
    else if (strbuf[i] >= 0x20 && strbuf[i] <= 0x7e)
      fprintf(out, "%c", strbuf[i]);
    else
      fprintf(out, "\\\\x%02x", (unsigned char)strbuf[i]);
  }
  fprintf(out, "\"");
}

void dump_short(FILE *out, mp_const_obj_t value) {
  fflush(out);
  if (value == NULL || value == MP_OBJ_NULL) {
    fprintf(out, "null");

  } else if (mp_obj_is_qstr(value)) {
    mp_int_t q = MP_OBJ_QSTR_VALUE(value);
    print_type(out, "qstr", qstr_str(q), NULL, true);

  } else if (mp_obj_is_small_int(value)) {
    static char num_buf[100];
    snprintf(num_buf, 100, "%ld", MP_OBJ_SMALL_INT_VALUE(value));
    print_type(out, "smallint", num_buf, NULL, true);

  } else if (!VERIFY_PTR(value)) {
    /*if (mp_obj_is_str(value)) {
      size_t len = 0;
      const char *val = mp_obj_str_get_data((mp_obj_t)value, &len);
      print_type(out, "romstr", NULL, value, false);
      fprintf(out, ", \"val\": ");
      print_repr(out, val, len);
      fprintf(out, "},\n");
    } else*/ {
      print_type(out, "romdata", NULL, value, true);
    }
  }
}

void dump_short_or_ptr(FILE *out, mp_const_obj_t value) {
  if (is_short(value))
    dump_short(out, value);
  else
    fprintf(out, "\"%p\"", value);
}

void dump_map_as_children(FILE *out, const mp_map_t *map) {
  fprintf(out, ", \"children\": [");
  bool first = true;
  for (size_t i = 0; i < map->alloc; ++i) {
    if (!mp_map_slot_is_filled(map, i)) continue;
    if (!first) fprintf(out, ",\n");
    first = false;
    fprintf(out, "{\"key\": ");
    dump_short_or_ptr(out, map->table[i].key);
    fprintf(out, ",\n\"value\": ");
    dump_short_or_ptr(out, map->table[i].value);
    fprintf(out, "}");
  }
  fprintf(out, "]");
}

void dump_map_as_values(FILE *out, const void *const owner,
                        const mp_map_t *map) {
  print_type(out, "mapitems", NULL, map->table, false);
  fprintf(out, ",\n\"owner\": \"%p\"", owner);
  fprintf(out, "},\n");

  for (size_t i = 0; i < map->alloc; ++i) {
    if (!mp_map_slot_is_filled(map, i)) continue;
    dump_value(out, map->table[i].key);
    dump_value(out, map->table[i].value);
  }
}

void dump_dict_inner(FILE *out, const mp_obj_dict_t *dict) {
  print_type(out, "dict", NULL, dict, false);
  dump_map_as_children(out, &dict->map);
  fprintf(out, "},\n");
  dump_map_as_values(out, dict, &dict->map);
}

void dump_function(FILE *out, const mp_obj_fun_bc_t *func) {
  print_type(out, "function", NULL, func, false);
  fprintf(out, ",\n\"globals\": \"%p\"", func->globals);
  fprintf(out, ",\n\"code_alloc\": %ld", find_allocated_size(func->bytecode));
  fprintf(out, ",\n\"code_ptr\": \"%p\"", func->bytecode);
  fprintf(out, ",\n\"const_table_alloc\": %ld",
          find_allocated_size(func->const_table));
  fprintf(out, ",\n\"const_table_ptr\": \"%p\"", func->const_table);
  mark(func->bytecode);
  mark(func->const_table);

  /*fprintf(out, ",\n\"extra_args\": [\n");
  char *maxptr =
      ((char *)func) + find_allocated_size(func) * BYTES_PER_BLOCK;
  bool first = true;
  for (mp_const_obj_t arg = func->extra_args; ((void *)arg) < ((void *)maxptr);
       ++arg) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, arg);
  }
  fprintf(out, "]},\n");*/
  fprintf(out, "},\n");

  dump_value(out, func->globals);
  /*for (mp_const_obj_t arg = func->extra_args; ((void *)arg) < ((void *)maxptr);
       ++arg) {
    dump_value(out, arg);
  }*/
}

typedef struct _mp_obj_bound_meth_t {
  mp_obj_base_t base;
  mp_obj_t meth;
  mp_obj_t self;
} mp_obj_bound_meth_t;

typedef struct _mp_obj_closure_t {
  mp_obj_base_t base;
  mp_obj_t fun;
  size_t n_closed;
  mp_obj_t closed[];
} mp_obj_closure_t;

extern const mp_obj_type_t mp_type_bound_meth;
extern const mp_obj_type_t closure_type;
extern const mp_obj_type_t mp_type_cell;
extern const mp_obj_type_t mod_trezorio_WebUSB_type;
extern const mp_obj_type_t mod_trezorio_USB_type;
extern const mp_obj_type_t mod_trezorio_VCP_type;
extern const mp_obj_type_t mod_trezorui_Display_type;

void dump_bound_method(FILE *out, const mp_obj_bound_meth_t *meth) {
  print_type(out, "method", NULL, meth, false);

  fprintf(out, ",\n\"self\": \"%p\"", meth->self);
  fprintf(out, ",\n\"body\": \"%p\"", meth->meth);
  fprintf(out, "},");

  dump_value(out, meth->self);
  dump_value(out, meth->meth);
}

void dump_static_method(FILE *out, const mp_obj_static_class_method_t *meth) {
  print_type(out, "staticmethod", NULL, meth, false);
  fprintf(out, ",\n\"body\": \"%p\"", meth->fun);
  fprintf(out, "},");
  dump_value(out, meth->fun);
}

void dump_closure(FILE *out, const mp_obj_closure_t *closure) {
  size_t size = find_allocated_size(closure);
  for (size_t i = 0; i < closure->n_closed; ++i) {
    // XXX this is unimportant to track properly, hopefully
    size += find_allocated_size(closure->closed[i]);
    assert(mp_obj_is_type(closure->closed[i], &mp_type_cell));
  }
  print_type(out, "closure", NULL, closure, false);

  fprintf(out, ",\n\"function\": \"%p\"", closure->fun);
  fprintf(out, ",\n\"closed\": [\n");
  bool first = true;
  for (size_t i = 0; i < closure->n_closed; ++i) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, mp_obj_cell_get(closure->closed[i]));
  }
  fprintf(out, "]},");

  dump_value(out, closure->fun);
  for (size_t i = 0; i < closure->n_closed; ++i) {
    dump_value(out, mp_obj_cell_get(closure->closed[i]));
  }
}

typedef struct _mp_obj_gen_instance_t {
  mp_obj_base_t base;
  // mp_const_none: Not-running, no exception.
  // MP_OBJ_NULL: Running, no exception.
  // other: Not running, pending exception.
  mp_obj_t pend_exc;
  mp_code_state_t code_state;
} mp_obj_gen_instance_t;

void dump_generator(FILE *out, const mp_obj_gen_instance_t *gen) {
  print_type(out, "generator", NULL, gen, false);

  fprintf(out, ",\n\"pending_exception\": \"%p\"", gen->pend_exc);
  fprintf(out, ",\n\"function\": \"%p\"", gen->code_state.fun_bc);
  fprintf(out, ",\n\"old_globals\": \"%p\"", gen->code_state.old_globals);
  fprintf(out, ",\n\"state\": [\n");
  bool first = true;
  for (size_t i = 0; i < gen->code_state.n_state; ++i) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, gen->code_state.state[i]);
  }

  fprintf(out, "]},\n");
  dump_value(out, gen->pend_exc);
  dump_value(out, gen->code_state.fun_bc);
  dump_value(out, gen->code_state.old_globals);
  for (size_t i = 0; i < gen->code_state.n_state; ++i) {
    dump_value(out, gen->code_state.state[i]);
  }
}

void dump_instance(FILE *out, const mp_obj_instance_t *obj) {
  print_type(out, "instance", NULL, obj, false);
  fprintf(out, ",\n\"base\": \"%p\"", obj->base.type);
  dump_map_as_children(out, &obj->members);
  /*fprintf(out, ",\n\"subobjs\": [\n");
  char *maxptr = ((char *)obj) + find_allocated_size(obj) * BYTES_PER_BLOCK;
  bool first = true;
  for (mp_const_obj_t arg = obj->subobj; ((void *)arg) < ((void *)maxptr);
       ++arg) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, arg);
  }
  fprintf(out, "]},\n");*/
  fprintf(out, "},\n");

  dump_value(out, obj->base.type);
  dump_map_as_values(out, obj, &obj->members);
  /*for (mp_const_obj_t arg = obj->subobj; ((void *)arg) < ((void *)maxptr);
       ++arg) {
    dump_value(out, arg);
  }*/
}

void dump_type(FILE *out, const mp_obj_type_t *type) {
  print_type(out, "type", qstr_str(type->name), type, false);
  fprintf(out, ",\n\"locals\": \"%p\"", type->locals_dict);
  fprintf(out, ",\n\"parent\": \"%p\"},\n", type->parent);

  dump_value(out, type->parent);
  dump_value(out, type->locals_dict);
}

void dump_list(FILE *out, const mp_obj_list_t *list) {
  print_type(out, "list", NULL, list, false);
  fprintf(out, ",\n\"items\": [\n");
  bool first = true;
  for (size_t i = 0; i < list->len; ++i) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, list->items[i]);
  }
  fprintf(out, "]},\n");

  print_type(out, "listitems", NULL, list->items, false);
  fprintf(out, ",\n\"owner\": \"%p\"},\n", list);
  for (size_t i = 0; i < list->len; ++i) {
    dump_value(out, list->items[i]);
  }
}

void dump_tuple(FILE *out, const mp_obj_tuple_t *tuple) {
  print_type(out, "tuple", NULL, tuple, false);
  fprintf(out, ",\n\"items\": [\n");
  bool first = true;
  for (size_t i = 0; i < tuple->len; ++i) {
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, tuple->items[i]);
  }
  fprintf(out, "]},\n");

  for (size_t i = 0; i < tuple->len; ++i) {
    dump_value(out, tuple->items[i]);
  }
}

typedef struct _mp_obj_set_t {
  mp_obj_base_t base;
  mp_set_t set;
} mp_obj_set_t;

STATIC bool is_set_or_frozenset(mp_const_obj_t o) {
  return mp_obj_is_type(o, &mp_type_set)
#if MICROPY_PY_BUILTINS_FROZENSET
         || mp_obj_is_type(o, &mp_type_frozenset)
#endif
      ;
}

void dump_set(FILE *out, const mp_obj_set_t *set) {
  print_type(out, "set", NULL, set, false);
  fprintf(out, ",\n\"items\": [\n");
  bool first = true;
  for (size_t i = 0; i < set->set.alloc; ++i) {
    if (!mp_set_slot_is_filled(&set->set, i)) continue;
    if (!first) fprintf(out, ",\n");
    first = false;
    dump_short_or_ptr(out, set->set.table[i]);
  }
  fprintf(out, "]},\n");

  print_type(out, "setitems", NULL, set->set.table, false);
  fprintf(out, ",\n\"owner\": \"%p\"},\n", set);

  for (size_t i = 0; i < set->set.alloc; ++i) {
    if (!mp_set_slot_is_filled(&set->set, i)) continue;
    dump_value(out, set->set.table[i]);
  }
}

void dump_value(FILE *out, mp_const_obj_t value) {
  if (is_short(value)) return;

  size_t block = BLOCK_FROM_PTR(value);
  switch (ATB_GET_KIND(block)) {
    case AT_HEAD:
      // all is ok
      ATB_HEAD_TO_MARK(block);
      break;
    case AT_TAIL:
      printf("===== pointer to tail???\n");
      break;
    case AT_MARK:
      // print_type(out, "already_dumped", 0, NULL, value);
      return;
  }

  if (mp_obj_is_str_or_bytes(value)) {
    size_t len = 0;
    const char *val = mp_obj_str_get_data((mp_obj_t)value, &len);
    print_type(out, "anystr", NULL, value, false);
    fprintf(out, ", \"val\": ");
    print_repr(out, val, len);
    fprintf(out, "},\n");
  }

  else if (mp_obj_is_type(value, &mp_type_bytearray)) {
    const mp_obj_array_t *array = (mp_obj_array_t *)value;
    print_type(out, "array", NULL, array, true);
    fprintf(out, ",\n");
    print_type(out, "arrayitems", NULL, array->items, false);
    fprintf(out, ", \"owner\": \"%p\"}", array);
    fprintf(out, ",\n");
  }

  else if (mp_obj_is_type(value, &mp_type_dict)) {
    dump_dict_inner(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_module)) {
    print_type(out, "module", NULL, value, false);
    mp_obj_module_t *module = MP_OBJ_TO_PTR(value);
    fprintf(out, ", \"globals\": \"%p\"", module->globals);
    fprintf(out, "},\n");
    dump_value(out, module->globals);
  }

  else if (mp_obj_is_type(value, &mp_type_fun_bc) ||
           mp_obj_is_type(value, &mp_type_gen_wrap)) {
    dump_function(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_bound_meth)) {
    dump_bound_method(out, value);
  }

  else if (mp_obj_is_type(value, &closure_type)) {
    dump_closure(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_staticmethod) ||
           mp_obj_is_type(value, &mp_type_classmethod)) {
    dump_static_method(out, value);
  }

  else if (mp_obj_is_instance_type(mp_obj_get_type(value))) {
    dump_instance(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_object)) {
    print_type(out, "object", NULL, value, true);
    fprintf(out, ",\n");
  }

  else if (mp_obj_is_type(value, &mp_type_type)) {
    dump_type(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_list)) {
    dump_list(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_tuple)) {
    dump_tuple(out, value);
  }

  else if (is_set_or_frozenset(value)) {
    dump_set(out, value);
  }

  else if (mp_obj_is_type(value, &mp_type_gen_instance)) {
    dump_generator(out, value);
  }

  else if (mp_obj_is_type(value, &mod_trezorio_WebUSB_type) ||
           mp_obj_is_type(value, &mod_trezorio_USB_type) ||
           mp_obj_is_type(value, &mod_trezorio_VCP_type) ||
           mp_obj_is_type(value, &mod_trezorui_Display_type)) {
    print_type(out, "trezor", NULL, value, true);
    fprintf(out, ",\n");
  }

  else {
    print_type(out, "unknown", NULL, value, true);
    fprintf(out, ",\n");
  }

  fflush(out);
}

STATIC mp_obj_t mod_trezorutils_meminfo(mp_obj_t filename) {
  size_t fn_len;
  FILE *out = fopen(mp_obj_str_get_data(filename, &fn_len), "w");
  fprintf(out, "[");
  dump_value(out, MP_STATE_THREAD(dict_locals));
  fprintf(out, "null]\n");
  fclose(out);
  for (size_t block = 0;
       block < MP_STATE_MEM(gc_alloc_table_byte_len) * BLOCKS_PER_ATB;
       block++) {
    if (ATB_GET_KIND(block) == AT_MARK) {
      ATB_MARK_TO_HEAD(block);
    }
  }

  gc_dump_alloc_table();
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorutils_meminfo_obj,
                                 mod_trezorutils_meminfo);
/// def memcpy(
///     dst: Union[bytearray, memoryview],
///     dst_ofs: int,
///     src: bytes,
///     src_ofs: int,
///     n: int = None,
/// ) -> int:
///     """
///     Copies at most `n` bytes from `src` at offset `src_ofs` to
///     `dst` at offset `dst_ofs`. Returns the number of actually
///     copied bytes. If `n` is not specified, tries to copy
///     as much as possible.
///     """
STATIC mp_obj_t mod_trezorutils_memcpy(size_t n_args, const mp_obj_t *args) {
  mp_arg_check_num(n_args, 0, 4, 5, false);

  mp_buffer_info_t dst = {0};
  mp_get_buffer_raise(args[0], &dst, MP_BUFFER_WRITE);
  uint32_t dst_ofs = trezor_obj_get_uint(args[1]);

  mp_buffer_info_t src = {0};
  mp_get_buffer_raise(args[2], &src, MP_BUFFER_READ);
  uint32_t src_ofs = trezor_obj_get_uint(args[3]);

  uint32_t n = 0;
  if (n_args > 4) {
    n = trezor_obj_get_uint(args[4]);
  } else {
    n = src.len;
  }

  size_t dst_rem = (dst_ofs < dst.len) ? dst.len - dst_ofs : 0;
  size_t src_rem = (src_ofs < src.len) ? src.len - src_ofs : 0;
  size_t ncpy = MIN(n, MIN(src_rem, dst_rem));

  memmove(((char *)dst.buf) + dst_ofs, ((const char *)src.buf) + src_ofs, ncpy);

  return mp_obj_new_int(ncpy);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorutils_memcpy_obj, 4, 5,
                                           mod_trezorutils_memcpy);

/// def halt(msg: str = None) -> None:
///     """
///     Halts execution.
///     """
STATIC mp_obj_t mod_trezorutils_halt(size_t n_args, const mp_obj_t *args) {
  mp_buffer_info_t msg = {0};
  if (n_args > 0 && mp_get_buffer(args[0], &msg, MP_BUFFER_READ)) {
    ensure(secfalse, msg.buf);
  } else {
    ensure(secfalse, "halt");
  }
  return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorutils_halt_obj, 0, 1,
                                           mod_trezorutils_halt);

#define PASTER(s) MP_QSTR_##s
#define MP_QSTR(s) PASTER(s)

/// GITREV: str
/// VERSION_MAJOR: int
/// VERSION_MINOR: int
/// VERSION_PATCH: int
/// MODEL: str
/// EMULATOR: bool
/// BITCOIN_ONLY: bool

STATIC const mp_rom_map_elem_t mp_module_trezorutils_globals_table[] = {
    {MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_trezorutils)},
    {MP_ROM_QSTR(MP_QSTR_consteq), MP_ROM_PTR(&mod_trezorutils_consteq_obj)},
    {MP_ROM_QSTR(MP_QSTR_meminfo), MP_ROM_PTR(&mod_trezorutils_meminfo_obj)},
    {MP_ROM_QSTR(MP_QSTR_memcpy), MP_ROM_PTR(&mod_trezorutils_memcpy_obj)},
    {MP_ROM_QSTR(MP_QSTR_halt), MP_ROM_PTR(&mod_trezorutils_halt_obj)},
    // various built-in constants
    {MP_ROM_QSTR(MP_QSTR_GITREV), MP_ROM_QSTR(MP_QSTR(GITREV))},
    {MP_ROM_QSTR(MP_QSTR_VERSION_MAJOR), MP_ROM_INT(VERSION_MAJOR)},
    {MP_ROM_QSTR(MP_QSTR_VERSION_MINOR), MP_ROM_INT(VERSION_MINOR)},
    {MP_ROM_QSTR(MP_QSTR_VERSION_PATCH), MP_ROM_INT(VERSION_PATCH)},
    {MP_ROM_QSTR(MP_QSTR_MODEL), MP_ROM_QSTR(MP_QSTR(TREZOR_MODEL))},
#ifdef TREZOR_EMULATOR
    {MP_ROM_QSTR(MP_QSTR_EMULATOR), mp_const_true},
#else
    {MP_ROM_QSTR(MP_QSTR_EMULATOR), mp_const_false},
#endif
#if BITCOIN_ONLY
    {MP_ROM_QSTR(MP_QSTR_BITCOIN_ONLY), mp_const_true},
#else
    {MP_ROM_QSTR(MP_QSTR_BITCOIN_ONLY), mp_const_false},
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_trezorutils_globals,
                            mp_module_trezorutils_globals_table);

const mp_obj_module_t mp_module_trezorutils = {
    .base = {&mp_type_module},
    .globals = (mp_obj_dict_t *)&mp_module_trezorutils_globals,
};

MP_REGISTER_MODULE(MP_QSTR_trezorutils, mp_module_trezorutils,
                   MICROPY_PY_TREZORUTILS);

#endif  // MICROPY_PY_TREZORUTILS
