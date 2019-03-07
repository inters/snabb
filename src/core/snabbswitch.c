/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

#include <stdio.h>
#include <string.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#if UINTPTR_MAX != UINT64_MAX
#error "64-bit word size required. See doc/porting.md."
#endif

int argc;
char** argv;

lua_State* L;

int main(int snabb_argc, char **snabb_argv)
{
  /* Store for use by LuaJIT code via FFI. */
  argc = snabb_argc;
  argv = snabb_argv;
  L = luaL_newstate();
  luaL_openlibs(L);
  return luaL_dostring(L, "require \"core.startup\"");
}

#define STR_MAX 1024
char tempstr[1024];

const char *lua_describe (int index) {
  int type = lua_type(L, index);
  const char *str;
  switch (type) {
  case LUA_TNONE:
    return "<corrupt>";
  case LUA_TNIL: 
    return "nil";
  case LUA_TNUMBER:
    snprintf(tempstr, STR_MAX, "%s: %s",
             lua_typename(L, type),
             lua_tostring(L, index));
    break;
  case LUA_TSTRING:
    str = lua_tostring(L, index);
    snprintf(tempstr, STR_MAX, "%s: \"%.32s%s",
             lua_typename(L, type),
             str, strlen(str) > 32 ? "...\"" : "\"");
    break;
  case LUA_TBOOLEAN:
    snprintf(tempstr, STR_MAX, "%s: %s",
             lua_typename(L, type),
             lua_toboolean(L, index) ? "true" : "false");
    break;
  default:
    snprintf(tempstr, STR_MAX, "%s: %p",
             lua_typename(L, type),
             lua_topointer(L, index));
  }
  return tempstr;
}

void lua_stacktrace () {
  lua_Debug entry;
  int depth = 0; 
  fprintf(stderr, "\nLua Stacktrace\n==============\n");
  while (lua_getstack(L, depth, &entry)) {
    int status = lua_getinfo(L, "Slnf", &entry);
    assert(status);
    fprintf(stderr, "(%d) %s at %s:%d\n",
            depth + 1,
            entry.name ? entry.name : "?",
            entry.short_src,
            entry.currentline);
    int local = 1;
    while (1) {
      const char *name = lua_getlocal(L, &entry, local);
      if (!name) break;
      fprintf(stderr, "   %s = %s\n", name, lua_describe(lua_gettop(L)));
      lua_pop(L, 1);
      local++;
    }
    int upvalue = 1;
    while (1) {
      const char *name = lua_getupvalue(L, lua_gettop(L), upvalue);
      if (!name) break;
      fprintf(stderr, "   %s = %s\n", name, lua_describe(lua_gettop(L)));
      lua_pop(L, 1);
      upvalue++;
    }
    lua_pop(L, 1);
    depth++;
  }
}
