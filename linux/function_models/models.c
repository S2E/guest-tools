/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Dependable Systems Lab, EPFL
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#define _GNU_SOURCE
#include <dlfcn.h>

#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#include <s2e/function_models/commands.h>
#include <s2e/s2e.h>

#include "function_models.h"

// Initialize copies of the modelled functions
T_strcpy orig_strcpy = NULL;
T_strncpy orig_strncpy = NULL;
T_strlen orig_strlen = NULL;
T_strcmp orig_strcmp = NULL;
T_strncmp orig_strncmp = NULL;
T_strcat orig_strcat = NULL;
T_strncat orig_strncat = NULL;
T_printf orig_printf = NULL;
T_fprintf orig_fprintf = NULL;

T_wcscpy orig_wcscpy = NULL;
T_wcsncpy orig_wcsncpy = NULL;
T_wcslen orig_wcslen = NULL;
T_wcscmp orig_wcscmp = NULL;
T_wcsncmp orig_wcsncmp = NULL;
T_wcscat orig_wcscat = NULL;
T_wcsncat orig_wcsncat = NULL;
T_wprintf orig_wprintf = NULL;
T_fwprintf orig_fwprintf = NULL;

T_memcpy orig_memcpy = NULL;
T_memcmp orig_memcmp = NULL;

T_crc32 orig_crc32 = NULL;
T_crc16 orig_crc16 = NULL;

#define SAVE_ORIG_FUNC(func) CONCAT(orig, func) = (CONCAT(T, func)) dlsym(RTLD_NEXT, #func)

// Save the original functions so we can use them if required
void initialize_models() {
    // String functions
    SAVE_ORIG_FUNC(strcpy);
    SAVE_ORIG_FUNC(strncpy);
    SAVE_ORIG_FUNC(strlen);
    SAVE_ORIG_FUNC(strcmp);
    SAVE_ORIG_FUNC(strncmp);
    SAVE_ORIG_FUNC(strcat);
    SAVE_ORIG_FUNC(strncat);
    SAVE_ORIG_FUNC(printf);
    SAVE_ORIG_FUNC(fprintf);

    // Wide string functions
    SAVE_ORIG_FUNC(wcscpy);
    SAVE_ORIG_FUNC(wcsncpy);
    SAVE_ORIG_FUNC(wcslen);
    SAVE_ORIG_FUNC(wcscmp);
    SAVE_ORIG_FUNC(wcsncmp);
    SAVE_ORIG_FUNC(wcscat);
    SAVE_ORIG_FUNC(wcsncat);
    SAVE_ORIG_FUNC(wprintf);
    SAVE_ORIG_FUNC(fwprintf);

    // Memory functions
    SAVE_ORIG_FUNC(memcpy);
    SAVE_ORIG_FUNC(memcmp);

    // CRC functions
    SAVE_ORIG_FUNC(crc32);
    SAVE_ORIG_FUNC(crc16);
}

//
// String functions
//

char *strcpy_model(char *dest, const char *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strcpy)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_strcpy)(dest, src);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCPY;
    cmd.Strcpy.char_size = sizeof(char);
    cmd.Strcpy.dest = (uintptr_t) dest;
    cmd.Strcpy.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_strcpy)(dest, src);
}

char *strncpy_model(char *dest, const char *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strncpy)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_strncpy)(dest, src, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCPY;
    cmd.Strncpy.char_size = sizeof(char);
    cmd.Strncpy.dest = (uintptr_t) dest;
    cmd.Strncpy.src = (uintptr_t) src;
    cmd.Strncpy.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_strncpy)(dest, src, n);
}

size_t strlen_model(const char *str) {
    if (s2e_is_symbolic(&str, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strlen)(str);
    }

    if (str == NULL) {
        return (*orig_strlen)(str);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRLEN;
    cmd.Strlen.char_size = sizeof(char);
    cmd.Strlen.str = (uintptr_t) str;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strlen.ret;
    }

    return (*orig_strlen)(str);
}

int strcmp_model(const char *str1, const char *str2) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strcmp)(str1, str2);
    }

    if (!str1 || !str2) {
        return (*orig_strcmp)(str1, str2);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRCMP;
    cmd.Strcmp.char_size = sizeof(char);
    cmd.Strcmp.str1 = (uintptr_t) str1;
    cmd.Strcmp.str2 = (uintptr_t) str2;
    cmd.needOrigFunc = 1;
    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strcmp.ret;
    }

    return (*orig_strcmp)(str1, str2);
}

int strncmp_model(const char *str1, const char *str2, size_t n) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strncmp)(str1, str2, n);
    }

    if (!str1 || !str2) {
        return (*orig_strncmp)(str1, str2, n);
    }

    if (!n) {
        return 0;
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCMP;
    cmd.Strncmp.char_size = sizeof(char);
    cmd.Strncmp.str1 = (uintptr_t) str1;
    cmd.Strncmp.str2 = (uintptr_t) str2;
    cmd.Strncmp.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strncmp.ret;
    }

    return (*orig_strncmp)(str1, str2, n);
}

char *strcat_model(char *dest, const char *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strcat)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_strcat)(dest, src);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCAT;
    cmd.Strcat.char_size = sizeof(char);
    cmd.Strcat.dest = (uintptr_t) dest;
    cmd.Strcat.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_strcat)(dest, src);
}

char *strncat_model(char *dest, const char *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_strncat)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_strncat)(dest, src, n);
    }

    if (n > MAX_STRLEN) {
        return (*orig_strncat)(dest, src, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRNCAT;
    cmd.Strncat.char_size = sizeof(char);
    cmd.Strncat.dest = (uintptr_t) dest;
    cmd.Strncat.src = (uintptr_t) src;
    cmd.Strncat.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_strncat)(dest, src, n);
}

static uint8_t printf_helper(const char *format) {
    if (s2e_is_symbolic(&format, sizeof(void *))) {
        s2e_message("Symbolic address for format string is not supported yet");
        return 0;
    }

    unsigned i = 0;
    do {
        if (s2e_is_symbolic((void *) (format + i), sizeof(char))) {
            s2e_message("Warning: user controllable format string can cause vulnerability");
            break;
        }
        if ('\0' == *(format + i)) { // check for null character
            break;
        }
    } while (1);

    return 1;
}

int printf_model(const char *format, ...) {
    printf_helper(format);

    return 0; // FIXME: how to handle the return value
}

int fprintf_model(FILE *stream, const char *format, ...) {
    // Writing to files is currently not supported
    if (stream == stderr || stream == stdout) {
        printf_helper(format);
        return 0;
    }

    va_list arg;
    int done;

    va_start(arg, format);
    done = vfprintf(stream, format, arg);
    va_end(arg);

    return done;
}

//
// Wide string functions
//

wchar_t *wcscpy_model(wchar_t *dest, const wchar_t *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcscpy)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_wcscpy)(dest, src);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCPY;
    cmd.Strcpy.char_size = sizeof(wchar_t);
    cmd.Strcpy.dest = (uintptr_t) dest;
    cmd.Strcpy.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_wcscpy)(dest, src);
}

wchar_t *wcsncpy_model(wchar_t *dest, const wchar_t *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(void *))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcsncpy)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_wcsncpy)(dest, src, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCPY;
    cmd.Strncpy.char_size = sizeof(wchar_t);
    cmd.Strncpy.dest = (uintptr_t) dest;
    cmd.Strncpy.src = (uintptr_t) src;
    cmd.Strncpy.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_wcsncpy)(dest, src, n);
}

size_t wcslen_model(const wchar_t *str) {
    if (s2e_is_symbolic(&str, sizeof(void *))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcslen)(str);
    }

    if (str == NULL) {
        return (*orig_wcslen)(str);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRLEN;
    cmd.Strlen.char_size = sizeof(wchar_t);
    cmd.Strlen.str = (uintptr_t) str;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strlen.ret;
    }

    return (*orig_wcslen)(str);
}

int wcscmp_model(const wchar_t *str1, const wchar_t *str2) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcscmp)(str1, str2);
    }

    if (!str1 || !str2) {
        return (*orig_wcscmp)(str1, str2);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRCMP;
    cmd.Strcmp.char_size = sizeof(wchar_t);
    cmd.Strcmp.str1 = (uintptr_t) str1;
    cmd.Strcmp.str2 = (uintptr_t) str2;
    cmd.needOrigFunc = 1;
    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strcmp.ret;
    }

    return (*orig_wcscmp)(str1, str2);
}

int wcsncmp_model(const wchar_t *str1, const wchar_t *str2, size_t n) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcsncmp)(str1, str2, n);
    }

    if (!str1 || !str2) {
        return (*orig_wcsncmp)(str1, str2, n);
    }

    if (!n) {
        return 0;
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_STRNCMP;
    cmd.Strncmp.char_size = sizeof(wchar_t);
    cmd.Strncmp.str1 = (uintptr_t) str1;
    cmd.Strncmp.str2 = (uintptr_t) str2;
    cmd.Strncmp.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Strncmp.ret;
    }

    return (*orig_wcsncmp)(str1, str2, n);
}

wchar_t *wcscat_model(wchar_t *dest, const wchar_t *src) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcscat)(dest, src);
    }

    if (!dest || !src) {
        return (*orig_wcscat)(dest, src);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRCAT;
    cmd.Strcat.char_size = sizeof(wchar_t);
    cmd.Strcat.dest = (uintptr_t) dest;
    cmd.Strcat.src = (uintptr_t) src;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_wcscat)(dest, src);
}

wchar_t *wcsncat_model(wchar_t *dest, const wchar_t *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a wide string is not supported yet");
        return (*orig_wcsncat)(dest, src, n);
    }

    if (!dest || !src || !n) {
        return (*orig_wcsncat)(dest, src, n);
    }

    if (n > MAX_STRLEN) {
        return (*orig_wcsncat)(dest, src, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBCWRAPPER_STRNCAT;
    cmd.Strncat.char_size = sizeof(wchar_t);
    cmd.Strncat.dest = (uintptr_t) dest;
    cmd.Strncat.src = (uintptr_t) src;
    cmd.Strncat.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return dest;
    }

    return (*orig_wcsncat)(dest, src, n);
}

static uint8_t wprintf_helper(const wchar_t *format) {
    if (s2e_is_symbolic(&format, sizeof(void *))) {
        s2e_message("Symbolic address for format string is not supported yet");
        return 0;
    }

    unsigned i = 0;
    do {
        if (s2e_is_symbolic((void *) (format + i), sizeof(wchar_t))) {
            s2e_message("Warning: user controllable format string can cause vulnerability");
            break;
        }
        if ('\0' == *(format + i)) { // check for null wchar_tacter
            break;
        }
    } while (1);

    return 1;
}

int wprintf_model(const wchar_t *format, ...) {
    wprintf_helper(format);

    return 0; // FIXME: how to handle the return value
}

int fwprintf_model(FILE *stream, const wchar_t *format, ...) {
    // Writing to files is currently not supported
    if (stream == stderr || stream == stdout) {
        wprintf_helper(format);
        return 0;
    }

    va_list arg;
    int done;

    va_start(arg, format);
    done = vfwprintf(stream, format, arg);
    va_end(arg);

    return done;
}

//
// Memory functions
//

void *memcpy_model(void *dest, const void *src, size_t n) {
    if (s2e_is_symbolic(&dest, sizeof(void *)) || s2e_is_symbolic(&src, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_memcpy)(dest, src, n);
    }

    if (!dest || !src) {
        return (*orig_memcpy)(dest, src, n);
    }

    if (!n) {
        return dest;
    }

    if (n > MAX_STRLEN) {
        return (*orig_memcpy)(dest, src, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_MEMCPY;
    cmd.Memcpy.dest = (uintptr_t) dest;
    cmd.Memcpy.src = (uintptr_t) src;
    cmd.Memcpy.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return (void *) dest;
    }

    return (*orig_memcpy)(dest, src, n);
}

int memcmp_model(const void *str1, const void *str2, size_t n) {
    if (s2e_is_symbolic(&str1, sizeof(void *)) || s2e_is_symbolic(&str2, sizeof(void *)) ||
        s2e_is_symbolic(&n, sizeof(size_t))) {
        s2e_message("Symbolic address for a string is not supported yet");
        return (*orig_memcmp)(str1, str2, n);
    }

    if (!str1 || !str2 || !n) {
        return (*orig_memcmp)(str1, str2, n);
    }

    if (n > MAX_STRLEN) {
        return (*orig_memcmp)(str1, str2, n);
    }

    struct S2E_WRAPPER_COMMAND cmd;
    cmd.Command = LIBCWRAPPER_MEMCMP;
    cmd.Memcmp.str1 = (uintptr_t) str1;
    cmd.Memcmp.str2 = (uintptr_t) str2;
    cmd.Memcmp.n = n;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        if (s2e_is_symbolic(&cmd.Memcmp.ret, sizeof(int))) {
            s2e_message("return value is symbolic");
        }

        return cmd.Memcmp.ret;
    }

    return (*orig_memcmp)(str1, str2, n);
}

//
// CRC functions
//

///
/// \brief crc32_model emulates the crc32 function in zlib
/// \param crc the initial crc
/// \param buf a pointer to the buffer
/// \param len the length of the buffer
/// \return the crc
///
uint32_t crc32_model(uint32_t crc, const uint8_t *buf, unsigned len) {
    if (!buf) {
        return 0;
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBZWRAPPER_CRC;
    cmd.Crc.initial_value_ptr = (uintptr_t) &crc;
    cmd.Crc.buffer = (uintptr_t) buf;
    cmd.Crc.size = len;
    cmd.Crc.xor_result = 1;
    cmd.Crc.type = LIBZWRAPPER_CRC32;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Crc.ret;
    }

    return (*orig_crc32)(crc, buf, len);
}

///
/// \brief crc16_model emulates the crc32 function
/// \param crc the initial crc
/// \param buf a pointer to the buffer
/// \param len the length of the buffer
/// \return the crc
///
uint16_t crc16_model(uint16_t crc, const uint8_t *buf, unsigned len) {
    if (!buf) {
        return 0;
    }

    struct S2E_WRAPPER_COMMAND cmd;

    cmd.Command = LIBZWRAPPER_CRC;
    cmd.Crc.initial_value_ptr = (uintptr_t) &crc;
    cmd.Crc.buffer = (uintptr_t) buf;
    cmd.Crc.size = len;
    cmd.Crc.type = LIBZWRAPPER_CRC16;
    cmd.needOrigFunc = 1;

    s2e_invoke_plugin("FunctionModels", &cmd, sizeof(cmd));

    if (!cmd.needOrigFunc) {
        return cmd.Crc.ret;
    }

    return (*orig_crc16)(crc, buf, len);
}
