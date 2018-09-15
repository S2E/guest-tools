/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2017, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef S2E_FUNCTION_MODELS_H
#define S2E_FUNCTION_MODELS_H

#include <inttypes.h>
#include <stdio.h>
#include <wchar.h>

//
// Modelled functions typedefs
//

typedef char *(*T_strcpy)(char *, const char *);
typedef char *(*T_strncpy)(char *, const char *, size_t);
typedef size_t (*T_strlen)(const char *);
typedef int (*T_strcmp)(const char *, const char *);
typedef int (*T_strncmp)(const char *, const char *, size_t);
typedef char *(*T_strcat)(char *, const char *);
typedef char *(*T_strncat)(char *, const char *, size_t);
typedef int (*T_printf)(const char *, ...);
typedef int (*T_fprintf)(FILE *, const char *, ...);

typedef wchar_t *(*T_wcscpy)(wchar_t *, const wchar_t *);
typedef wchar_t *(*T_wcsncpy)(wchar_t *, const wchar_t *, size_t);
typedef size_t (*T_wcslen)(const wchar_t *);
typedef int (*T_wcscmp)(const wchar_t *, const wchar_t *);
typedef int (*T_wcsncmp)(const wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*T_wcscat)(wchar_t *, const wchar_t *);
typedef wchar_t *(*T_wcsncat)(wchar_t *, const wchar_t *, size_t);
typedef int (*T_wprintf)(const wchar_t *, ...);
typedef int (*T_fwprintf)(FILE *, const wchar_t *, ...);

typedef void *(*T_memcpy)(void *, const void *, size_t);
typedef int (*T_memcmp)(const void *, const void *, size_t);

typedef uint32_t (*T_crc32)(uint32_t, const uint8_t *, unsigned);
typedef uint16_t (*T_crc16)(uint16_t, const uint8_t *, unsigned);

//
// Pointers to copies of modelled functions
//

extern T_strcpy orig_strcpy;
extern T_strncpy orig_strncpy;
extern T_strlen orig_strlen;
extern T_strcmp orig_strcmp;
extern T_strncmp orig_strncmp;
extern T_strcat orig_strcat;
extern T_strncat orig_strncat;
extern T_printf orig_printf;
extern T_fprintf orig_fprintf;

extern T_wcscpy orig_wcscpy;
extern T_wcsncpy orig_wcsncpy;
extern T_wcslen orig_wcslen;
extern T_wcscmp orig_wcscmp;
extern T_wcsncmp orig_wcsncmp;
extern T_wcscat orig_wcscat;
extern T_wcsncat orig_wcsncat;
extern T_wprintf orig_wprintf;
extern T_fwprintf orig_fwprintf;

extern T_memcpy orig_memcpy;
extern T_memcmp orig_memcmp;

extern T_crc32 orig_crc32;
extern T_crc16 orig_crc16;

/// Initialize the pointers to the original modelled functions
void initialize_models();

#define CONCAT__(x, y) x##_##y
#define CONCAT_(x, y) CONCAT__(x, y)
#define CONCAT(x, y) CONCAT_(x, y)

#define FUNC_MODEL_BODY(func, ...)                 \
    if (!g_enable_function_models) {               \
        if (!CONCAT(orig, func)) {                 \
            initialize_models();                   \
        }                                          \
                                                   \
        return (*CONCAT(orig, func))(__VA_ARGS__); \
    }                                              \
                                                   \
    return CONCAT(func, model)(__VA_ARGS__);

//
// Function model prototypes
//

char *strcpy_model(char *, const char *);
char *strncpy_model(char *, const char *, size_t);
size_t strlen_model(const char *);
int strcmp_model(const char *, const char *);
int strncmp_model(const char *, const char *, size_t);
char *strcat_model(char *, const char *);
char *strncat_model(char *, const char *, size_t);
int printf_model(const char *, ...);
int fprintf_model(FILE *, const char *, ...);

wchar_t *wcscpy_model(wchar_t *, const wchar_t *);
wchar_t *wcsncpy_model(wchar_t *, const wchar_t *, size_t);
size_t wcslen_model(const wchar_t *);
int wcscmp_model(const wchar_t *, const wchar_t *);
int wcsncmp_model(const wchar_t *, const wchar_t *, size_t);
wchar_t *wcscat_model(wchar_t *, const wchar_t *);
wchar_t *wcsncat_model(wchar_t *, const wchar_t *, size_t);
int wprintf_model(const wchar_t *, ...);
int fwprintf_model(FILE *, const wchar_t *, ...);

void *memcpy_model(void *, const void *, size_t);
int memcmp_model(const void *, const void *, size_t);

uint32_t crc32_model(uint32_t, const uint8_t *, unsigned);
uint16_t crc16_model(uint16_t, const uint8_t *, unsigned);

#endif
