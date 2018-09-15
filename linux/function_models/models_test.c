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

#include <string.h>
#include <wchar.h>

#include <s2e/s2e.h>

#include "function_models.h"

#define STR_LEN 8

//
// Check that the signs of the two results validate the correctness of the
// function model
//
static inline void validate_signs(int res1, int res2) {
    s2e_assert((res1 ^ res2) >= 0);
}

//
// Check that the memory contents validate the correctness of the function
// model
//
static inline void validate_contents(const void *mem1, const void *mem2, size_t char_size) {
    s2e_assert(memcmp(mem1, mem2, STR_LEN * char_size) == 0);
}

//
// Ensure that the two strings to have the same memory contents
//
static inline void init_strings(char *str1, char *str2) {
    memset(str1, 'A', STR_LEN);
    memset(str2, 'A', STR_LEN);
}

static inline void init_wstrings(wchar_t *str1, wchar_t *str2) {
    wmemset(str1, L'A', STR_LEN);
    wmemset(str2, L'A', STR_LEN);
}

//
// String unit tests
//

static void test_strcpy() {
    char *src = "abc";
    s2e_make_concolic(src, strlen(src) * sizeof(char), "src");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    strcpy(str1, src);
    strcpy_model(str2, src);

    validate_contents(str1, str2, sizeof(char));
}

static void test_strncpy() {
    char *src = "abc";
    const unsigned src_len = strlen(src);
    s2e_make_concolic(src, src_len * sizeof(char), "src");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    strncpy(str1, src, src_len);
    strncpy_model(str2, src, src_len);

    validate_contents(str1, str2, sizeof(char));
}

static void test_strlen() {
    char *str = "abc";
    s2e_make_concolic(str, strlen(str) * sizeof(char), "str");

    size_t res1 = strlen(str);
    size_t res2 = strlen_model(str);

    s2e_assert(res1 == res2);
}

static void test_strcmp() {
    char *str1 = "abc";
    s2e_make_concolic(str1, strlen(str1) * sizeof(char), "str1");

    char *str2 = "123";
    s2e_make_concolic(str2, strlen(str2) * sizeof(char), "str2");

    int res1 = strcmp(str1, str2);
    int res2 = strcmp_model(str1, str2);

    s2e_print_expression("res1", res1);
    s2e_print_expression("res2", res2);

    validate_signs(res1, res2);
}

static void test_strncmp() {
    char *str1 = "abc";
    s2e_make_concolic(str1, strlen(str1) * sizeof(char), "str1");

    char *str2 = "123";
    s2e_make_concolic(str2, strlen(str2) * sizeof(char), "str2");

    int res1 = strncmp(str1, str2, 4);
    int res2 = strncmp_model(str1, str2, 4);

    validate_signs(res1, res2);
}

static void test_strcat() {
    char *src = "abc";
    s2e_make_concolic(src, strlen(src) * sizeof(char), "src");

    char *dest = "ABCD";
    const unsigned dest_len = strlen(dest);
    s2e_make_concolic(dest, dest_len * sizeof(char), "dest");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < dest_len; ++i) {
        str1[i] = str2[i] = dest[i];
    }

    strcat(str1, src);
    strcat_model(str2, src);

    validate_contents(str1, str2, sizeof(char));
}

static void test_strncat() {
    char *src = "abc";
    const unsigned src_len = strlen(src);
    s2e_make_concolic(src, src_len * sizeof(char), "src");

    char *dest = "ABCD";
    const unsigned dest_len = strlen(dest);
    s2e_make_concolic(dest, dest_len * sizeof(char), "dest");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < dest_len; ++i) {
        str1[i] = str2[i] = dest[i];
    }

    strncat(str1, src, src_len);
    strncat_model(str2, src, src_len);

    validate_contents(str1, str2, sizeof(char));
}

//
// Wide string unit tests
//

static void test_wcscpy() {
    wchar_t *src = L"abc";
    s2e_make_concolic(src, wcslen(src) * sizeof(wchar_t), "src");

    wchar_t str1[STR_LEN];
    wchar_t str2[STR_LEN];

    init_wstrings(str1, str2);

    wcscpy(str1, src);
    wcscpy_model(str2, src);

    validate_contents(str1, str2, sizeof(wchar_t));
}

static void test_wcsncpy() {
    wchar_t *src = L"abc";
    const unsigned src_len = wcslen(src);
    s2e_make_concolic(src, src_len * sizeof(wchar_t), "src");

    wchar_t str1[STR_LEN];
    wchar_t str2[STR_LEN];

    init_wstrings(str1, str2);

    wcsncpy(str1, src, src_len);
    wcsncpy_model(str2, src, src_len);

    validate_contents(str1, str2, sizeof(wchar_t));
}

static void test_wcslen() {
    wchar_t *str = L"abc";
    s2e_make_concolic(str, wcslen(str) * sizeof(wchar_t), "str");

    size_t res1 = wcslen(str);
    size_t res2 = wcslen_model(str);

    s2e_assert(res1 == res2);
}

static void test_wcscmp() {
    wchar_t *str1 = L"abc";
    s2e_make_concolic(str1, wcslen(str1) * sizeof(wchar_t), "str1");

    wchar_t *str2 = L"123";
    s2e_make_concolic(str2, wcslen(str2) * sizeof(wchar_t), "str2");

    int res1 = wcscmp(str1, str2);
    int res2 = wcscmp_model(str1, str2);

    s2e_print_expression("res1", res1);
    s2e_print_expression("res2", res2);

    validate_signs(res1, res2);
}

static void test_wcsncmp() {
    wchar_t *str1 = L"abc";
    s2e_make_concolic(str1, wcslen(str1) * sizeof(wchar_t), "str1");

    wchar_t *str2 = L"123";
    s2e_make_concolic(str2, wcslen(str2) * sizeof(wchar_t), "str2");

    int res1 = wcsncmp(str1, str2, 4);
    int res2 = wcsncmp_model(str1, str2, 4);

    validate_signs(res1, res2);
}

static void test_wcscat() {
    wchar_t *src = L"abc";
    s2e_make_concolic(src, wcslen(src) * sizeof(wchar_t), "src");

    wchar_t *dest = L"ABCD";
    const unsigned dest_len = wcslen(dest);
    s2e_make_concolic(dest, dest_len * sizeof(wchar_t), "dest");

    wchar_t str1[STR_LEN];
    wchar_t str2[STR_LEN];

    init_wstrings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < dest_len; ++i) {
        str1[i] = str2[i] = dest[i];
    }

    wcscat(str1, src);
    wcscat_model(str2, src);

    validate_contents(str1, str2, sizeof(wchar_t));
}

static void test_wcsncat() {
    wchar_t *src = L"abc";
    const unsigned src_len = wcslen(src);
    s2e_make_concolic(src, src_len * sizeof(wchar_t), "src");

    wchar_t *dest = L"ABCD";
    const unsigned dest_len = wcslen(dest);
    s2e_make_concolic(dest, dest_len * sizeof(wchar_t), "dest");

    wchar_t str1[STR_LEN];
    wchar_t str2[STR_LEN];

    init_wstrings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < wcslen(dest); ++i) {
        str1[i] = str2[i] = dest[i];
    }

    wcsncat(str1, src, src_len);
    wcsncat_model(str2, src, src_len);

    validate_contents(str1, str2, sizeof(wchar_t));
}

//
// Memory unit tests
//

static void test_memcpy() {
    char *src = "abc";
    const unsigned src_len = strlen(src);
    s2e_make_concolic(src, src_len * sizeof(char), "src");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    memcpy(str1, src, src_len);
    memcpy_model(str2, src, src_len);

    validate_contents(str1, str2, sizeof(char));
}

static void test_memcmp() {
    char *str1 = "abc";
    const unsigned str1_len = strlen(str1);
    s2e_make_concolic(str1, str1_len * sizeof(char), "str1");

    char *str2 = "123";
    s2e_make_concolic(str2, strlen(str2), "str2");

    int res1 = memcmp(str1, str2, str1_len);
    int res2 = memcmp_model(str1, str2, str1_len);

    validate_signs(res1, res2);
}

//
// CRC unit tests
//

static void test_crc32(void) {
    // Test empty buffer
    uint32_t crc = crc32_model(0, NULL, 0);
    s2e_assert(crc == 0);

    const char *test = "test";
    const uint32_t expected_crc = 0xd87f7e0c;
    crc = crc32_model(crc, (const uint8_t *) test, strlen(test));
    s2e_printf("actual crc: %#x expected: %#x\n", crc, expected_crc);
    s2e_assert(crc == expected_crc);
}

static void test_crc16(void) {
    // Test empty buffer
    uint16_t crc = crc16_model(0, NULL, 0);
    s2e_assert(crc == 0);

    const char *test = "test";
    const uint16_t expected_crc = 0xdc2e;
    crc = crc16_model(crc, (const uint8_t *) test, strlen(test));
    s2e_printf("actual crc: %#x expected: %#x\n", crc, expected_crc);
    s2e_assert(crc == expected_crc);
}

//
// Main function
//

int main(int argc, char *argv[]) {
    if (argc != 2) {
        s2e_printf("Usage: %s function_name\n", argv[0]);
        return -1;
    }

    s2e_printf("Testing %s function model\n", argv[1]);

    initialize_models();

    if (!strcmp(argv[1], "strcpy")) {
        test_strcpy();
    } else if (!strcmp(argv[1], "strncpy")) {
        test_strncpy();
    } else if (!strcmp(argv[1], "strlen")) {
        test_strlen();
    } else if (!strcmp(argv[1], "strcmp")) {
        test_strcmp();
    } else if (!strcmp(argv[1], "strncmp")) {
        test_strncmp();
    } else if (!strcmp(argv[1], "strcat")) {
        test_strcat();
    } else if (!strcmp(argv[1], "strncat")) {
        test_strncat();
    } else if (!strcmp(argv[1], "wcscpy")) {
        test_wcscpy();
    } else if (!strcmp(argv[1], "wcsncpy")) {
        test_wcsncpy();
    } else if (!strcmp(argv[1], "wcslen")) {
        test_wcslen();
    } else if (!strcmp(argv[1], "wcscmp")) {
        test_wcscmp();
    } else if (!strcmp(argv[1], "wcsncmp")) {
        test_wcsncmp();
    } else if (!strcmp(argv[1], "wcscat")) {
        test_wcscat();
    } else if (!strcmp(argv[1], "wcsncat")) {
        test_wcsncat();
    } else if (!strcmp(argv[1], "memcpy")) {
        test_memcpy();
    } else if (!strcmp(argv[1], "memcmp")) {
        test_memcmp();
    } else if (!strcmp(argv[1], "crc32")) {
        test_crc32();
    } else if (!strcmp(argv[1], "crc16")) {
        test_crc16();
    } else {
        s2e_printf("Function %s is not supported!\n", argv[1]);
    }

    return 0;
}
