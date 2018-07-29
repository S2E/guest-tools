/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Adrian Herrera
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

#include <stdint.h>

#include "function_models.h"
#include "s2e_so.h"

// ****************************
// Overriding libz functions
// ****************************

uint32_t crc32(uint32_t crc, const uint8_t *buf, unsigned len) {
    if (!g_enable_function_models) {
        if (!orig_crc32) {
            initialize_models();
        }

        return (*orig_crc32)(crc, buf, len);
    }

    return crc32_model(crc, buf, len);
}

uint16_t crc16(uint16_t crc, const uint8_t *buf, unsigned len) {
    if (!g_enable_function_models) {
        if (!orig_crc16) {
            initialize_models();
        }

        return (*orig_crc16)(crc, buf, len);
    }

    return crc16_model(crc, buf, len);
}
