/* SPDX-License-Identifier: MIT
 * Freestanding integer subset for the preserved portable charging core.
 * WDK has no stdint.h in this kit; MSVC's user CRT header conflicts with the
 * kernel CRT already included by ntifs.h. Only the WDK project uses this
 * include directory. Host/firmware tests continue to use their normal stdint.
 */
#ifndef N976N_WDK_PORTABLE_STDINT_H
#define N976N_WDK_PORTABLE_STDINT_H
#if !defined(_KERNEL_MODE) || !defined(N976N_BATTERY_EXTERNAL_TYPES)
#error This adapter requires the WDK kernel build and KernelTypes.h
#endif
typedef UINT8 uint8_t;
typedef INT8 int8_t;
typedef UINT16 uint16_t;
typedef INT16 int16_t;
typedef UINT32 uint32_t;
typedef INT32 int32_t;
typedef UINT64 uint64_t;
typedef INT64 int64_t;
#define UINT32_MAX ((uint32_t)0xFFFFFFFFU)
#define UINT64_MAX ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
C_ASSERT(sizeof(uint8_t)==1 && sizeof(uint16_t)==2);
C_ASSERT(sizeof(uint32_t)==4 && sizeof(uint64_t)==8);
C_ASSERT(sizeof(int32_t)==4 && sizeof(int64_t)==8);
#endif
