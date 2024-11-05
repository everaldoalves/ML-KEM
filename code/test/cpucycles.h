#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#include <stdint.h>

#ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */

static inline uint64_t cpucycles(void) {
  const uint32_t ecx = (1U << 30) + 1;
  uint64_t result;

  __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

#else

static inline uint64_t cpucycles(void) {
  uint64_t result;
  //uint64_t frequency;
  //asm volatile("mrs %0, CNTFRQ_EL0" : "=r" (frequency));
  __asm__ volatile ("mrs %0, cntvct_el0" : "=r" (result));

  return result;
}

#endif

uint64_t cpucycles_overhead(void);

#endif
