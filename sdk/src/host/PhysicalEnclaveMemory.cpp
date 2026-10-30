//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Memory.hpp"

#include <cstdio>
#include <sys/mman.h>

namespace Keystone {

void
PhysicalEnclaveMemory::init(
    KeystoneDevice* dev, uintptr_t phys_addr, size_t min_pages) {
  pDevice = dev;
  // TODO(dayeol): need to set actual EPM size
  epmSize       = PAGE_SIZE * min_pages;
  epmFreeList   = 0; 
  startAddr 		= phys_addr;
}

uintptr_t
PhysicalEnclaveMemory::allocYXSTm(size_t size, uint64_t ms) {
  uintptr_t ret   = pDevice->initYXSTM(size, ms);
  ms_YXSTM        = ms;
  YXSTrustedSize  = size;
  YXSTmPhysAddr   = ret;
  return ret;
}

uintptr_t
PhysicalEnclaveMemory::allocYXSTm(size_t size, uint64_t ms,
                                  uint64_t _engine_id,
                                  uint64_t slice_size,
                                  uint64_t bank_count) {
  uintptr_t ret = pDevice->initYXSTM(
      size, ms, _engine_id, slice_size, bank_count);
  ms_YXSTM        = ms;
  engine_id       = _engine_id;
  YXSTrustedSize  = size;
  YXSTmPhysAddr   = ret;
  return ret;
}

uintptr_t
PhysicalEnclaveMemory::allocUtm(size_t size) {
  uintptr_t ret = pDevice->initUTM(size);
  untrustedSize = size;
  utmPhysAddr   = ret;
  return ret;
}

// TODO: delete this 
/* Only used to allocate memory for root page table */
uintptr_t
PhysicalEnclaveMemory::allocMem(size_t size) {
  uintptr_t ret;

  assert(pDevice);

  ret = reinterpret_cast<uintptr_t>(pDevice->map(0, size));
  return ret;
}

// unused 
uintptr_t
PhysicalEnclaveMemory::readMem(uintptr_t src, size_t size) {
  uintptr_t ret;

  assert(pDevice);

  ret = reinterpret_cast<uintptr_t>(pDevice->map(src, size));
  return ret;
}

/* src: virtual address */
void
PhysicalEnclaveMemory::writeMem(uintptr_t src, uintptr_t offset, size_t size) {
  assert(pDevice);
  void* va_dst = pDevice->map(offset, size);
  assert(va_dst);
  memcpy(va_dst, reinterpret_cast<void*>(src), size);

  /*
   * EPM is loaded page by page.  Keeping each temporary device mapping alive
   * leaks one userspace VMA per page and eventually exhausts vm.max_map_count
   * during create/run/destroy stress.  The mapping is not part of the
   * enclave's persistent address space, so release it as soon as the copy is
   * complete.
   */
  if (munmap(va_dst, size) != 0) {
    std::perror("PhysicalEnclaveMemory::writeMem: munmap");
    assert(false);
  }
}

}  // namespace Keystone
