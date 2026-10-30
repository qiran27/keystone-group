//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <cstdio>

#if __riscv_xlen == 64
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_YXSTRUSTED_PTR 0xffffffffa0000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#elif __riscv_xlen == 32
#define DEFAULT_FREEMEM_SIZE 1024 * 512  // 512 KiB
#define DEFAULT_UNTRUSTED_PTR 0x80000000
#define DEFAULT_YXSTRUSTED_PTR 0xa0000000
#define DEFAULT_STACK_SIZE 1024 * 8  // 3 KiB
#define DEFAULT_STACK_START 0x40000000
#else                                     // for x86 tests
#define DEFAULT_FREEMEM_SIZE 1024 * 1024  // 1 MB
#define DEFAULT_UNTRUSTED_PTR 0xffffffff80000000
#define DEFAULT_YXSTRUSTED_PTR 0xffffffffa0000000
#define DEFAULT_STACK_SIZE 1024 * 16  // 16k
#define DEFAULT_STACK_START 0x0000000040000000
#endif

#define DEFAULT_UNTRUSTED_SIZE 8192  // 8 KB
#define DEFAULT_YXSHARETRUSTED_SIZE 256 * 1024  // 256 KB
#define DEFAULT_YXSTM_SLICE_COUNT 4
#define DEFAULT_YXSTM_SLICE_SIZE \
  (DEFAULT_YXSHARETRUSTED_SIZE / DEFAULT_YXSTM_SLICE_COUNT)
#define DEFAULT_MS_YXSTM 0  //  no ms, not use YXSTM
#define DEFAULT_MS_ENGINE_ID 0  //  no engine is, no ms, not use YXSTM
#define DEFAULT_SEC_MMIO_BASE 0
#define DEFAULT_SEC_MMIO_SIZE 0
#define DEFAULT_SEC_FLAGS 0
#define DEFAULT_SEC_ENGINE_ID 0

/* parameters for enclave creation */
namespace Keystone {

class Params {
 public:
  Params() {
    untrusted_size = DEFAULT_UNTRUSTED_SIZE;
    freemem_size   = DEFAULT_FREEMEM_SIZE;
    YXsharedtrusted_size  = DEFAULT_YXSHARETRUSTED_SIZE;
    YXsharedtrusted_slice_size = DEFAULT_YXSTM_SLICE_SIZE;
    YXsharedtrusted_bank_count = 1;
    ms                    = DEFAULT_MS_YXSTM;
    engine_id             = DEFAULT_MS_ENGINE_ID;
    shared_utm_owner_eid  = 0;  // 0 means no shared UTM
    sec_mmio_base         = DEFAULT_SEC_MMIO_BASE;
    sec_mmio_size         = DEFAULT_SEC_MMIO_SIZE;
    sec_flags             = DEFAULT_SEC_FLAGS;
    sec_engine_id         = DEFAULT_SEC_ENGINE_ID;
  }

  void setUntrustedSize(uint64_t size) { untrusted_size = size; }
  void setFreeMemSize(uint64_t size) { freemem_size = size; }
  uintptr_t getUntrustedSize() const { return untrusted_size; }
  uintptr_t getFreeMemSize() const { return freemem_size; }
  uintptr_t getYXShareTrustedMemSize() const { return YXsharedtrusted_size; }
  uintptr_t getYXShareTrustedSliceSize() const {
    return YXsharedtrusted_slice_size;
  }
  uintptr_t getYXShareTrustedBankCount() const {
    return YXsharedtrusted_bank_count;
  }
  uint64_t getYXms() const { return ms; }
  uint64_t getEngineID() const { return engine_id; }
  void setYXShareTrustedMemSize(uint64_t size) {
    YXsharedtrusted_size = size;
    YXsharedtrusted_slice_size =
        size % DEFAULT_YXSTM_SLICE_COUNT == 0 ?
        size / DEFAULT_YXSTM_SLICE_COUNT : 0;
    YXsharedtrusted_bank_count = 1;
  }
  bool setYXShareTrustedSliceSize(uint64_t size) {
    YXsharedtrusted_slice_size = size;
    return isYXSTMLayoutValid();
  }
  bool setYXSTMLayout(uint64_t total_size, uint64_t slice_size) {
    YXsharedtrusted_size = total_size;
    YXsharedtrusted_slice_size = slice_size;
    YXsharedtrusted_bank_count = 1;
    return isYXSTMLayoutValid();
  }
  bool setYXSTMBankedLayout(uint64_t total_size, uint64_t bank_count,
                            uint64_t bank_slice_size) {
    YXsharedtrusted_size = total_size;
    YXsharedtrusted_slice_size = bank_slice_size;
    YXsharedtrusted_bank_count = bank_count;
    return isYXSTMLayoutValid();
  }
  bool isYXSTMLayoutValid() const {
    const uint64_t page_size = 4096;
    return YXsharedtrusted_size != 0 &&
        YXsharedtrusted_slice_size != 0 &&
        YXsharedtrusted_bank_count != 0 &&
        YXsharedtrusted_bank_count <= 4 &&
        YXsharedtrusted_slice_size <=
            UINT64_MAX / DEFAULT_YXSTM_SLICE_COUNT /
                YXsharedtrusted_bank_count &&
        YXsharedtrusted_slice_size * DEFAULT_YXSTM_SLICE_COUNT *
                YXsharedtrusted_bank_count ==
            YXsharedtrusted_size &&
        (YXsharedtrusted_size & (YXsharedtrusted_size - 1)) == 0 &&
        (YXsharedtrusted_slice_size & (page_size - 1)) == 0;
  }
  void setYXms(uint64_t _ms) { ms = _ms; }
  void setEngineID(uint64_t _engine_id) { engine_id = _engine_id; }

  // Shared UTM support
  void setSharedUtmOwnerEid(unsigned long eid) { shared_utm_owner_eid = eid; }
  unsigned long getSharedUtmOwnerEid() const { return shared_utm_owner_eid; }
  bool hasSharedUtm() const { return shared_utm_owner_eid != 0; }
  void setSecDevice(uint64_t _engine_id, uintptr_t mmio_base, uintptr_t mmio_size, uint64_t flags) {
    sec_engine_id = _engine_id;
    sec_mmio_base = mmio_base;
    sec_mmio_size = mmio_size;
    sec_flags = flags;
  }
  bool useSecDevice() const { return sec_mmio_base != 0 && sec_mmio_size != 0; }
  uintptr_t getSecPaddr() const { return sec_mmio_base; }
  uintptr_t getSecSize() const { return sec_mmio_size; }
  uint64_t getSecFlags() const { return sec_flags; }
  uint64_t getSecEngineID() const { return sec_engine_id; }

 private:
  uint64_t untrusted_size;
  uint64_t freemem_size;
  uint64_t YXsharedtrusted_size;
  uint64_t YXsharedtrusted_slice_size;
  uint64_t YXsharedtrusted_bank_count;
  uint64_t ms;
  uint64_t engine_id;
  unsigned long shared_utm_owner_eid;  // Owner enclave ID for shared UTM (0 = no sharing)
  uintptr_t sec_mmio_base;
  uintptr_t sec_mmio_size;
  uint64_t sec_flags;
  uint64_t sec_engine_id;
};

}  // namespace Keystone
