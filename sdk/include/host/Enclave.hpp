//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>

#include "./common.h"
extern "C" {
#include "common/sha3.h"
}
#include "ElfFile.hpp"
#include "Error.hpp"
#include "KeystoneDevice.hpp"
#include "Memory.hpp"
#include "Params.hpp"

namespace Keystone {

typedef std::function<void(void*)> OcallFunc;

class Enclave {
 private:
  Params params;
  uintptr_t runtimeElfAddr;
  uintptr_t enclaveElfAddr;
  Memory* pMemory;
  KeystoneDevice* pDevice;
  void* shared_buffer;
  size_t shared_buffer_size;
  OcallFunc oFuncDispatch;
  bool mapUntrusted(size_t size);
  void copyFile(uintptr_t filePtr, size_t fileSize);
  void allocUninitialized(ElfFile* elfFile);
  void loadElf(ElfFile* elfFile);

  bool initFiles(const char*, const char*);
  bool initDevice();
  bool prepareEnclaveMemory(size_t requiredPages, uintptr_t alternatePhysAddr);
  bool test_other_os_access_epm_prepareEnclaveMemory(size_t requiredPages, uintptr_t alternatePhysAddr);
  bool initMemory();

  // Shared UTM support
  unsigned long owner_eid_;           // Owner enclave ID if using shared UTM
  uintptr_t shared_utm_paddr_;        // Physical address of shared UTM
  size_t shared_utm_size_;            // Size of shared UTM
  
  // Own UTM buffer for OCALL (used when sharing UTM from another enclave)
  // When using shared UTM mode, the enclave still needs its own small UTM
  // for edge_call communication, while the shared UTM is used for data transfer.
  void* own_utm_buffer_;              // Enclave's own UTM buffer (for OCALL)
  size_t own_utm_buffer_size_;        // Size of own UTM buffer

 public:
  Enclave();
  ~Enclave();
  static Error measure(char* hash, const char* eapppath, const char* runtimepath, const char* loaderpath);
  void* getSharedBuffer();
  size_t getSharedBufferSize();
  Memory* getMemory();
  uintptr_t getRuntimeElfAddr() { return runtimeElfAddr; }
  uintptr_t getEnclaveElfAddr() { return enclaveElfAddr; }
  Error registerOcallDispatch(OcallFunc func);
  Error init(const char* filepath, const char* runtime, const char* loaderpath, Params parameters);
  Error initNoFinalize(const char* filepath, const char* runtime, const char* loaderpath, Params parameters);
  Error finalize();
  Error init(
      const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params,
      uintptr_t alternatePhysAddr);
  
  // Shared UTM initialization - creates enclave that shares UTM with owner enclave
  Error initWithSharedUtm(
      const char* eapppath, const char* runtimepath, const char* loaderpath, 
      Params _params, unsigned long owner_eid);
  
  Error test_other_os_access_epm_init(const char* filepath, const char* runtime, const char* loaderpath, Params parameters);
  Error test_other_os_access_epm_init(
      const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params,
      uintptr_t alternatePhysAddr);
  Error destroy();
  Error run(uintptr_t* ret = nullptr);
  Error test_os_access_epm_run(uintptr_t* ret = nullptr);
  Error test_os_access_stm_run(uintptr_t* ret = nullptr);

  // Getters for enclave info
  int getEid() const;
  
  // Shared UTM getters
  unsigned long getOwnerEid() const { return owner_eid_; }
  uintptr_t getSharedUtmPaddr() const { return shared_utm_paddr_; }
  size_t getSharedUtmSize() const { return shared_utm_size_; }
  bool hasSharedUtm() const { return owner_eid_ != 0; }
  
  // Get the buffer used for OCALL communication
  // For shared UTM mode, this returns the enclave's own UTM buffer
  // For regular mode, this returns the shared_buffer (same as getSharedBuffer)
  void* getOcallBuffer();
  size_t getOcallBufferSize();
};

uint64_t
calculate_required_pages(ElfFile** elfFiles, size_t numElfFiles);

}  // namespace Keystone
