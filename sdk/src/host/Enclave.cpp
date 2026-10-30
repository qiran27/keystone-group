//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "Enclave.hpp"
#include <cstdio>
#include <cstdlib>
#include <math.h>
#include <sys/mman.h>
#include <sys/stat.h>
extern "C" {
#include "common/sha3.h"
#include "shared/keystone_user.h"
}
#include "ElfFile.hpp"
#include "hash_util.hpp"

namespace Keystone {

static bool
validateYXSTMLayout(const Params& params) {
  if (params.getYXms() == 0)
    return true;
  if (params.isYXSTMLayoutValid())
    return true;

  ERROR("invalid YXSTM layout: total=%lu slice=%lu count=%u\n",
        (unsigned long)params.getYXShareTrustedMemSize(),
        (unsigned long)params.getYXShareTrustedSliceSize(),
        (unsigned int)DEFAULT_YXSTM_SLICE_COUNT);
  return false;
}

static uint64_t
keystoneRunLoopLimit() {
  static bool parsed = false;
  static uint64_t limit = 0;

  if (!parsed) {
    const char* env = getenv("KEYSTONE_RUN_LOOP_LIMIT");
    if (env && env[0]) {
      limit = strtoull(env, NULL, 0);
    }
    parsed = true;
  }

  return limit;
}

static bool
diagnoseRunLoop(const char* label, int eid, Error ret, uint64_t edgeCalls,
                uint64_t interrupts) {
  uint64_t total = edgeCalls + interrupts;

  if (total <= 8 || total % 1000 == 0) {
    const char* reason =
        ret == Error::EdgeCallHost ? "edge-call-host" : "interrupted";
    fprintf(stderr,
            "[Keystone SDK][run-loop] %s eid=%d reason=%s total=%llu "
            "edge_calls=%llu interrupts=%llu\n",
            label, eid, reason, (unsigned long long)total,
            (unsigned long long)edgeCalls, (unsigned long long)interrupts);
  }

  uint64_t limit = keystoneRunLoopLimit();
  if (limit != 0 && total >= limit) {
    fprintf(stderr,
            "[Keystone SDK][run-loop] %s eid=%d aborting after %llu "
            "automatic resumes; set KEYSTONE_RUN_LOOP_LIMIT=0 to disable\n",
            label, eid, (unsigned long long)total);
    return true;
  }

  return false;
}

Enclave::Enclave() {
  owner_eid_ = 0;
  shared_utm_paddr_ = 0;
  shared_utm_size_ = 0;
  own_utm_buffer_ = nullptr;
  own_utm_buffer_size_ = 0;
  pMemory = nullptr;
  pDevice = nullptr;
  shared_buffer = nullptr;
  shared_buffer_size = 0;
}

Enclave::~Enclave() {
  destroy();
}

uint64_t
calculate_required_pages(ElfFile** elfFiles, size_t numElfFiles) {
  uint64_t req_pages = 0;

  for (int i = 0; i < numElfFiles; i++) {
    ElfFile* elfFile = elfFiles[i];
    req_pages += ceil(elfFile->getFileSize() / PAGE_SIZE);
  }
  /* FIXME: calculate the required number of pages for the page table.
   * We actually don't know how many page tables the enclave might need,
   * because the SDK never knows how its memory will be aligned.
   * Ideally, this should be managed by the driver.
   * For now, we naively allocate enough pages so that we can temporarily get
   * away from this problem.
   * 15 pages will be more than sufficient to cover several hundreds of
   * megabytes of enclave/runtime. */
  /* FIXME Part 2: now that loader does loading, .bss sections also eat up
   * space. Eapp dev must make FREEMEM big enough to fit this!!
   * Possible fix -- re-add exact .bss calculations?
   */

  /* Add one page each for bss segments of runtime and eapp */ 
  // TODO: add space for stack?
  req_pages += 16;
  return req_pages;
}

bool
Enclave::prepareEnclaveMemory(size_t requiredPages, uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE; 
  minPages += requiredPages;

  /* Call Enclave Driver */
  if (pDevice->create(minPages, params.getYXms(), params.getEngineID()) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

bool
Enclave::test_other_os_access_epm_prepareEnclaveMemory(size_t requiredPages, uintptr_t alternatePhysAddr) {
  // FIXME: this will be deprecated with complete freemem support.
  // We just add freemem size for now.
  uint64_t minPages;
  minPages = ROUND_UP(params.getFreeMemSize(), PAGE_BITS) / PAGE_SIZE; 
  minPages += requiredPages;

  /* Call Enclave Driver */
  if (pDevice->test_other_os_access_epm_create(minPages, params.getYXms(), params.getEngineID()) != Error::Success) {
    return false;
  }

  /* We switch out the phys addr as needed */
  uintptr_t physAddr;
  if (alternatePhysAddr) {
    physAddr = alternatePhysAddr;
  } else {
    physAddr = pDevice->getPhysAddr();
  }

  pMemory->init(pDevice, physAddr, minPages);
  return true;
}

void
Enclave::copyFile(uintptr_t filePtr, size_t fileSize) {
	uintptr_t startOffset = pMemory->getCurrentOffset(); 
  size_t bytesRemaining = fileSize; 
	
	uintptr_t currOffset;
	while (bytesRemaining > 0) {
		currOffset = pMemory->getCurrentOffset(); 
    pMemory->incrementEPMFreeList();

		size_t bytesToWrite = (bytesRemaining > PAGE_SIZE) ? PAGE_SIZE : bytesRemaining;
		size_t bytesWritten = fileSize - bytesRemaining;

    // need 0 padding for hashes to be consistent,
    // and to keep code aligned to be able to map page-wise without copying.
    if (bytesToWrite < PAGE_SIZE) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) (filePtr + bytesWritten), (size_t)(bytesToWrite));
      pMemory->writeMem((uintptr_t) page, currOffset, PAGE_SIZE);
    } else {
		  pMemory->writeMem(filePtr + bytesWritten, currOffset, bytesToWrite);
    }
		bytesRemaining -= bytesToWrite;
	}
}

static void measureElfFile(hash_ctx_t* hash_ctx, ElfFile* file) {
  uintptr_t fptr = (uintptr_t) file->getPtr();
  uintptr_t fend = fptr + (uintptr_t) file->getFileSize();

  for (; fptr < fend; fptr += PAGE_SIZE) {
    if (fend - fptr < PAGE_SIZE) {
      char page[PAGE_SIZE];
      memset(page, 0, PAGE_SIZE);
      memcpy(page, (const void*) fptr, (size_t)(fend-fptr));
      hash_extend_page(hash_ctx, (void*) page);
    } else {
      hash_extend_page(hash_ctx, (void*) fptr);
    }
  }
}

Error
Enclave::measure(char* hash, const char* eapppath, const char* runtimepath, const char* loaderpath) {
  hash_ctx_t hash_ctx;
  hash_init(&hash_ctx);

  ElfFile* loader = new ElfFile(loaderpath);
  ElfFile* runtime = new ElfFile(runtimepath);
  ElfFile* eapp = new ElfFile(eapppath);

  uintptr_t sizes[3] = { PAGE_UP(loader->getFileSize()), PAGE_UP(runtime->getFileSize()),
                          PAGE_UP(eapp->getFileSize()) };
  hash_extend(&hash_ctx, (void*) sizes, sizeof(sizes));

  measureElfFile(&hash_ctx, loader);
  delete loader;
  measureElfFile(&hash_ctx, runtime);
  delete runtime;
  measureElfFile(&hash_ctx, eapp);
  delete eapp;

  hash_finalize(hash, &hash_ctx);

  return Error::Success;
}

Error
Enclave::init(const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params) {
  return this->init(eapppath, runtimepath, loaderpath, _params, (uintptr_t)0);
}

Error
Enclave::initNoFinalize(const char* eapppath, const char* runtimepath,
    const char* loaderpath, Params _params) {
  params = _params;

  if (!validateYXSTMLayout(params))
    return Error::DeviceError;

  pMemory = new PhysicalEnclaveMemory();
  pDevice = new KeystoneDevice();

  ElfFile* enclaveFile = new ElfFile(eapppath);
  ElfFile* runtimeFile = new ElfFile(runtimepath);
  ElfFile* loaderFile = new ElfFile(loaderpath);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!prepareEnclaveMemory(requiredPages, 0)) {
    destroy();
    return Error::DeviceError;
  }
  if (!pMemory->allocUtm(params.getUntrustedSize())) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }
  if (params.getYXms() != 0) {
    if (params.getEngineID() == 0) {
      std::cout << "dont set Engine id" << std::endl;
    }
    if (!pMemory->allocYXSTm(params.getYXShareTrustedMemSize(),
            params.getYXms(), params.getEngineID(),
            params.getYXShareTrustedSliceSize(),
            params.getYXShareTrustedBankCount())) {
      ERROR("failed to init YX share trusted memory - ioctl() failed");
      destroy();
      return Error::DeviceError;
    }
  }

  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());

  pMemory->startEappMem();
  copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());

  pMemory->startFreeMem();

  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;
  return Error::Success;
}

Error
Enclave::finalize() {
  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), params.getFreeMemSize()) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }
  return Error::Success;
}

Error
Enclave::init(
    const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (!validateYXSTMLayout(params))
    return Error::DeviceError;

  pMemory = new PhysicalEnclaveMemory();
  pDevice = new KeystoneDevice();

  ElfFile* enclaveFile = new ElfFile(eapppath);
  ElfFile* runtimeFile = new ElfFile(runtimepath);
  ElfFile* loaderFile = new ElfFile(loaderpath);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!prepareEnclaveMemory(requiredPages, alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }
  if (!pMemory->allocUtm(params.getUntrustedSize())) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }
  if (params.getYXms() != 0) {
    // Additional logic can be added here if needed
    if (params.getEngineID() == 0) {
      std::cout << "dont set Engine id" << std::endl;
    }
    if (!pMemory->allocYXSTm(params.getYXShareTrustedMemSize(),
            params.getYXms(), params.getEngineID(),
            params.getYXShareTrustedSliceSize(),
            params.getYXShareTrustedBankCount())) {
      ERROR("failed to init YX share trusted memory - ioctl() failed");
      destroy();
      return Error::DeviceError;
    }
  }
	
  /* Copy loader into beginning of enclave memory */
  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());

  pMemory->startEappMem();
  copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());

  pMemory->startFreeMem();

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), params.getFreeMemSize()) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;
  return Error::Success;
}

Error
Enclave::test_other_os_access_epm_init(const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params) {
  return this->test_other_os_access_epm_init(eapppath, runtimepath, loaderpath, _params, (uintptr_t)0);
}

Error
Enclave::test_other_os_access_epm_init(
    const char* eapppath, const char* runtimepath, const char* loaderpath, Params _params,
    uintptr_t alternatePhysAddr) {
  params = _params;

  if (!validateYXSTMLayout(params))
    return Error::DeviceError;

  pMemory = new PhysicalEnclaveMemory();
  pDevice = new KeystoneDevice();

  ElfFile* enclaveFile = new ElfFile(eapppath);
  ElfFile* runtimeFile = new ElfFile(runtimepath);
  ElfFile* loaderFile = new ElfFile(loaderpath);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!test_other_os_access_epm_prepareEnclaveMemory(requiredPages, alternatePhysAddr)) {
    destroy();
    return Error::DeviceError;
  }
  if (!pMemory->allocUtm(params.getUntrustedSize())) {
    ERROR("failed to init untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }
  if (params.getYXms() != 0) {
    // Additional logic can be added here if needed
    if (!pMemory->allocYXSTm(params.getYXShareTrustedMemSize(), params.getYXms())) {
      ERROR("failed to init YX share trusted memory - ioctl() failed");
      destroy();
      return Error::DeviceError;
    }
  }
	
  /* Copy loader into beginning of enclave memory */
  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());

  pMemory->startEappMem();
  copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());

  pMemory->startFreeMem();

  if (pDevice->test_other_os_access_epm_finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), params.getFreeMemSize()) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }
  if (!mapUntrusted(params.getUntrustedSize())) {
    ERROR(
        "failed to finalize enclave - cannot obtain the untrusted buffer "
        "pointer \n");
    destroy();
    return Error::DeviceMemoryMapError;
  }

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;
  return Error::Success;
}

Error
Enclave::initWithSharedUtm(
    const char* eapppath, const char* runtimepath, const char* loaderpath,
    Params _params, unsigned long owner_eid) {
  params = _params;
  owner_eid_ = owner_eid;

  if (!validateYXSTMLayout(params))
    return Error::DeviceError;

  pMemory = new PhysicalEnclaveMemory();
  pDevice = new KeystoneDevice();

  ElfFile* enclaveFile = new ElfFile(eapppath);
  ElfFile* runtimeFile = new ElfFile(runtimepath);
  ElfFile* loaderFile = new ElfFile(loaderpath);

  if (!pDevice->initDevice(params)) {
    destroy();
    return Error::DeviceInitFailure;
  }

  ElfFile* elfFiles[3] = {enclaveFile, runtimeFile, loaderFile};
  size_t requiredPages = calculate_required_pages(elfFiles, 3);

  if (!prepareEnclaveMemory(requiredPages, 0)) {
    destroy();
    return Error::DeviceError;
  }

  // For shared UTM mode, we still need a minimal UTM for edge_call
  // But the main data transfer will use the shared UTM from owner
  if (!pMemory->allocUtm(params.getUntrustedSize())) {
    ERROR("failed to init minimal untrusted memory - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  // Set up YXSTM if needed for synchronization
  if (params.getYXms() != 0) {
    if (params.getEngineID() == 0) {
      std::cout << "dont set Engine id" << std::endl;
    }
    if (!pMemory->allocYXSTm(params.getYXShareTrustedMemSize(),
            params.getYXms(), params.getEngineID(),
            params.getYXShareTrustedSliceSize(),
            params.getYXShareTrustedBankCount())) {
      ERROR("failed to init YX share trusted memory - ioctl() failed");
      destroy();
      return Error::DeviceError;
    }
  }

  /*
   * CRITICAL: Share UTM BEFORE finalize
   * ===================================
   * 
   * The shared UTM information must be set up in the Driver's enclave struct
   * BEFORE calling finalize, because finalize passes the shared_utm_region
   * to SM, which then passes it to Runtime via registers.
   * 
   * If we call shareUtm after finalize, the Runtime will not know about
   * the shared UTM and will use its own small UTM, causing access faults.
   */
  Error shareErr = pDevice->shareUtm(owner_eid, pDevice->getEid(), 
                                      &shared_utm_paddr_, &shared_utm_size_);
  if (shareErr != Error::Success) {
    ERROR("failed to share UTM from owner enclave %lu\n", owner_eid);
    destroy();
    return shareErr;
  }

  /* Copy loader into beginning of enclave memory */
  copyFile((uintptr_t) loaderFile->getPtr(), loaderFile->getFileSize());

  pMemory->startRuntimeMem();
  copyFile((uintptr_t) runtimeFile->getPtr(), runtimeFile->getFileSize());

  pMemory->startEappMem();
  copyFile((uintptr_t) enclaveFile->getPtr(), enclaveFile->getFileSize());

  pMemory->startFreeMem();

  if (pDevice->finalize(
          pMemory->getRuntimePhysAddr(), pMemory->getEappPhysAddr(),
          pMemory->getFreePhysAddr(), params.getFreeMemSize()) != Error::Success) {
    destroy();
    return Error::DeviceError;
  }

  // Map the shared UTM for this enclave (for Host access to data)
  // The shared UTM is mapped at offset 0 (same as regular UTM)
  if (shared_utm_size_ > 0) {
    shared_buffer = pDevice->map(0, shared_utm_size_);
    if (shared_buffer == NULL) {
      ERROR("failed to map shared UTM buffer\n");
      destroy();
      return Error::DeviceMemoryMapError;
    }
    shared_buffer_size = shared_utm_size_;
    
    /*
     * CRITICAL FIX: Map own UTM for OCALL communication
     * =================================================
     * 
     * When using shared UTM mode, the enclave still needs its own small UTM
     * for edge_call communication. The Runtime uses the enclave's own UTM
     * (not the shared UTM) for OCALL edge_call structures.
     * 
     * We need to map the enclave's own UTM separately so that the Host can
     * read/write edge_call structures from the correct buffer.
     * 
     * Memory layout:
     * - own_utm_buffer_: Enclave's own 1MB UTM (for OCALL edge_call)
     * - shared_buffer: Main's 64MB shared UTM (for data transfer)
     * 
     * The OCALL handler (oFuncDispatch) should use own_utm_buffer_ for
     * edge_call communication, while data transfer uses shared_buffer.
     */
    own_utm_buffer_ = pDevice->mapOwnUtm(params.getUntrustedSize());
    if (own_utm_buffer_ == NULL) {
      ERROR("failed to map own UTM buffer for OCALL\n");
      destroy();
      return Error::DeviceMemoryMapError;
    }
    own_utm_buffer_size_ = params.getUntrustedSize();
  } else {
    // Fall back to own UTM if shared UTM is not available
    if (!mapUntrusted(params.getUntrustedSize())) {
      ERROR("failed to map untrusted buffer\n");
      destroy();
      return Error::DeviceMemoryMapError;
    }
    // In non-shared mode, own_utm_buffer_ is the same as shared_buffer
    own_utm_buffer_ = shared_buffer;
    own_utm_buffer_size_ = shared_buffer_size;
  }

  /* ELF files are no longer needed */
  delete enclaveFile;
  delete runtimeFile;
  delete loaderFile;
  return Error::Success;
}

int
Enclave::getEid() const {
  if (pDevice) {
    return pDevice->getEid();
  }
  return -1;
}

bool
Enclave::mapUntrusted(size_t size) {
  if (size == 0) {
    return true;
  }

  shared_buffer = pDevice->map(0, size);

  if (shared_buffer == NULL) {
    return false;
  }

  shared_buffer_size = size;

  return true;
}

Error
Enclave::destroy() {
  Error ret = Error::Success;

  /* In the normal UTM path these two members refer to the same mapping. */
  void* mapped_shared_buffer = shared_buffer;

  if (shared_buffer && shared_buffer_size) {
    munmap(shared_buffer, shared_buffer_size);
  }
  shared_buffer = nullptr;
  shared_buffer_size = 0;

  if (own_utm_buffer_ && own_utm_buffer_size_ &&
      own_utm_buffer_ != mapped_shared_buffer) {
    munmap(own_utm_buffer_, own_utm_buffer_size_);
  }
  own_utm_buffer_ = nullptr;
  own_utm_buffer_size_ = 0;

  if (pDevice) {
    ret = pDevice->destroy();
    delete pDevice;
    pDevice = nullptr;
  }

  delete pMemory;
  pMemory = nullptr;

  return ret;
}

Error
Enclave::run(uintptr_t* retval) {
  Error ret = pDevice->run(retval);
  uint64_t edgeCalls = 0;

  while (ret == Error::EdgeCallHost) {
    edgeCalls++;

    if (diagnoseRunLoop("run", pDevice->getEid(), ret, edgeCalls, 0)) {
      destroy();
      return Error::DeviceError;
    }

    /* enclave is stopped in the middle. */
    if (oFuncDispatch == NULL) {
      return Error::EdgeCallHost;
    }

    /*
     * CRITICAL FIX: Use getOcallBuffer() for OCALL communication
     * ===========================================================
     *
     * For shared UTM mode, the enclave uses its own UTM for edge_call
     * communication, not the shared UTM. The shared UTM is only used
     * for data transfer.
     *
     * getOcallBuffer() returns:
     * - own_utm_buffer_ for shared UTM mode (enclave's own 1MB UTM)
     * - shared_buffer for regular mode (same as getSharedBuffer())
    */
    oFuncDispatch(getOcallBuffer());

    /*
     * A group enclave's edge call is a scheduler-visible blocking event.
     * Once the host dispatcher has completed the call, explicitly transfer
     * the enclave from BLOCKED back to RUNNABLE before using the normal
     * resume ioctl.  Non-group enclaves retain the original Keystone path.
     */
    if (params.getYXms() != 0 && params.getEngineID() != 0) {
      Error unblock = pDevice->groupResumeBlockedOcall(
          params.getEngineID(), KEYSTONE_GROUP_OCALL_ANY_HART,
          static_cast<uint64_t>(pDevice->getEid()), 0, 0);
      if (unblock != Error::Success) {
        ERROR("failed to resume blocked group OCALL");
        destroy();
        return Error::DeviceError;
      }
    }
    ret = pDevice->resume(retval);
  }

  if (ret == Error::EnclaveInterrupted) {
    return ret;
  }

  if (ret == Error::EnclaveFatalFault) {
    ERROR("enclave fatal fault");
    destroy();
    return ret;
  }

  if (ret != Error::Success) {
    ERROR("failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

Error
Enclave::test_os_access_epm_run(uintptr_t* retval) {
  Error ret = pDevice->test_os_access_run(retval, false);
  uint64_t edgeCalls = 0;

  while (ret == Error::EdgeCallHost) {
    edgeCalls++;

    if (diagnoseRunLoop("test-os-access-epm", pDevice->getEid(), ret,
                        edgeCalls, 0)) {
      destroy();
      return Error::DeviceError;
    }

    /* enclave is stopped in the middle. */
    if (oFuncDispatch == NULL) {
      return Error::EdgeCallHost;
    }

    oFuncDispatch(getSharedBuffer());
    ret = pDevice->test_os_access_resume(retval, false);
  }

  if (ret == Error::EnclaveInterrupted) {
    return ret;
  }

  if (ret == Error::EnclaveFatalFault) {
    ERROR("test os access epm enclave fatal fault");
    destroy();
    return ret;
  }

  if (ret != Error::Success) {
    ERROR("test os access epm failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

Error
Enclave::test_os_access_stm_run(uintptr_t* retval) {
  Error ret = pDevice->test_os_access_run(retval, true);
  uint64_t edgeCalls = 0;

  while (ret == Error::EdgeCallHost) {
    edgeCalls++;

    if (diagnoseRunLoop("test-os-access-stm", pDevice->getEid(), ret,
                        edgeCalls, 0)) {
      destroy();
      return Error::DeviceError;
    }

    /* enclave is stopped in the middle. */
    if (oFuncDispatch == NULL) {
      return Error::EdgeCallHost;
    }

    oFuncDispatch(getSharedBuffer());
    ret = pDevice->test_os_access_resume(retval, true);
  }

  if (ret == Error::EnclaveInterrupted) {
    return ret;
  }

  if (ret == Error::EnclaveFatalFault) {
    ERROR("test os access stm enclave fatal fault");
    destroy();
    return ret;
  }

  if (ret != Error::Success) {
    ERROR("test os access stm failed to run enclave - ioctl() failed");
    destroy();
    return Error::DeviceError;
  }

  return Error::Success;
}

void*
Enclave::getSharedBuffer() {
  return shared_buffer;
}

size_t
Enclave::getSharedBufferSize() {
  return shared_buffer_size;
}

void*
Enclave::getOcallBuffer() {
  /*
   * Get the buffer used for OCALL communication
   * ============================================
   * 
   * For shared UTM mode:
   *   - Returns own_utm_buffer_ (enclave's own 1MB UTM)
   *   - This is where the Runtime writes edge_call structures
   * 
   * For regular mode:
   *   - Returns shared_buffer (same as getSharedBuffer())
   *   - own_utm_buffer_ is set to shared_buffer in this case
   */
  if (own_utm_buffer_ != nullptr) {
    return own_utm_buffer_;
  }
  // Fall back to shared_buffer for backward compatibility
  return shared_buffer;
}

size_t
Enclave::getOcallBufferSize() {
  if (own_utm_buffer_size_ > 0) {
    return own_utm_buffer_size_;
  }
  return shared_buffer_size;
}

Memory*
Enclave::getMemory() {
  return pMemory;
}

Error
Enclave::registerOcallDispatch(OcallFunc func) {
  oFuncDispatch = func;
  return Error::Success;
}

}  // namespace Keystone
