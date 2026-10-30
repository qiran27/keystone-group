//******************************************************************************
// Copyright (c) 2020, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "./common.h"
#include "Error.hpp"
#include "Params.hpp"
#include "shared/keystone_user.h"

namespace Keystone {

class KeystoneDevice {
 protected:
  int eid;
  uintptr_t physAddr;

 private:
  int fd;
  uintptr_t secPaddr;
  uintptr_t secSize;
  uintptr_t secFlags;
  uintptr_t secEngineId;
  Error __run(bool resume, uintptr_t* ret);
  Error __test_os_access_run(bool test_os_access_stm, bool resume, uintptr_t* ret);

 public:
  virtual uintptr_t getPhysAddr() { return physAddr; }
  virtual int getEid() { return eid; }

  KeystoneDevice();
  virtual ~KeystoneDevice();
  virtual bool initDevice(Params params);
  virtual Error create(uint64_t minPages, uint64_t ms = 0, uint64_t engineId = 0);
  virtual Error test_other_os_access_epm_create(uint64_t minPages, uint64_t ms = 0, uint64_t engineId = 0);
  virtual uintptr_t initUTM(size_t size);
  virtual uintptr_t initYXSTM(size_t size, uint64_t ms);
  virtual uintptr_t initYXSTM(size_t size, uint64_t ms, uint64_t _engine_id,
                              uint64_t slice_size = 0,
                              uint64_t bank_count = 1);
  virtual Error shareUtm(unsigned long owner_eid, unsigned long target_eid, 
                         uintptr_t* utm_paddr, size_t* utm_size);
  virtual Error groupSetCount(uint64_t groupCount);
  virtual Error groupSetHartCount(uint64_t groupId, uint64_t hartCount);
  virtual Error groupQuery(uint64_t groupId, uint64_t* groupCount,
                           uint64_t* hartCount, uint64_t* hartMask,
                           uint64_t* memberCapacity = nullptr,
                           uint64_t* memberCount = nullptr,
                           uint64_t* lifecycleState = nullptr,
                           uint64_t* generation = nullptr);
  virtual Error groupConfigTopology(
      struct keystone_group_topology* topology);
  virtual Error groupQueryTopology(
      uint64_t groupId, struct keystone_group_topology* topology);
  virtual Error groupLeaseWorkers(
      uint64_t groupId, uint64_t flags = 0,
      struct keystone_group_lease* lease = nullptr);
  virtual Error groupReleaseWorkers(
      uint64_t groupId, uint64_t flags = 0,
      struct keystone_group_lease* lease = nullptr);
  virtual Error groupCreate(uint64_t groupId, uint64_t memberCapacity = 0);
  virtual Error groupActivate(uint64_t groupId);
  virtual Error groupDestroy(uint64_t groupId);
  virtual Error groupBindEnclave(
      uint64_t eid, uint64_t hartId,
      uint64_t priority = KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT,
      uint64_t quantumTicks = KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT);
  virtual Error groupEnqueueEnclave(uint64_t eid);
  virtual Error groupPollBlockedOcall(uint64_t groupId, uint64_t hartId,
                                      uint64_t* pendingEid,
                                      uint64_t* pendingCount,
                                      uint64_t* ocallId = nullptr,
                                      uint64_t* timeoutCycles = nullptr,
                                      uint64_t* hostCookie = nullptr,
                                      uint64_t* createdAt = nullptr,
                                      uint64_t* deadline = nullptr,
                                      uint64_t* flags = nullptr);
  virtual Error groupResumeBlockedOcall(uint64_t groupId, uint64_t hartId,
                                        uint64_t eid, uint64_t ocallId = 0,
                                        uintptr_t result = 0,
                                        uint64_t flags = 0);
  virtual Error groupResumeBlockedOcalls(
      uint64_t groupId,
      const struct keystone_group_ocall_resume_entry* entries,
      uint64_t count, uint64_t* resumedCount = nullptr);
  virtual Error groupCancelBlockedOcall(uint64_t groupId, uint64_t hartId,
                                         uint64_t eid, uint64_t ocallId = 0);
  virtual Error groupAbandonBlockedOcall(uint64_t groupId, uint64_t hartId,
                                         uint64_t eid, uint64_t ocallId = 0,
                                         uint64_t hostCookie = 0);
  virtual Error groupRunHart(uint64_t groupId, uint64_t hartId,
                             uint64_t* eventEid, uint64_t* event,
                             uintptr_t* ret,
                             uint64_t* eventSequence = nullptr,
                             uint64_t* schedulerEpoch = nullptr,
                             uint64_t* queueOverflows = nullptr);
  virtual Error groupRunMaster(uint64_t groupId, uint64_t* eventEid,
                               uint64_t* event, uintptr_t* ret,
                               uint64_t* eventSequence = nullptr,
                               uint64_t* schedulerEpoch = nullptr,
                               uint64_t* queueOverflows = nullptr);
  virtual Error groupWaitEvent(
      uint64_t groupId, uint64_t eventMask, uint64_t timeoutMs,
      struct keystone_group_wait_event* event);
  virtual Error groupPauseMaster(uint64_t groupId,
                                 uint64_t* status = nullptr,
                                 uint64_t* schedulerEpoch = nullptr);
  virtual Error groupControlEnclave(uint64_t eid, uint64_t action,
                                    uint64_t* status = nullptr,
                                    uint64_t* schedulerEpoch = nullptr);
  virtual Error groupTestSnapshot(uint64_t groupId,
                                  struct keystone_group_test_snapshot* snapshot);
  virtual Error groupTestInject(uint64_t operation, uint64_t groupId,
                                uint64_t hartId, uint64_t count);
  virtual Error groupPerfQuery(
      uint64_t groupId, uint64_t operation,
      struct keystone_group_perf_snapshot* snapshot,
      uint64_t memberEid = 0);
  virtual Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  virtual Error test_other_os_access_epm_finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  virtual Error destroy();
  virtual Error run(uintptr_t* ret);
  virtual Error resume(uintptr_t* ret);
  virtual Error test_os_access_run(uintptr_t* ret, bool test_os_access_stm);
  virtual Error test_os_access_resume(uintptr_t* ret, bool test_os_access_stm);
  virtual void* map(uintptr_t addr, size_t size);
  
  // Map the enclave's own UTM (for OCALL communication in shared UTM mode)
  // This is separate from map() which maps the shared UTM for data transfer
  virtual void* mapOwnUtm(size_t size);
};

class MockKeystoneDevice : public KeystoneDevice {
 private:
  /* allocated buffer with map() */
  void* sharedBuffer;

 public:
  MockKeystoneDevice() {}
  ~MockKeystoneDevice();
  bool initDevice(Params params);
  Error create(uint64_t minPages, uint64_t ms = 0, uint64_t engineId = 0);
  Error test_other_os_access_epm_create(uint64_t minPages, uint64_t ms = 0, uint64_t engineId = 0);
  uintptr_t initUTM(size_t size);
  uintptr_t initYXSTM(size_t size, uint64_t ms);
  uintptr_t initYXSTM(size_t size, uint64_t ms, uint64_t _engine_id,
                      uint64_t slice_size = 0,
                      uint64_t bank_count = 1);
  Error shareUtm(unsigned long owner_eid, unsigned long target_eid,
                 uintptr_t* utm_paddr, size_t* utm_size);
  Error groupSetCount(uint64_t groupCount);
  Error groupSetHartCount(uint64_t groupId, uint64_t hartCount);
  Error groupQuery(uint64_t groupId, uint64_t* groupCount,
                   uint64_t* hartCount, uint64_t* hartMask,
                   uint64_t* memberCapacity = nullptr,
                   uint64_t* memberCount = nullptr,
                   uint64_t* lifecycleState = nullptr,
                   uint64_t* generation = nullptr);
  Error groupConfigTopology(struct keystone_group_topology* topology);
  Error groupQueryTopology(uint64_t groupId,
                           struct keystone_group_topology* topology);
  Error groupLeaseWorkers(uint64_t groupId, uint64_t flags = 0,
                          struct keystone_group_lease* lease = nullptr);
  Error groupReleaseWorkers(uint64_t groupId, uint64_t flags = 0,
                            struct keystone_group_lease* lease = nullptr);
  Error groupCreate(uint64_t groupId, uint64_t memberCapacity = 0);
  Error groupActivate(uint64_t groupId);
  Error groupDestroy(uint64_t groupId);
  Error groupBindEnclave(
      uint64_t eid, uint64_t hartId,
      uint64_t priority = KEYSTONE_GROUP_SCHED_PRIORITY_DEFAULT,
      uint64_t quantumTicks = KEYSTONE_GROUP_SCHED_QUANTUM_DEFAULT);
  Error groupEnqueueEnclave(uint64_t eid);
  Error groupPollBlockedOcall(uint64_t groupId, uint64_t hartId,
                              uint64_t* pendingEid,
                              uint64_t* pendingCount,
                              uint64_t* ocallId = nullptr,
                              uint64_t* timeoutCycles = nullptr,
                              uint64_t* hostCookie = nullptr,
                              uint64_t* createdAt = nullptr,
                              uint64_t* deadline = nullptr,
                              uint64_t* flags = nullptr);
  Error groupResumeBlockedOcall(uint64_t groupId, uint64_t hartId,
                                uint64_t eid, uint64_t ocallId = 0,
                                uintptr_t result = 0,
                                uint64_t flags = 0);
  Error groupResumeBlockedOcalls(
      uint64_t groupId,
      const struct keystone_group_ocall_resume_entry* entries,
      uint64_t count, uint64_t* resumedCount = nullptr);
  Error groupCancelBlockedOcall(uint64_t groupId, uint64_t hartId,
                                 uint64_t eid, uint64_t ocallId = 0);
  Error groupAbandonBlockedOcall(uint64_t groupId, uint64_t hartId,
                                 uint64_t eid, uint64_t ocallId = 0,
                                 uint64_t hostCookie = 0);
  Error groupRunHart(uint64_t groupId, uint64_t hartId,
                     uint64_t* eventEid, uint64_t* event,
                     uintptr_t* ret,
                     uint64_t* eventSequence = nullptr,
                     uint64_t* schedulerEpoch = nullptr,
                     uint64_t* queueOverflows = nullptr);
  Error groupRunMaster(uint64_t groupId, uint64_t* eventEid,
                       uint64_t* event, uintptr_t* ret,
                       uint64_t* eventSequence = nullptr,
                       uint64_t* schedulerEpoch = nullptr,
                       uint64_t* queueOverflows = nullptr);
  Error groupWaitEvent(uint64_t groupId, uint64_t eventMask,
                       uint64_t timeoutMs,
                       struct keystone_group_wait_event* event);
  Error groupPauseMaster(uint64_t groupId, uint64_t* status = nullptr,
                         uint64_t* schedulerEpoch = nullptr);
  Error groupControlEnclave(uint64_t eid, uint64_t action,
                            uint64_t* status = nullptr,
                            uint64_t* schedulerEpoch = nullptr);
  Error groupTestSnapshot(uint64_t groupId,
                          struct keystone_group_test_snapshot* snapshot);
  Error groupTestInject(uint64_t operation, uint64_t groupId,
                        uint64_t hartId, uint64_t count);
  Error groupPerfQuery(uint64_t groupId, uint64_t operation,
                       struct keystone_group_perf_snapshot* snapshot,
                       uint64_t memberEid = 0);
  Error finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  Error test_other_os_access_epm_finalize(
      uintptr_t runtimePhysAddr, uintptr_t eappPhysAddr, uintptr_t freePhysAddr,
      uintptr_t freeRequested);
  Error destroy();
  Error run(uintptr_t* ret);
  Error resume(uintptr_t* ret);
  Error test_os_access_run(uintptr_t* ret, bool test_os_access_stm);
  Error test_os_access_resume(uintptr_t* ret, bool test_os_access_stm);
  void* map(uintptr_t addr, size_t size);
  void* mapOwnUtm(size_t size);
};

}  // namespace Keystone
