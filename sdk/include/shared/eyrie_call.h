#ifndef __EYRIE_CALL_H__
#define __EYRIE_CALL_H__

#include <stdint.h>

#define RUNTIME_SYSCALL_UNKNOWN             1000
#define RUNTIME_SYSCALL_OCALL               1001
#define RUNTIME_SYSCALL_SHAREDCOPY          1002
#define RUNTIME_SYSCALL_ATTEST_ENCLAVE      1003
#define RUNTIME_SYSCALL_GET_SEALING_KEY     1004
#define RUNTIME_SYSCALL_MAIN_ENCLAVE_GET_SLAVE_ENCLAVE_DATA 1005
#define RUNTIME_SYSCALL_SLAVE_ENCLAVE_SET_DATAPTR           1006
#define RUNTIME_SYSCALL_CREATE_GROUP                        1007
#define RUNTIME_SYSCALL_JOIN_GROUP                          1008
#define RUNTIME_SYSCALL_YXSTM_SET_NUMBERBLOCK               1009
#define RUNTIME_SYSCALL_YXSTM_GET_NUMBERBLOCK               1010
#define RUNTIME_SYSCALL_STM_ACCESS_TEST                     1011
#define RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_O     1012
#define RUNTIME_SYSCALL_TEST_OTHER_ENCLAVE_ACCESS_EPM_S     1013
#define RUNTIME_SYSCALL_M_ATTEST_S_ENCLAVE                  1014
#define RUNTIME_SYSCALL_S_ENCLAVE_ATTESTTED                 1015
#define RUNTIME_SYSCALL_WAIT_MAIN_DISPATCH                  1016
#define RUNTIME_SYSCALL_MAIN_DISPATCH_SEND                  1017
#define RUNTIME_SYSCALL_SLAVE_SET_BLOCK                     1018
#define RUNTIME_SYSCALL_GET_SLAVE_BLOCK                     1019
#define RUNTIME_SYSCALL_SLAVE_SET_BLOCK_EXT                 1020
#define RUNTIME_SYSCALL_GET_SLAVE_BLOCK_EXT                 1021
#define RUNTIME_SYSCALL_SHAREDCOPY_UTM                      1022
#define RUNTIME_SYSCALL_SHAREDWRITE_UTM                     1023
#define RUNTIME_SYSCALL_SEC_ACQUIRE                         1024
#define RUNTIME_SYSCALL_SEC_RELEASE                         1025
#define RUNTIME_SYSCALL_SEC_QUERY                           1026
#define RUNTIME_SYSCALL_TEST_CORRUPT_ATTESTATION_KEY        1027
#define RUNTIME_SYSCALL_TEST_SET_ATTESTATION_MUTATION       1028
#define RUNTIME_SYSCALL_GROUP_PRIVATE_REGION_INFO           1029
#define RUNTIME_SYSCALL_YIELD                               1034
#define RUNTIME_SYSCALL_YXSTM_QUERY_LAYOUT                  1035
#define RUNTIME_SYSCALL_YXSTM_ACQUIRE_SLICE                 1036
#define RUNTIME_SYSCALL_YXSTM_RELEASE_SLICE                 1037
#define RUNTIME_SYSCALL_YXSTM_ACQUIRE_MASK                  1038
#define RUNTIME_SYSCALL_YXSTM_RELEASE_MASK                  1039
#define RUNTIME_SYSCALL_YXSTM_QUERY_PROTOCOL                1040
#define RUNTIME_SYSCALL_YXSTM_PHASE_TRANSITION              1041
#define RUNTIME_SYSCALL_YXSTM_PHASE_ACK                     1042
#define RUNTIME_SYSCALL_YXSTM_REGISTER_MAILBOX               1043
#define RUNTIME_SYSCALL_YXSTM_TASK_BANK_TRANSITION           1044
#define RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACQUIRE              1045
#define RUNTIME_SYSCALL_YXSTM_TASK_BANK_RELEASE              1046
#define RUNTIME_SYSCALL_YXSTM_TASK_BANK_ACK                  1047
#define RUNTIME_SYSCALL_GROUP_LANE_TURN                      1048
#define RUNTIME_SYSCALL_YXSTM_QUERY_SLOT                     1049
#define RUNTIME_SYSCALL_YXSTM_SLOT_COMMAND                   1050
#define RUNTIME_SYSCALL_UTM_QUERY_DIRECT                     1051

#define KEYSTONE_UTM_DIRECT_ABI_VERSION UINT64_C(1)
#define KEYSTONE_UTM_DIRECT_CONTROL_BYTES UINT64_C(4096)
#define KEYSTONE_UTM_DIRECT_FLAG_READ  (UINT64_C(1) << 0)
#define KEYSTONE_UTM_DIRECT_FLAG_WRITE (UINT64_C(1) << 1)
#define KEYSTONE_UTM_DIRECT_FLAG_NX    (UINT64_C(1) << 2)
#define KEYSTONE_UTM_DIRECT_DATA_MARKER "keystone-utm-direct-data-v1"

struct keystone_utm_direct_info {
  uint64_t abi_version;
  uint64_t struct_size;
  uint64_t data_va;
  uint64_t data_size;
  uint64_t data_utm_offset;
  uint64_t flags;
};

#if defined(__cplusplus)
static_assert(sizeof(struct keystone_utm_direct_info) == 48,
              "keystone_utm_direct_info ABI size");
#else
_Static_assert(sizeof(struct keystone_utm_direct_info) == 48,
               "keystone_utm_direct_info ABI size");
#endif

#define RUNTIME_SYSCALL_EXIT                1101

#endif  // __EYRIE_CALL_H__
