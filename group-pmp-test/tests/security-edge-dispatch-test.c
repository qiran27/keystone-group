#include "../security/security-aead.h"
#include "edge_call.h"
#include <assert.h>
#include <stdio.h>

_Static_assert(SECURITY_AEAD_OCALL < MAX_EDGE_CALL, "AEAD dispatch slot out of range");
static unsigned calls;
static void handler(void* buffer) {
  struct edge_call* call = buffer;
  assert(call->call_id == SECURITY_AEAD_OCALL);
  ++calls;
  call->return_data.call_status = CALL_STATUS_OK;
}
int main(void) {
  struct edge_call call = {0};
  assert(register_call(17, handler) == -1);
  assert(register_call(SECURITY_AEAD_OCALL, handler) == 0);
  call.call_id = SECURITY_AEAD_OCALL;
  incoming_call_dispatch(&call);
  assert(calls == 1 && call.return_data.call_status == CALL_STATUS_OK);
  call.call_id = 17;
  incoming_call_dispatch(&call);
  assert(calls == 1 && call.return_data.call_status == CALL_STATUS_BAD_CALL_ID);
  puts("Security AEAD real SDK dispatch PASS: old slot rejected, new slot dispatched");
  return 0;
}
