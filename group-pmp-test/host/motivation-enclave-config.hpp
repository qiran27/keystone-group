/* Included inside the runner namespace, after add_instance is available. */
static const char motivation_epm_reservation_marker[] __attribute__((used)) =
    "keystone-motivation-epm-reservation-v2";

static void add_motivation_instances(std::vector<EnclaveInstance>& enclaves,unsigned workers=1,bool active_master=false) {
  const char* names[] = {"motivation-inactive-owner", "motivation-worker-1", "motivation-worker-2", "motivation-worker-3"};
  // The first image sizes the group's future EPM reservation. Match both images
  // and Params for both the legacy owner and the active task Master.
  for (unsigned i=0;i<=workers;++i)
    add_instance(enclaves,i==0 && active_master?"motivation-task-master":names[i],"group-pmp-motivation-worker.eapp_riscv",kDefaultGroupId,workers+1,
        kYxstmSize,MOT_UTM_BYTES,kYxstmSize/KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT,
        UINT64_C(4)*1024*1024);
}
