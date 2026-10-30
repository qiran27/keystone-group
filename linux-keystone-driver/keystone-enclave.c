//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <linux/dma-mapping.h>
#include <linux/string.h>
#include "keystone.h"
#include <linux/export.h>
#include "security-evidence-ranges.h"
/* idr for enclave UID to struct enclave */
DEFINE_IDR(idr_enclave);
DEFINE_MUTEX(idr_enclave_lock);

#define ENCLAVE_IDR_MIN 0x1000
#define ENCLAVE_IDR_MAX 0xffff

extern spinlock_t YXSTM_spinlock;

struct GLOBAL_YXSTM global_yxstm;
struct GLOBAL_EPM_GROUPS global_epm_groups;
static DEFINE_MUTEX(YXSTM_GROUP_mutex);

/* Optional observation module receives only live group metadata, never EPM/TSR
 * contents. SM per-task grants remain evidenced by the independent access tests. */
int keystone_security_protected_ranges(struct ke_range *out, unsigned int capacity)
{
  unsigned int count = 0;
  int i, j, result = 0;
  if (!out || capacity < KEYSTONE_MAX_ENABLED_GROUPS * (KEYSTONE_GROUP_MAX_REGIONS + 1))
    return -ENOSPC;
  mutex_lock(&EPM_GROUP_mutex);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; ++i) {
    struct EPM_GROUP_SLOT *slot = &global_epm_groups.slots[i];
    if (!slot->engine_id) continue;
    if (slot->pool.size)
      out[count++] = (struct ke_range){slot->pool.pa, slot->pool.size, slot->engine_id,
        slot->permission_epoch, KEYSTONE_GROUP_REGION_PRIVATE_EPM,
        KEYSTONE_GROUP_REGION_PERM_R | KEYSTONE_GROUP_REGION_PERM_W | KEYSTONE_GROUP_REGION_PERM_X};
    for (j = 0; j < KEYSTONE_GROUP_MAX_REGIONS; ++j) {
      const struct keystone_group_region_descriptor *r = &slot->region_table[j];
      if (!r->valid || !r->size ||
          (r->type != KEYSTONE_GROUP_REGION_PRIVATE_EPM &&
           r->type != KEYSTONE_GROUP_REGION_SHARED)) continue;
      out[count++] = (struct ke_range){r->paddr, r->size, slot->engine_id,
        slot->permission_epoch, r->type, r->permissions};
    }
  }
  result = count;
  mutex_unlock(&EPM_GROUP_mutex);
  return result;
}
EXPORT_SYMBOL_GPL(keystone_security_protected_ranges);

static const char* group_region_type_name(enum keystone_group_region_type type)
{
  switch (type) {
  case KEYSTONE_GROUP_REGION_PRIVATE_EPM:
    return "private_epm";
  case KEYSTONE_GROUP_REGION_SHARED:
    return "shared";
  case KEYSTONE_GROUP_REGION_METADATA:
    return "metadata";
  case KEYSTONE_GROUP_REGION_CHANNEL:
    return "channel";
  case KEYSTONE_GROUP_REGION_UTM:
    return "utm";
  case KEYSTONE_GROUP_REGION_SHARED_UTM:
    return "shared_utm";
  case KEYSTONE_GROUP_REGION_SEC:
    return "sec";
  default:
    return "invalid";
  }
}

static int group_context_upsert_region(unsigned long long group_id,
                                       enum keystone_group_region_type type,
                                       paddr_t paddr,
                                       size_t size,
                                       unsigned long long permissions,
                                       struct keystone_group_region_descriptor* out)
{
  int i;
  int j;
  int free_region = -1;
  int ret = -ENOENT;

  if (!group_id || !size)
    return -EINVAL;

  mutex_lock(&EPM_GROUP_mutex);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct EPM_GROUP_SLOT* slot = &global_epm_groups.slots[i];

    if (slot->engine_id != group_id)
      continue;

    for (j = 0; j < KEYSTONE_GROUP_MAX_REGIONS; j++) {
      struct keystone_group_region_descriptor* region =
        &slot->region_table[j];

      if (region->valid &&
          region->type == type &&
          region->paddr == paddr &&
          region->size == size) {
        if (region->permissions != permissions) {
          region->permissions = permissions;
          slot->permission_epoch++;
        }
        if (out)
          *out = *region;
        ret = 0;
        goto out;
      }

      if (!region->valid && free_region < 0)
        free_region = j;
    }

    if (free_region < 0) {
      ret = -ENOSPC;
      goto out;
    }

    if (!slot->next_region_id)
      slot->next_region_id = 1;

    slot->region_table[free_region].valid = true;
    slot->region_table[free_region].region_id = slot->next_region_id++;
    slot->region_table[free_region].type = type;
    slot->region_table[free_region].paddr = paddr;
    slot->region_table[free_region].size = size;
    slot->region_table[free_region].owner_group = group_id;
    slot->region_table[free_region].permissions = permissions;
    slot->region_count++;
    slot->permission_epoch++;
    keystone_info("group region registered: group=%llu region=%llu type=%s pa=0x%lx size=0x%lx perms=0x%llx epoch=%llu count=%llu\n",
                  group_id,
                  slot->region_table[free_region].region_id,
                  group_region_type_name(type),
                  (unsigned long)paddr,
                  (unsigned long)size,
                  permissions,
                  slot->permission_epoch,
                  slot->region_count);

    if (out)
      *out = slot->region_table[free_region];

    ret = 0;
    goto out;
  }

out:
  mutex_unlock(&EPM_GROUP_mutex);
  return ret;
}

static void group_context_remove_region(unsigned long long group_id,
                                        enum keystone_group_region_type type,
                                        paddr_t paddr,
                                        size_t size)
{
  int i;
  int j;

  if (!group_id)
    return;

  mutex_lock(&EPM_GROUP_mutex);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    struct EPM_GROUP_SLOT* slot = &global_epm_groups.slots[i];

    if (slot->engine_id != group_id)
      continue;

    for (j = 0; j < KEYSTONE_GROUP_MAX_REGIONS; j++) {
      if (slot->region_table[j].valid &&
          slot->region_table[j].type == type &&
          slot->region_table[j].paddr == paddr &&
          slot->region_table[j].size == size) {
        memset(&slot->region_table[j], 0, sizeof(slot->region_table[j]));
        if (slot->region_count > 0)
          slot->region_count--;
        slot->permission_epoch++;
        keystone_info("group region removed: group=%llu type=%s pa=0x%lx size=0x%lx epoch=%llu count=%llu\n",
                      group_id,
                      group_region_type_name(type),
                      (unsigned long)paddr,
                      (unsigned long)size,
                      slot->permission_epoch,
                      slot->region_count);
        break;
      }
    }
    break;
  }
  mutex_unlock(&EPM_GROUP_mutex);
}

static void yxstm_copy_desc(struct YXSTM* dst, struct YXSTM* src)
{
  dst->order = src->order;
  dst->ptr = src->ptr;
  dst->root_page_table = src->root_page_table;
  dst->size = src->size;
  dst->is_cma = src->is_cma;
  dst->pa = src->pa;
  dst->cma_ptr = src->cma_ptr;
  dst->cma_pa = src->cma_pa;
  dst->cma_size = src->cma_size;
  dst->bank_slice_size = src->bank_slice_size;
  dst->bank_count = src->bank_count;
}

int yxstm_group_get(unsigned long long engine_id, size_t size,
                    size_t bank_slice_size, unsigned long bank_count,
                    struct YXSTM* out)
{
  int i;
  int free_slot = -1;
  int ret = 0;
  struct keystone_group_region_descriptor region_desc;

  if (!engine_id || !size || !bank_slice_size || !bank_count ||
      bank_count > KEYSTONE_YXSTM_MAX_BANKS ||
      bank_slice_size > SIZE_MAX / KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT /
                            bank_count ||
      bank_slice_size * KEYSTONE_YXSTM_DEFAULT_SLICE_COUNT * bank_count !=
          size || !out)
    return -EINVAL;

  memset(&region_desc, 0, sizeof(region_desc));

  mutex_lock(&YXSTM_GROUP_mutex);

  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (global_yxstm.slots[i].engine_id == engine_id) {
      if (global_yxstm.slots[i].yxstm.size != size ||
          global_yxstm.slots[i].yxstm.bank_slice_size != bank_slice_size ||
          global_yxstm.slots[i].yxstm.bank_count != bank_count) {
        mutex_unlock(&YXSTM_GROUP_mutex);
        return -EINVAL;
      }
      global_yxstm.slots[i].ref_count++;
      yxstm_copy_desc(out, &global_yxstm.slots[i].yxstm);
      region_desc = global_yxstm.slots[i].region;
      mutex_unlock(&YXSTM_GROUP_mutex);
      ret = group_context_upsert_region(engine_id,
                                        KEYSTONE_GROUP_REGION_SHARED,
                                        region_desc.paddr,
                                        region_desc.size,
                                        region_desc.permissions,
                                        NULL);
      if (ret) {
        yxstm_group_put(engine_id);
        memset(out, 0, sizeof(*out));
        return ret;
      }
      return 0;
    }
    if (!global_yxstm.slots[i].engine_id && free_slot < 0)
      free_slot = i;
  }

  if (free_slot < 0) {
    mutex_unlock(&YXSTM_GROUP_mutex);
    return -ENOSPC;
  }

  ret = YXSTM_init(&global_yxstm.slots[free_slot].yxstm, size);
  if (ret) {
    mutex_unlock(&YXSTM_GROUP_mutex);
    return ret;
  }

  global_yxstm.slots[free_slot].yxstm.bank_slice_size = bank_slice_size;
  global_yxstm.slots[free_slot].yxstm.bank_count = bank_count;

  global_yxstm.slots[free_slot].engine_id = engine_id;
  global_yxstm.slots[free_slot].ref_count = 1;
  global_yxstm.slots[free_slot].region.valid = true;
  global_yxstm.slots[free_slot].region.region_id = 1;
  global_yxstm.slots[free_slot].region.type = KEYSTONE_GROUP_REGION_SHARED;
  global_yxstm.slots[free_slot].region.paddr =
    global_yxstm.slots[free_slot].yxstm.pa;
  global_yxstm.slots[free_slot].region.size =
    global_yxstm.slots[free_slot].yxstm.size;
  global_yxstm.slots[free_slot].region.owner_group = engine_id;
  global_yxstm.slots[free_slot].region.permissions =
    KEYSTONE_GROUP_REGION_PERM_R | KEYSTONE_GROUP_REGION_PERM_W;
  region_desc = global_yxstm.slots[free_slot].region;
  yxstm_copy_desc(out, &global_yxstm.slots[free_slot].yxstm);

  mutex_unlock(&YXSTM_GROUP_mutex);
  ret = group_context_upsert_region(engine_id,
                                    KEYSTONE_GROUP_REGION_SHARED,
                                    region_desc.paddr,
                                    region_desc.size,
                                    region_desc.permissions,
                                    &region_desc);
  if (ret) {
    yxstm_group_put(engine_id);
    memset(out, 0, sizeof(*out));
    return ret;
  }
  return 0;
}

int yxstm_group_put(unsigned long long engine_id)
{
  int i;
  bool remove_shared_region = false;
  struct keystone_group_region_descriptor region_desc;

  if (!engine_id)
    return 0;

  memset(&region_desc, 0, sizeof(region_desc));

  mutex_lock(&YXSTM_GROUP_mutex);
  for (i = 0; i < KEYSTONE_MAX_ENABLED_GROUPS; i++) {
    if (global_yxstm.slots[i].engine_id != engine_id)
      continue;

    if (global_yxstm.slots[i].ref_count > 0)
      global_yxstm.slots[i].ref_count--;

    if (global_yxstm.slots[i].ref_count == 0) {
      region_desc = global_yxstm.slots[i].region;
      YXSTM_destroy(&global_yxstm.slots[i].yxstm);
      memset(&global_yxstm.slots[i], 0, sizeof(global_yxstm.slots[i]));
      remove_shared_region = true;
    }
    mutex_unlock(&YXSTM_GROUP_mutex);
    if (remove_shared_region)
      group_context_remove_region(engine_id,
                                  KEYSTONE_GROUP_REGION_SHARED,
                                  region_desc.paddr,
                                  region_desc.size);
    return 0;
  }
  mutex_unlock(&YXSTM_GROUP_mutex);
  return -ENOENT;
}

/* Smart destroy, handles partial initialization of epm and utm etc */
int destroy_enclave(struct enclave* enclave)
{
  struct epm* epm;
  struct utm* utm;
  struct utm* shared_utm;
  struct YXSTM* YXSTM;
  if (enclave == NULL)
    return -ENOSYS;

  epm = enclave->epm;
  utm = enclave->utm;
  shared_utm = enclave->shared_utm;
  YXSTM = enclave->YXSTM;

  if (enclave->eid == (unsigned long)-1) {
    keystone_info("destroy_enclave: eid=unassigned, epm=%p, utm=%p, shared_utm=%p\n",
                  epm, utm, shared_utm);
  } else {
    keystone_info("destroy_enclave: eid=%lu, epm=%p, utm=%p, shared_utm=%p\n",
                  enclave->eid, epm, utm, shared_utm);
  }

  if (YXSTM) {
    yxstm_group_put(enclave->yxstm_group_id);
    kfree(YXSTM);
    enclave->YXSTM = NULL;
  }

  if (epm)
  {
    epm_destroy(epm);
    kfree(epm);
  }

  /* Handle shared UTM: decrement reference count */
  if (shared_utm) {
    int old_ref_count = atomic_read(&shared_utm->ref_count);
    int new_ref_count = atomic_dec_return(&shared_utm->ref_count);
    keystone_info("Shared UTM ref_count: %d -> %d (enclave was sharing from owner_eid=%lu)\n",
                  old_ref_count, new_ref_count, enclave->owner_eid);
    enclave->shared_utm = NULL;
    enclave->owner_eid = 0;
  }

  /* Handle own UTM: check reference count before destroying */
  if (utm)
  {
    int ref_count = atomic_read(&utm->ref_count);
    keystone_info("Own UTM ref_count=%d (1=safe to destroy, >1=still shared)\n", ref_count);
    
    if (ref_count > 1) {
      /* Other enclaves are still using this UTM */
      keystone_err("Cannot destroy UTM: %d enclave(s) still sharing it\n", ref_count - 1);
      /* We still destroy the enclave but leave the UTM intact */
      /* The UTM will be destroyed when the last reference is released */
      keystone_warn("UTM not destroyed, waiting for all sharers to release\n");
    } else {
      /* No other enclaves using this UTM, safe to destroy */
      keystone_info("UTM ref_count=1, safe to destroy UTM\n");
      utm_destroy(utm);
      kfree(utm);
    }
  }

  kfree(enclave);
  return 0;
}

struct enclave* create_enclave(unsigned long min_pages, unsigned long long ms, unsigned long long engine_id)
{
  struct enclave* enclave;

  enclave = kzalloc(sizeof(struct enclave), GFP_KERNEL);
  if (!enclave){
    keystone_err("failed to allocate enclave struct\n");
    goto error_no_free;
  }

  enclave->eid = -1;
  enclave->close_on_pexit = 1;

  enclave->epm = kzalloc(sizeof(struct epm), GFP_KERNEL);
  enclave->is_init = true;
  if (!enclave->epm)
  {
    keystone_err("failed to allocate epm\n");
    goto error_destroy_enclave;
  }

  if(ms && engine_id) {
    int ret = epm_group_slice_init(enclave->epm, min_pages, ms, engine_id);
    if(ret) {
      keystone_err("failed to initialize group EPM slice: group=%llu capacity=%llu min_pages=%lu ret=%d\n",
                   engine_id, ms, min_pages, ret);
      goto error_destroy_enclave;
    }
    enclave->ms = ms;
    enclave->engine_id = engine_id;
  } else if(epm_init(enclave->epm, min_pages)) {
    keystone_err("failed to initialize epm\n");
    goto error_destroy_enclave;
  }
  return enclave;

 error_destroy_enclave:
  destroy_enclave(enclave);
 error_no_free:
  return NULL;
}

unsigned int enclave_idr_alloc(struct enclave* enclave)
{
  unsigned int ueid;

  mutex_lock(&idr_enclave_lock);
  ueid = idr_alloc(&idr_enclave, enclave, ENCLAVE_IDR_MIN, ENCLAVE_IDR_MAX, GFP_KERNEL);
  mutex_unlock(&idr_enclave_lock);

  if (ueid < ENCLAVE_IDR_MIN || ueid >= ENCLAVE_IDR_MAX) {
    keystone_err("failed to allocate UID\n");
    return 0;
  }

  return ueid;
}

struct enclave* enclave_idr_remove(unsigned int ueid)
{
  struct enclave* enclave;
  mutex_lock(&idr_enclave_lock);
  enclave = idr_remove(&idr_enclave, ueid);
  mutex_unlock(&idr_enclave_lock);
  return enclave;
}

struct enclave* get_enclave_by_id(unsigned int ueid)
{
  struct enclave* enclave;
  mutex_lock(&idr_enclave_lock);
  enclave = idr_find(&idr_enclave, ueid);
  mutex_unlock(&idr_enclave_lock);
  return enclave;
}

unsigned int enclave_idr_find_by_sm_eid(unsigned long sm_eid)
{
  struct enclave* enclave;
  int ueid = 0;
  unsigned int found = 0;

  mutex_lock(&idr_enclave_lock);
  idr_for_each_entry(&idr_enclave, enclave, ueid) {
    if (enclave && enclave->eid == sm_eid) {
      found = (unsigned int)ueid;
      break;
    }
  }
  mutex_unlock(&idr_enclave_lock);
  return found;
}
