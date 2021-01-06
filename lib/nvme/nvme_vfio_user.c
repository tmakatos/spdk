/*-
 *   BSD LICENSE
 *
 *   Copyright (c) Intel Corporation. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* VFIO transport extensions for spdk_nvme_ctrlr */

#include "spdk/stdinc.h"
#include "spdk/env.h"
#include "spdk/likely.h"
#include "spdk/string.h"
#include "spdk/vfio_user_pci.h"
#include "nvme_internal.h"

#include <linux/vfio.h>
#include <vfio-user/vfio-user.h>
#include "vfio-user/libvfio-user.h"
#include <stddef.h>

#define NVME_MIN_COMPLETIONS	(1)
#define NVME_MAX_COMPLETIONS	(128)

#define NVME_MAX_SGL_DESCRIPTORS	(250)
#define NVME_MAX_PRP_LIST_ENTRIES	(503)

#define NVME_MAX_IO_QUEUES		(256)

#define NVME_MAX_XFER_SIZE		(131072)
#define NVME_MAX_SGES			(1)

struct nvme_vfio_poll_group {
	struct spdk_nvme_transport_poll_group group;
};

struct nvme_vfio_ctrlr {
	volatile uint32_t *doorbell_base;
	struct spdk_nvme_ctrlr ctrlr;
	struct vfio_device *dev;
	uint32_t doorbell_stride_u32;
	int bar0_fd;
};

/* VFIO transport extensions for spdk_nvme_qpair */
struct nvme_vfio_qpair {
	/* Submission queue tail doorbell */
	volatile uint32_t *sq_tdbl;

	/* Completion queue head doorbell */
	volatile uint32_t *cq_hdbl;

	/* Submission queue */
	struct spdk_nvme_cmd *cmd;

	/* Completion queue */
	struct spdk_nvme_cpl *cpl;

	TAILQ_HEAD(, nvme_tracker) free_tr;
	TAILQ_HEAD(nvme_outstanding_tr_head, nvme_tracker) outstanding_tr;

	/* Array of trackers indexed by command ID. */
	struct nvme_tracker *tr;

	uint16_t num_entries;

	uint8_t retry_count;

	uint16_t max_completions_cap;

	uint16_t last_sq_tail;
	uint16_t sq_tail;
	uint16_t cq_head;
	uint16_t sq_head;

	struct {
		uint8_t phase			: 1;
		uint8_t delay_cmd_submit	: 1;
		uint8_t has_shadow_doorbell	: 1;
	} flags;

	/*
	 * Base qpair structure.
	 * This is located after the hot data in this structure so that the important parts of
	 * nvme_pcie_qpair are in the same cache line.
	 */
	struct spdk_nvme_qpair qpair;

	uint64_t cmd_bus_addr;
	uint64_t cpl_bus_addr;
};

struct nvme_tracker {
	TAILQ_ENTRY(nvme_tracker)       tq_list;

	struct nvme_request		*req;
	uint16_t			cid;

	uint16_t			rsvd0;
	uint32_t			rsvd1;

	spdk_nvme_cmd_cb		cb_fn;
	void				*cb_arg;

	uint64_t			prp_sgl_bus_addr;

	/* Don't move, metadata SGL is always contiguous with Data Block SGL */
	struct spdk_nvme_sgl_descriptor		meta_sgl;
	union {
		uint64_t			prp[NVME_MAX_PRP_LIST_ENTRIES];
		struct spdk_nvme_sgl_descriptor	sgl[NVME_MAX_SGL_DESCRIPTORS];
	} u;
};
/*
 * struct nvme_tracker must be exactly 4K so that the prp[] array does not cross a page boundary
 * and so that there is no padding required to meet alignment requirements.
 */
SPDK_STATIC_ASSERT(sizeof(struct nvme_tracker) == 4096, "nvme_tracker is not 4K");
SPDK_STATIC_ASSERT((offsetof(struct nvme_tracker, u.sgl) & 7) == 0, "SGL must be Qword aligned");
SPDK_STATIC_ASSERT((offsetof(struct nvme_tracker, meta_sgl) & 7) == 0, "SGL must be Qword aligned");

static inline uint64_t
vfio_vtophys(void *vaddr)
{
	return (uint64_t)(uintptr_t)vaddr;
}

struct nvme_vfio_ctrlr *
nvme_vfio_ctrlr(struct spdk_nvme_ctrlr *ctrlr)
{
	return SPDK_CONTAINEROF(ctrlr, struct nvme_vfio_ctrlr, ctrlr);
}

static inline struct nvme_vfio_qpair *
nvme_vfio_qpair(struct spdk_nvme_qpair *qpair)
{
	return SPDK_CONTAINEROF(qpair, struct nvme_vfio_qpair, qpair);
}

static int
nvme_vfio_ctrlr_set_reg_4(struct spdk_nvme_ctrlr *ctrlr, uint64_t offset, uint32_t value)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);
	int region = vfu_get_region(offset, 4, &offset);

	/* FIXME re-enable assert but only for BAR0 */
#if 0
	assert(offset <= sizeof(struct spdk_nvme_registers) - 4);
#endif
	SPDK_DEBUGLOG(nvme_vfio, "ctrlr %s: region %d, offset %#lx, value %#x\n",
	              ctrlr->trid.traddr, region, offset, value);

	return spdk_vfio_user_pci_bar_access(vctrlr->dev, region,
					     offset, 4, &value, true);
}

static int
nvme_vfio_ctrlr_set_reg_8(struct spdk_nvme_ctrlr *ctrlr, uint64_t offset, uint64_t value)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);

	assert(offset <= sizeof(struct spdk_nvme_registers) - 8);
	SPDK_DEBUGLOG(nvme_vfio, "ctrlr %s: offset 0x%lx, value 0x%"PRIx64"\n",
	              ctrlr->trid.traddr, offset, value);

	return spdk_vfio_user_pci_bar_access(vctrlr->dev, VFIO_PCI_BAR0_REGION_INDEX,
					     offset, 8, &value, true);
}

static int
nvme_vfio_ctrlr_get_reg_4(struct spdk_nvme_ctrlr *ctrlr, uint64_t offset, uint32_t *value)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);
	int ret;
	int region = vfu_get_region(offset, 4, &offset);

	/* FIXME re-enable assert but only for BAR0 */
#if 0
	assert(offset <= sizeof(struct spdk_nvme_registers) - 4);
#endif

	ret = spdk_vfio_user_pci_bar_access(vctrlr->dev, region, offset,
	                                    4, value, false);
	if (ret != 0) {
		SPDK_ERRLOG("ctrlr %p, region %d, offset %lx\n", ctrlr, region,
		            offset);
		return ret;
	}

	SPDK_DEBUGLOG(nvme_vfio, "ctrlr %s: offset %#lx, value %#x\n",
	              ctrlr->trid.traddr, offset, *value);

	return 0;
}

static int
nvme_vfio_ctrlr_get_reg_8(struct spdk_nvme_ctrlr *ctrlr, uint64_t offset, uint64_t *value)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);
	int ret;

	assert(offset <= sizeof(struct spdk_nvme_registers) - 8);

	ret = spdk_vfio_user_pci_bar_access(vctrlr->dev, VFIO_PCI_BAR0_REGION_INDEX,
					    offset, 8, value, false);
	if (ret != 0) {
		SPDK_ERRLOG("ctrlr %p, offset %lx\n", ctrlr, offset);
		return ret;
	}

	SPDK_DEBUGLOG(nvme_vfio, "ctrlr %s: offset %#lx, value 0x%"PRIx64"\n",
	              ctrlr->trid.traddr, offset, *value);

	return 0;
}

static int
nvme_vfio_ctrlr_set_asq(struct nvme_vfio_ctrlr *vctrlr, uint64_t value)
{
	return nvme_vfio_ctrlr_set_reg_8(&vctrlr->ctrlr, offsetof(struct spdk_nvme_registers, asq),
					 value);
}

static int
nvme_vfio_ctrlr_set_acq(struct nvme_vfio_ctrlr *vctrlr, uint64_t value)
{
	return nvme_vfio_ctrlr_set_reg_8(&vctrlr->ctrlr, offsetof(struct spdk_nvme_registers, acq),
					 value);
}

static int
nvme_vfio_ctrlr_set_aqa(struct nvme_vfio_ctrlr *vctrlr, const union spdk_nvme_aqa_register *aqa)
{
	return nvme_vfio_ctrlr_set_reg_4(&vctrlr->ctrlr, offsetof(struct spdk_nvme_registers, aqa.raw),
					 aqa->raw);
}

static int
nvme_vfio_qpair_reset(struct spdk_nvme_qpair *qpair)
{
	struct nvme_vfio_qpair *vqpair = nvme_vfio_qpair(qpair);
	uint32_t i;

	/* all head/tail vals are set to 0 */
	vqpair->last_sq_tail = vqpair->sq_tail = vqpair->sq_head = vqpair->cq_head = 0;

	/*
	 * First time through the completion queue, HW will set phase
	 *  bit on completions to 1.  So set this to 1 here, indicating
	 *  we're looking for a 1 to know which entries have completed.
	 *  we'll toggle the bit each time when the completion queue
	 *  rolls over.
	 */
	vqpair->flags.phase = 1;
	for (i = 0; i < vqpair->num_entries; i++) {
		vqpair->cpl[i].status.p = 0;
	}

	return 0;
}

static void
nvme_qpair_construct_tracker(struct nvme_tracker *tr, uint16_t cid, uint64_t phys_addr)
{
	tr->prp_sgl_bus_addr = phys_addr + offsetof(struct nvme_tracker, u.prp);
	tr->cid = cid;
	tr->req = NULL;
}

static int
nvme_vfio_qpair_construct(struct spdk_nvme_qpair *qpair,
			  const struct spdk_nvme_io_qpair_opts *opts)
{
	struct spdk_nvme_ctrlr	*ctrlr = qpair->ctrlr;
	struct nvme_vfio_ctrlr	*vctrlr = nvme_vfio_ctrlr(ctrlr);
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);
	struct nvme_tracker	*tr;
	uint16_t		i;
	volatile uint32_t	*doorbell_base;
	uint16_t		num_trackers;
	size_t			page_align = VALUE_2MB;
	uint32_t                flags = SPDK_MALLOC_DMA;

	vqpair->retry_count = ctrlr->opts.transport_retry_count;

	/*
	 * Limit the maximum number of completions to return per call to prevent wraparound,
	 * and calculate how many trackers can be submitted at once without overflowing the
	 * completion queue.
	 */
	vqpair->max_completions_cap = vqpair->num_entries / 4;
	vqpair->max_completions_cap = spdk_max(vqpair->max_completions_cap, NVME_MIN_COMPLETIONS);
	vqpair->max_completions_cap = spdk_min(vqpair->max_completions_cap, NVME_MAX_COMPLETIONS);
	num_trackers = vqpair->num_entries - vqpair->max_completions_cap;

	SPDK_INFOLOG(nvme_vfio, "max_completions_cap = %" PRIu16 " num_trackers = %" PRIu16 "\n",
		     vqpair->max_completions_cap, num_trackers);

	assert(num_trackers != 0);

	if (nvme_qpair_is_admin_queue(&vqpair->qpair)) {
		flags |= SPDK_MALLOC_SHARE;
	}

	/* To ensure physical address contiguity we make each ring occupy
	 * a single hugepage only. See MAX_IO_QUEUE_ENTRIES.
	 */
	vqpair->cmd = spdk_zmalloc(vqpair->num_entries * sizeof(struct spdk_nvme_cmd),
				   page_align, NULL,
				   SPDK_ENV_SOCKET_ID_ANY, flags);
	if (vqpair->cmd == NULL) {
		SPDK_ERRLOG("alloc qpair_cmd failed\n");
		return -ENOMEM;
	}
	vqpair->cmd_bus_addr = vfio_vtophys(vqpair->cmd);

	vqpair->cpl = spdk_zmalloc(vqpair->num_entries * sizeof(struct spdk_nvme_cpl),
				   page_align, NULL,
				   SPDK_ENV_SOCKET_ID_ANY, flags);
	if (vqpair->cpl == NULL) {
		SPDK_ERRLOG("alloc qpair_cpl failed\n");
		return -ENOMEM;
	}

	vqpair->cpl_bus_addr = vfio_vtophys(vqpair->cpl);

	doorbell_base = vctrlr->doorbell_base;
	vqpair->sq_tdbl = doorbell_base + (2 * qpair->id + 0) * vctrlr->doorbell_stride_u32;
	vqpair->cq_hdbl = doorbell_base + (2 * qpair->id + 1) * vctrlr->doorbell_stride_u32;

	/*
	 * Reserve space for all of the trackers in a single allocation.
	 *   struct nvme_tracker must be padded so that its size is already a power of 2.
	 *   This ensures the PRP list embedded in the nvme_tracker object will not span a
	 *   4KB boundary, while allowing access to trackers in tr[] via normal array indexing.
	 */
	vqpair->tr = spdk_zmalloc(num_trackers * sizeof(*tr), sizeof(*tr), NULL,
				  SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (vqpair->tr == NULL) {
		SPDK_ERRLOG("nvme_tr failed\n");
		return -ENOMEM;
	}

	TAILQ_INIT(&vqpair->free_tr);
	TAILQ_INIT(&vqpair->outstanding_tr);

	for (i = 0; i < num_trackers; i++) {
		tr = &vqpair->tr[i];
		nvme_qpair_construct_tracker(tr, i, vfio_vtophys(tr));
		TAILQ_INSERT_HEAD(&vqpair->free_tr, tr, tq_list);
	}

	SPDK_DEBUGLOG(nvme_vfio, "QID %u, SQ vaddr %p, paddr 0x%"PRIx64", CQ vaddr %p, paddr 0x%"PRIx64"\n",
		      qpair->id, vqpair->cmd, vqpair->cmd_bus_addr, vqpair->cpl, vqpair->cpl_bus_addr);

	nvme_vfio_qpair_reset(qpair);

	return 0;
}

static int
nvme_vfio_ctrlr_construct_admin_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t num_entries)
{
	struct nvme_vfio_qpair *vqpair;
	int rc;

	vqpair = spdk_zmalloc(sizeof(*vqpair), 64, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (vqpair == NULL) {
		return -ENOMEM;
	}

	vqpair->num_entries = num_entries;
	vqpair->flags.delay_cmd_submit = 0;

	ctrlr->adminq = &vqpair->qpair;

	rc = nvme_qpair_init(ctrlr->adminq,
			     0, /* qpair ID */
			     ctrlr,
			     SPDK_NVME_QPRIO_URGENT,
			     num_entries);
	if (rc != 0) {
		return rc;
	}

	return nvme_vfio_qpair_construct(ctrlr->adminq, NULL);
}

/* TODO: remove this function after enable SPARSE MMAP */
static int
nvme_vfio_setup_bar0(struct nvme_vfio_ctrlr *vctrlr, const char *path)
{
	volatile uint32_t *doorbell;
	int fd;

	fd = open(path, O_RDWR);
	if (fd < 0) {
		SPDK_ERRLOG("Failed to open file %s\n", path);
		return fd;
	}

	doorbell = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x1000);
	if (doorbell == MAP_FAILED) {
		SPDK_ERRLOG("Failed to mmap file %s\n", path);
		close(fd);
		return -EFAULT;
	}

	vctrlr->bar0_fd = fd;
	vctrlr->doorbell_base = doorbell;

	return 0;
}

static void
nvme_vfio_bar0_destruct(struct nvme_vfio_ctrlr *vctrlr)
{
	if (vctrlr->doorbell_base) {
		munmap((void *)vctrlr->doorbell_base, 0x1000);
	}

	close(vctrlr->bar0_fd);
}

static struct spdk_nvme_ctrlr *
	nvme_vfio_ctrlr_construct(const struct spdk_nvme_transport_id *trid,
			  const struct spdk_nvme_ctrlr_opts *opts,
			  void *devhandle)
{
	struct nvme_vfio_ctrlr *vctrlr;
	uint16_t cmd_reg;
	union spdk_nvme_cap_register cap;
	union spdk_nvme_vs_register vs;
	int ret;
	char ctrlr_path[PATH_MAX];
	char ctrlr_bar0[PATH_MAX];

	snprintf(ctrlr_path, sizeof(ctrlr_path), "%s/cntrl", trid->traddr);
	snprintf(ctrlr_bar0, sizeof(ctrlr_bar0), "%s/bar0", trid->traddr);

	ret = access(ctrlr_path, F_OK);
	if (ret != 0) {
		SPDK_ERRLOG("Access path %s failed\n", ctrlr_path);
		return NULL;
	}

	ret = access(ctrlr_bar0, F_OK);
	if (ret != 0) {
		SPDK_ERRLOG("Access path %s failed\n", ctrlr_bar0);
		return NULL;
	}

	vctrlr = calloc(1, sizeof(*vctrlr));
	if (!vctrlr) {
		return NULL;
	}

	ret = nvme_vfio_setup_bar0(vctrlr, ctrlr_bar0);
	if (ret != 0) {
		free(vctrlr);
		return NULL;
	}

	vctrlr->dev = spdk_vfio_user_setup(ctrlr_path);
	if (!vctrlr->dev) {
		SPDK_ERRLOG("Error to setup vfio device\n");
		nvme_vfio_bar0_destruct(vctrlr);
		free(vctrlr);
		return NULL;
	}

	vctrlr->ctrlr.is_removed = false;
	vctrlr->ctrlr.opts = *opts;
	vctrlr->ctrlr.trid = *trid;

	ret = nvme_ctrlr_construct(&vctrlr->ctrlr);
	if (ret != 0) {
		goto exit;
	}

	/* Enable PCI busmaster and disable INTx */
	ret = spdk_vfio_user_pci_bar_access(vctrlr->dev, VFIO_PCI_CONFIG_REGION_INDEX, 4, 2,
					    &cmd_reg, false);
	if (ret != 0) {
		SPDK_ERRLOG("Read PCI CMD REG failed\n");
		goto exit;
	}
	cmd_reg |= 0x404;
	ret = spdk_vfio_user_pci_bar_access(vctrlr->dev, VFIO_PCI_CONFIG_REGION_INDEX, 4, 2,
					    &cmd_reg, true);
	if (ret != 0) {
		SPDK_ERRLOG("Write PCI CMD REG failed\n");
		goto exit;
	}

	if (nvme_ctrlr_get_cap(&vctrlr->ctrlr, &cap)) {
		SPDK_ERRLOG("get_cap() failed\n");
		goto exit;
	}

	if (nvme_ctrlr_get_vs(&vctrlr->ctrlr, &vs)) {
		SPDK_ERRLOG("get_vs() failed\n");
		goto exit;
	}

	nvme_ctrlr_init_cap(&vctrlr->ctrlr, &cap, &vs);
	vctrlr->doorbell_stride_u32 = 1 << cap.bits.dstrd;

	ret = nvme_vfio_ctrlr_construct_admin_qpair(&vctrlr->ctrlr, vctrlr->ctrlr.opts.admin_queue_size);
	if (ret != 0) {
		nvme_ctrlr_destruct(&vctrlr->ctrlr);
		goto exit;
	}

	/* Construct the primary process properties */
	ret = nvme_ctrlr_add_process(&vctrlr->ctrlr, 0);
	if (ret != 0) {
		nvme_ctrlr_destruct(&vctrlr->ctrlr);
		goto exit;
	}

	return &vctrlr->ctrlr;

exit:
	nvme_vfio_bar0_destruct(vctrlr);
	spdk_vfio_user_release(vctrlr->dev);
	free(vctrlr);
	return NULL;
}

static int
nvme_vfio_ctrlr_scan(struct spdk_nvme_probe_ctx *probe_ctx,
		     bool direct_connect)
{
	int ret;

	if (probe_ctx->trid.trtype != SPDK_NVME_TRANSPORT_CUSTOM) {
		SPDK_ERRLOG("Can only use SPDK_NVME_TRANSPORT_CUSTOM");
		return -EINVAL;
	}

	ret = access(probe_ctx->trid.traddr, F_OK);
	if (ret != 0) {
		SPDK_ERRLOG("Error to access file %s\n", probe_ctx->trid.traddr);
		return ret;
	}
	SPDK_NOTICELOG("Scan controller : %s\n", probe_ctx->trid.traddr);

	return nvme_ctrlr_probe(&probe_ctx->trid, probe_ctx, NULL);
}

static int
nvme_vfio_ctrlr_enable(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);
	struct nvme_vfio_qpair *vadminq = nvme_vfio_qpair(ctrlr->adminq);
	union spdk_nvme_aqa_register aqa;

	if (nvme_vfio_ctrlr_set_asq(vctrlr, vadminq->cmd_bus_addr)) {
		SPDK_ERRLOG("set_asq() failed\n");
		return -EIO;
	}

	if (nvme_vfio_ctrlr_set_acq(vctrlr, vadminq->cpl_bus_addr)) {
		SPDK_ERRLOG("set_acq() failed\n");
		return -EIO;
	}

	aqa.raw = 0;
	/* acqs and asqs are 0-based. */
	aqa.bits.acqs = nvme_vfio_qpair(ctrlr->adminq)->num_entries - 1;
	aqa.bits.asqs = nvme_vfio_qpair(ctrlr->adminq)->num_entries - 1;

	if (nvme_vfio_ctrlr_set_aqa(vctrlr, &aqa)) {
		SPDK_ERRLOG("set_aqa() failed\n");
		return -EIO;
	}

	return 0;
}

static int
nvme_vfio_qpair_destroy(struct spdk_nvme_qpair *qpair);

static int
nvme_vfio_ctrlr_destruct(struct spdk_nvme_ctrlr *ctrlr)
{
	struct nvme_vfio_ctrlr *vctrlr = nvme_vfio_ctrlr(ctrlr);

	if (ctrlr->adminq) {
		nvme_vfio_qpair_destroy(ctrlr->adminq);
	}

	nvme_ctrlr_destruct_finish(ctrlr);

	nvme_ctrlr_free_processes(ctrlr);

	nvme_vfio_bar0_destruct(vctrlr);
	spdk_vfio_user_release(vctrlr->dev);
	free(vctrlr);

	return 0;
}

static  uint32_t
nvme_vfio_ctrlr_get_max_xfer_size(struct spdk_nvme_ctrlr *ctrlr)
{
	return NVME_MAX_XFER_SIZE;
}

static uint16_t
nvme_vfio_ctrlr_get_max_sges(struct spdk_nvme_ctrlr *ctrlr)
{
	return NVME_MAX_SGES;
}

static int
nvme_vfio_ctrlr_cmd_create_io_cq(struct spdk_nvme_ctrlr *ctrlr,
				 struct spdk_nvme_qpair *io_que, spdk_nvme_cmd_cb cb_fn,
				 void *cb_arg)
{
	struct nvme_vfio_qpair *vqpair = nvme_vfio_qpair(io_que);
	struct nvme_request *req;
	struct spdk_nvme_cmd *cmd;

	req = nvme_allocate_request_null(ctrlr->adminq, cb_fn, cb_arg);
	if (req == NULL) {
		return -ENOMEM;
	}

	cmd = &req->cmd;
	cmd->opc = SPDK_NVME_OPC_CREATE_IO_CQ;

	cmd->cdw10_bits.create_io_q.qid = io_que->id;
	cmd->cdw10_bits.create_io_q.qsize = vqpair->num_entries - 1;

	cmd->cdw11_bits.create_io_cq.pc = 1;
	cmd->dptr.prp.prp1 = vqpair->cpl_bus_addr;

	return nvme_ctrlr_submit_admin_request(ctrlr, req);
}

static int
nvme_vfio_ctrlr_cmd_create_io_sq(struct spdk_nvme_ctrlr *ctrlr,
				 struct spdk_nvme_qpair *io_que, spdk_nvme_cmd_cb cb_fn, void *cb_arg)
{
	struct nvme_vfio_qpair *vqpair = nvme_vfio_qpair(io_que);
	struct nvme_request *req;
	struct spdk_nvme_cmd *cmd;

	req = nvme_allocate_request_null(ctrlr->adminq, cb_fn, cb_arg);
	if (req == NULL) {
		return -ENOMEM;
	}

	cmd = &req->cmd;
	cmd->opc = SPDK_NVME_OPC_CREATE_IO_SQ;

	cmd->cdw10_bits.create_io_q.qid = io_que->id;
	cmd->cdw10_bits.create_io_q.qsize = vqpair->num_entries - 1;
	cmd->cdw11_bits.create_io_sq.pc = 1;
	cmd->cdw11_bits.create_io_sq.qprio = io_que->qprio;
	cmd->cdw11_bits.create_io_sq.cqid = io_que->id;
	cmd->dptr.prp.prp1 = vqpair->cmd_bus_addr;

	return nvme_ctrlr_submit_admin_request(ctrlr, req);
}

static int
nvme_vfio_ctrlr_cmd_delete_io_cq(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair,
				 spdk_nvme_cmd_cb cb_fn, void *cb_arg)
{
	struct nvme_request *req;
	struct spdk_nvme_cmd *cmd;

	req = nvme_allocate_request_null(ctrlr->adminq, cb_fn, cb_arg);
	if (req == NULL) {
		return -ENOMEM;
	}

	cmd = &req->cmd;
	cmd->opc = SPDK_NVME_OPC_DELETE_IO_CQ;
	cmd->cdw10_bits.delete_io_q.qid = qpair->id;

	return nvme_ctrlr_submit_admin_request(ctrlr, req);
}

static int
nvme_vfio_ctrlr_cmd_delete_io_sq(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair,
				 spdk_nvme_cmd_cb cb_fn, void *cb_arg)
{
	struct nvme_request *req;
	struct spdk_nvme_cmd *cmd;

	req = nvme_allocate_request_null(ctrlr->adminq, cb_fn, cb_arg);
	if (req == NULL) {
		return -ENOMEM;
	}

	cmd = &req->cmd;
	cmd->opc = SPDK_NVME_OPC_DELETE_IO_SQ;
	cmd->cdw10_bits.delete_io_q.qid = qpair->id;

	return nvme_ctrlr_submit_admin_request(ctrlr, req);
}

static int
_nvme_vfio_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair,
				 uint16_t qid)
{
	struct nvme_completion_poll_status	*status;
	int					rc;

	status = calloc(1, sizeof(*status));
	if (!status) {
		SPDK_ERRLOG("Failed to allocate status tracker\n");
		return -ENOMEM;
	}

	rc = nvme_vfio_ctrlr_cmd_create_io_cq(ctrlr, qpair, nvme_completion_poll_cb, status);
	if (rc != 0) {
		free(status);
		return rc;
	}

	if (nvme_wait_for_completion(ctrlr->adminq, status)) {
		SPDK_ERRLOG("nvme_create_io_cq failed!\n");
		if (!status->timed_out) {
			free(status);
		}
		return -1;
	}

	memset(status, 0, sizeof(*status));
	rc = nvme_vfio_ctrlr_cmd_create_io_sq(qpair->ctrlr, qpair, nvme_completion_poll_cb, status);
	if (rc != 0) {
		free(status);
		return rc;
	}

	if (nvme_wait_for_completion(ctrlr->adminq, status)) {
		SPDK_ERRLOG("nvme_create_io_sq failed!\n");
		if (status->timed_out) {
			/* Request is still queued, the memory will be freed in a completion callback.
			   allocate a new request */
			status = calloc(1, sizeof(*status));
			if (!status) {
				SPDK_ERRLOG("Failed to allocate status tracker\n");
				return -ENOMEM;
			}
		}

		memset(status, 0, sizeof(*status));
		/* Attempt to delete the completion queue */
		rc = nvme_vfio_ctrlr_cmd_delete_io_cq(qpair->ctrlr, qpair, nvme_completion_poll_cb, status);
		if (rc != 0) {
			/* The originall or newly allocated status structure can be freed since
			 * the corresponding request has been completed of failed to submit */
			free(status);
			return -1;
		}
		nvme_wait_for_completion(ctrlr->adminq, status);
		if (!status->timed_out) {
			/* status can be freed regardless of nvme_wait_for_completion return value */
			free(status);
		}
		return -1;
	}

	nvme_vfio_qpair_reset(qpair);
	free(status);

	return 0;
}

static struct spdk_nvme_qpair *
nvme_vfio_ctrlr_create_io_qpair(struct spdk_nvme_ctrlr *ctrlr, uint16_t qid,
				const struct spdk_nvme_io_qpair_opts *opts)
{
	struct nvme_vfio_qpair *vqpair;
	struct spdk_nvme_qpair *qpair;
	int rc;

	assert(ctrlr != NULL);

	vqpair = spdk_zmalloc(sizeof(*vqpair), 64, NULL,
			      SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_SHARE);
	if (vqpair == NULL) {
		return NULL;
	}

	vqpair->num_entries = opts->io_queue_size;
	vqpair->flags.delay_cmd_submit = opts->delay_cmd_submit;

	qpair = &vqpair->qpair;

	rc = nvme_qpair_init(qpair, qid, ctrlr, opts->qprio, opts->io_queue_requests);
	if (rc != 0) {
		nvme_vfio_qpair_destroy(qpair);
		return NULL;
	}

	rc = nvme_vfio_qpair_construct(qpair, opts);

	if (rc != 0) {
		nvme_vfio_qpair_destroy(qpair);
		return NULL;
	}

	return qpair;
}

static int
nvme_vfio_ctrlr_connect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	if (nvme_qpair_is_admin_queue(qpair)) {
		return 0;
	} else {
		return _nvme_vfio_ctrlr_create_io_qpair(ctrlr, qpair, qpair->id);
	}
}

static void
nvme_vfio_ctrlr_disconnect_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
}

static void
nvme_vfio_qpair_abort_trackers(struct spdk_nvme_qpair *qpair, uint32_t dnr);

static int
nvme_vfio_ctrlr_delete_io_qpair(struct spdk_nvme_ctrlr *ctrlr, struct spdk_nvme_qpair *qpair)
{
	struct nvme_completion_poll_status *status;
	int rc;

	assert(ctrlr != NULL);

	if (ctrlr->is_removed) {
		goto free;
	}

	status = calloc(1, sizeof(*status));
	if (!status) {
		SPDK_ERRLOG("Failed to allocate status tracker\n");
		return -ENOMEM;
	}

	/* Delete the I/O submission queue */
	rc = nvme_vfio_ctrlr_cmd_delete_io_sq(ctrlr, qpair, nvme_completion_poll_cb, status);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to send request to delete_io_sq with rc=%d\n", rc);
		free(status);
		return rc;
	}
	if (nvme_wait_for_completion(ctrlr->adminq, status)) {
		if (!status->timed_out) {
			free(status);
		}
		return -1;
	}

	memset(status, 0, sizeof(*status));
	/* Delete the completion queue */
	rc = nvme_vfio_ctrlr_cmd_delete_io_cq(ctrlr, qpair, nvme_completion_poll_cb, status);
	if (rc != 0) {
		SPDK_ERRLOG("Failed to send request to delete_io_cq with rc=%d\n", rc);
		free(status);
		return rc;
	}
	if (nvme_wait_for_completion(ctrlr->adminq, status)) {
		if (!status->timed_out) {
			free(status);
		}
		return -1;
	}
	free(status);

free:
	if (qpair->no_deletion_notification_needed == 0) {
		/* Abort the rest of the I/O */
		nvme_vfio_qpair_abort_trackers(qpair, 1);
	}

	nvme_vfio_qpair_destroy(qpair);
	return 0;
}

static struct spdk_nvme_transport_poll_group *
nvme_vfio_poll_group_create(void)
{
	struct nvme_vfio_poll_group *group = calloc(1, sizeof(*group));

	if (group == NULL) {
		SPDK_ERRLOG("Unable to allocate poll group.\n");
		return NULL;
	}

	return &group->group;
}

static int
nvme_vfio_poll_group_connect_qpair(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int
nvme_vfio_poll_group_disconnect_qpair(struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int
nvme_vfio_poll_group_add(struct spdk_nvme_transport_poll_group *tgroup,
			 struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int
nvme_vfio_poll_group_remove(struct spdk_nvme_transport_poll_group *tgroup,
			    struct spdk_nvme_qpair *qpair)
{
	return 0;
}

static int64_t
nvme_vfio_poll_group_process_completions(struct spdk_nvme_transport_poll_group *tgroup,
		uint32_t completions_per_qpair, spdk_nvme_disconnected_qpair_cb disconnected_qpair_cb)
{
	struct spdk_nvme_qpair *qpair, *tmp_qpair;
	int32_t local_completions = 0;
	int64_t total_completions = 0;

	STAILQ_FOREACH_SAFE(qpair, &tgroup->disconnected_qpairs, poll_group_stailq, tmp_qpair) {
		disconnected_qpair_cb(qpair, tgroup->group->ctx);
	}

	STAILQ_FOREACH_SAFE(qpair, &tgroup->connected_qpairs, poll_group_stailq, tmp_qpair) {
		local_completions = spdk_nvme_qpair_process_completions(qpair, completions_per_qpair);
		if (local_completions < 0) {
			disconnected_qpair_cb(qpair, tgroup->group->ctx);
			local_completions = 0;
		}
		total_completions += local_completions;
	}

	return total_completions;
}

static int
nvme_vfio_poll_group_destroy(struct spdk_nvme_transport_poll_group *tgroup)
{
	if (!STAILQ_EMPTY(&tgroup->connected_qpairs) || !STAILQ_EMPTY(&tgroup->disconnected_qpairs)) {
		return -EBUSY;
	}

	free(tgroup);

	return 0;
}

static inline void
nvme_vfio_qpair_ring_sq_doorbell(struct spdk_nvme_qpair *qpair)
{
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);

	if (qpair->first_fused_submitted) {
		/* This is first cmd of two fused commands - don't ring doorbell */
		qpair->first_fused_submitted = 0;
		return;
	}

	spdk_wmb();
	spdk_mmio_write_4(vqpair->sq_tdbl, vqpair->sq_tail);
}

static inline void
nvme_vfio_qpair_ring_cq_doorbell(struct spdk_nvme_qpair *qpair)
{
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);

	spdk_mmio_write_4(vqpair->cq_hdbl, vqpair->cq_head);
}

static void
nvme_vfio_qpair_submit_tracker(struct spdk_nvme_qpair *qpair, struct nvme_tracker *tr)
{
	struct nvme_request	*req;
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);

	req = tr->req;
	assert(req != NULL);

	if (req->cmd.fuse == SPDK_NVME_IO_FLAGS_FUSE_FIRST) {
		/* This is first cmd of two fused commands - don't ring doorbell */
		qpair->first_fused_submitted = 1;
	}

	vqpair->cmd[vqpair->sq_tail] = req->cmd;

	if (spdk_unlikely(++vqpair->sq_tail == vqpair->num_entries)) {
		vqpair->sq_tail = 0;
	}

	if (spdk_unlikely(vqpair->sq_tail == vqpair->sq_head)) {
		SPDK_ERRLOG("sq_tail is passing sq_head!\n");
	}

	nvme_vfio_qpair_ring_sq_doorbell(qpair);
}

static void
nvme_vfio_qpair_insert_pending_admin_request(struct spdk_nvme_qpair *qpair,
		struct nvme_request *req, struct spdk_nvme_cpl *cpl)
{
	struct spdk_nvme_ctrlr		*ctrlr = qpair->ctrlr;
	struct nvme_request		*active_req = req;
	struct spdk_nvme_ctrlr_process	*active_proc;

	/*
	 * The admin request is from another process. Move to the per
	 *  process list for that process to handle it later.
	 */
	assert(nvme_qpair_is_admin_queue(qpair));
	assert(active_req->pid != getpid());

	active_proc = nvme_ctrlr_get_process(ctrlr, active_req->pid);
	if (active_proc) {
		/* Save the original completion information */
		memcpy(&active_req->cpl, cpl, sizeof(*cpl));
		STAILQ_INSERT_TAIL(&active_proc->active_reqs, active_req, stailq);
	} else {
		SPDK_ERRLOG("The owning process (pid %d) is not found. Dropping the request.\n",
			    active_req->pid);

		nvme_free_request(active_req);
	}
}

static void
nvme_vfio_qpair_complete_tracker(struct spdk_nvme_qpair *qpair, struct nvme_tracker *tr,
				 struct spdk_nvme_cpl *cpl, bool print_on_error)
{
	struct nvme_vfio_qpair		*vqpair = nvme_vfio_qpair(qpair);
	struct nvme_request		*req;
	bool				retry, error;
	bool				req_from_current_proc = true;

	req = tr->req;

	assert(req != NULL);

	error = spdk_nvme_cpl_is_error(cpl);
	retry = error && nvme_completion_is_retry(cpl) &&
		req->retries < vqpair->retry_count;

	if (error && print_on_error && !qpair->ctrlr->opts.disable_error_logging) {
		spdk_nvme_qpair_print_command(qpair, &req->cmd);
		spdk_nvme_qpair_print_completion(qpair, cpl);
	}

	assert(cpl->cid == req->cmd.cid);

	if (retry) {
		req->retries++;
		nvme_vfio_qpair_submit_tracker(qpair, tr);
	} else {
		/* Only check admin requests from different processes. */
		if (nvme_qpair_is_admin_queue(qpair) && req->pid != getpid()) {
			req_from_current_proc = false;
			nvme_vfio_qpair_insert_pending_admin_request(qpair, req, cpl);
		} else {
			nvme_complete_request(tr->cb_fn, tr->cb_arg, qpair, req, cpl);
		}

		if (req_from_current_proc == true) {
			nvme_qpair_free_request(qpair, req);
		}

		tr->req = NULL;

		TAILQ_REMOVE(&vqpair->outstanding_tr, tr, tq_list);
		TAILQ_INSERT_HEAD(&vqpair->free_tr, tr, tq_list);
	}
}

static void
nvme_vfio_qpair_manual_complete_tracker(struct spdk_nvme_qpair *qpair,
					struct nvme_tracker *tr, uint32_t sct, uint32_t sc, uint32_t dnr,
					bool print_on_error)
{
	struct spdk_nvme_cpl	cpl;

	memset(&cpl, 0, sizeof(cpl));
	cpl.sqid = qpair->id;
	cpl.cid = tr->cid;
	cpl.status.sct = sct;
	cpl.status.sc = sc;
	cpl.status.dnr = dnr;
	nvme_vfio_qpair_complete_tracker(qpair, tr, &cpl, print_on_error);
}

static void
nvme_vfio_qpair_abort_trackers(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
	struct nvme_vfio_qpair *pqpair = nvme_vfio_qpair(qpair);
	struct nvme_tracker *tr, *temp, *last;

	last = TAILQ_LAST(&pqpair->outstanding_tr, nvme_outstanding_tr_head);

	/* Abort previously submitted (outstanding) trs */
	TAILQ_FOREACH_SAFE(tr, &pqpair->outstanding_tr, tq_list, temp) {
		if (!qpair->ctrlr->opts.disable_error_logging) {
			SPDK_ERRLOG("aborting outstanding command\n");
		}
		nvme_vfio_qpair_manual_complete_tracker(qpair, tr, SPDK_NVME_SCT_GENERIC,
							SPDK_NVME_SC_ABORTED_BY_REQUEST, dnr, true);

		if (tr == last) {
			break;
		}
	}
}

static void
nvme_vfio_qpair_abort_reqs(struct spdk_nvme_qpair *qpair, uint32_t dnr)
{
	nvme_vfio_qpair_abort_trackers(qpair, dnr);
}

static void
nvme_vfio_admin_qpair_abort_aers(struct spdk_nvme_qpair *qpair)
{
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);
	struct nvme_tracker	*tr;

	tr = TAILQ_FIRST(&vqpair->outstanding_tr);
	while (tr != NULL) {
		assert(tr->req != NULL);
		if (tr->req->cmd.opc == SPDK_NVME_OPC_ASYNC_EVENT_REQUEST) {
			nvme_vfio_qpair_manual_complete_tracker(qpair, tr,
								SPDK_NVME_SCT_GENERIC, SPDK_NVME_SC_ABORTED_SQ_DELETION, 0,
								false);
			tr = TAILQ_FIRST(&vqpair->outstanding_tr);
		} else {
			tr = TAILQ_NEXT(tr, tq_list);
		}
	}
}

static void
nvme_vfio_admin_qpair_destroy(struct spdk_nvme_qpair *qpair)
{
	nvme_vfio_admin_qpair_abort_aers(qpair);
}

static int
nvme_vfio_qpair_destroy(struct spdk_nvme_qpair *qpair)
{
	struct nvme_vfio_qpair *vqpair = nvme_vfio_qpair(qpair);

	if (nvme_qpair_is_admin_queue(qpair)) {
		nvme_vfio_admin_qpair_destroy(qpair);
	}

	spdk_free(vqpair->cmd);
	spdk_free(vqpair->cpl);

	if (vqpair->tr) {
		spdk_free(vqpair->tr);
	}

	nvme_qpair_deinit(qpair);

	spdk_free(vqpair);

	return 0;
}

static inline int
nvme_vfio_prp_list_append(struct nvme_tracker *tr, uint32_t *prp_index, void *virt_addr, size_t len,
			  uint32_t page_size)
{
	struct spdk_nvme_cmd *cmd = &tr->req->cmd;
	uintptr_t page_mask = page_size - 1;
	uint64_t phys_addr;
	uint32_t i;

	SPDK_DEBUGLOG(nvme_vfio, "prp_index:%u virt_addr:%p len:%u\n",
		      *prp_index, virt_addr, (uint32_t)len);

	if (spdk_unlikely(((uintptr_t)virt_addr & 3) != 0)) {
		SPDK_ERRLOG("virt_addr %p not dword aligned\n", virt_addr);
		return -EFAULT;
	}

	i = *prp_index;
	while (len) {
		uint32_t seg_len;

		/*
		 * prp_index 0 is stored in prp1, and the rest are stored in the prp[] array,
		 * so prp_index == count is valid.
		 */
		if (spdk_unlikely(i > SPDK_COUNTOF(tr->u.prp))) {
			SPDK_ERRLOG("out of PRP entries\n");
			return -EFAULT;
		}

		phys_addr = vfio_vtophys(virt_addr);

		if (i == 0) {
			SPDK_DEBUGLOG(nvme_vfio, "prp1 = %p\n", (void *)phys_addr);
			cmd->dptr.prp.prp1 = phys_addr;
			seg_len = page_size - ((uintptr_t)virt_addr & page_mask);
		} else {
			if ((phys_addr & page_mask) != 0) {
				SPDK_ERRLOG("PRP %u not page aligned (%p)\n", i, virt_addr);
				return -EFAULT;
			}

			SPDK_DEBUGLOG(nvme_vfio, "prp[%u] = %p\n", i - 1, (void *)phys_addr);
			tr->u.prp[i - 1] = phys_addr;
			seg_len = page_size;
		}

		seg_len = spdk_min(seg_len, len);
		virt_addr += seg_len;
		len -= seg_len;
		i++;
	}

	cmd->psdt = SPDK_NVME_PSDT_PRP;
	if (i <= 1) {
		cmd->dptr.prp.prp2 = 0;
	} else if (i == 2) {
		cmd->dptr.prp.prp2 = tr->u.prp[0];
		SPDK_DEBUGLOG(nvme_vfio, "prp2 = %p\n", (void *)cmd->dptr.prp.prp2);
	} else {
		cmd->dptr.prp.prp2 = tr->prp_sgl_bus_addr;
		SPDK_DEBUGLOG(nvme_vfio, "prp2 = %p (PRP list)\n", (void *)cmd->dptr.prp.prp2);
	}

	*prp_index = i;
	return 0;
}

static int
nvme_vfio_qpair_build_contig_request(struct spdk_nvme_qpair *qpair, struct nvme_request *req,
				     struct nvme_tracker *tr, bool dword_aligned)
{
	uint32_t prp_index = 0;
	int rc;

	rc = nvme_vfio_prp_list_append(tr, &prp_index, req->payload.contig_or_cb_arg + req->payload_offset,
				       req->payload_size, qpair->ctrlr->page_size);
	if (rc) {
		nvme_vfio_qpair_manual_complete_tracker(qpair, tr, SPDK_NVME_SCT_GENERIC,
							SPDK_NVME_SC_INVALID_FIELD,
							1 /* do not retry */, true);
	}

	return rc;
}

static int
nvme_vfio_qpair_submit_request(struct spdk_nvme_qpair *qpair, struct nvme_request *req)
{
	struct nvme_tracker	*tr;
	int			rc = 0;
	struct spdk_nvme_ctrlr	*ctrlr = qpair->ctrlr;
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);

	if (spdk_unlikely(nvme_qpair_is_admin_queue(qpair))) {
		nvme_robust_mutex_lock(&ctrlr->ctrlr_lock);
	}

	tr = TAILQ_FIRST(&vqpair->free_tr);

	if (tr == NULL) {
		/* Inform the upper layer to try again later. */
		rc = -EAGAIN;
		goto exit;
	}

	TAILQ_REMOVE(&vqpair->free_tr, tr, tq_list); /* remove tr from free_tr */
	TAILQ_INSERT_TAIL(&vqpair->outstanding_tr, tr, tq_list);
	tr->req = req;
	tr->cb_fn = req->cb_fn;
	tr->cb_arg = req->cb_arg;
	req->cmd.cid = tr->cid;

	if (req->payload_size != 0) {
		rc = nvme_vfio_qpair_build_contig_request(qpair, req, tr, true);
		if (rc) {
			goto exit;
		}
	}

	nvme_vfio_qpair_submit_tracker(qpair, tr);

exit:
	if (spdk_unlikely(nvme_qpair_is_admin_queue(qpair))) {
		nvme_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	}

	return rc;
}

static void
nvme_vfio_qpair_complete_pending_admin_request(struct spdk_nvme_qpair *qpair)
{
	struct spdk_nvme_ctrlr		*ctrlr = qpair->ctrlr;
	struct nvme_request		*req, *tmp_req;
	pid_t				pid = getpid();
	struct spdk_nvme_ctrlr_process	*proc;

	/*
	 * Check whether there is any pending admin request from
	 * other active processes.
	 */
	assert(nvme_qpair_is_admin_queue(qpair));

	proc = nvme_ctrlr_get_current_process(ctrlr);
	if (!proc) {
		SPDK_ERRLOG("the active process (pid %d) is not found for this controller.\n", pid);
		assert(proc);
		return;
	}

	STAILQ_FOREACH_SAFE(req, &proc->active_reqs, stailq, tmp_req) {
		STAILQ_REMOVE(&proc->active_reqs, req, nvme_request, stailq);

		assert(req->pid == pid);

		nvme_complete_request(req->cb_fn, req->cb_arg, qpair, req, &req->cpl);
		nvme_free_request(req);
	}
}

static int32_t
nvme_vfio_qpair_process_completions(struct spdk_nvme_qpair *qpair, uint32_t max_completions)
{
	struct nvme_vfio_qpair	*vqpair = nvme_vfio_qpair(qpair);
	struct nvme_tracker	*tr;
	struct spdk_nvme_cpl	*cpl, *next_cpl;
	uint32_t		 num_completions = 0;
	struct spdk_nvme_ctrlr	*ctrlr = qpair->ctrlr;
	uint16_t		 next_cq_head;
	uint8_t			 next_phase;
	bool			 next_is_valid = false;

	if (spdk_unlikely(nvme_qpair_is_admin_queue(qpair))) {
		nvme_robust_mutex_lock(&ctrlr->ctrlr_lock);
	}

	if (max_completions == 0 || max_completions > vqpair->max_completions_cap) {
		/*
		 * max_completions == 0 means unlimited, but complete at most
		 * max_completions_cap batch of I/O at a time so that the completion
		 * queue doorbells don't wrap around.
		 */
		max_completions = vqpair->max_completions_cap;
	}

	while (1) {
		cpl = &vqpair->cpl[vqpair->cq_head];

		if (!next_is_valid && cpl->status.p != vqpair->flags.phase) {
			break;
		}

		if (spdk_likely(vqpair->cq_head + 1 != vqpair->num_entries)) {
			next_cq_head = vqpair->cq_head + 1;
			next_phase = vqpair->flags.phase;
		} else {
			next_cq_head = 0;
			next_phase = !vqpair->flags.phase;
		}
		next_cpl = &vqpair->cpl[next_cq_head];
		next_is_valid = (next_cpl->status.p == next_phase);
		if (next_is_valid) {
			__builtin_prefetch(&vqpair->tr[next_cpl->cid]);
		}

		if (spdk_unlikely(++vqpair->cq_head == vqpair->num_entries)) {
			vqpair->cq_head = 0;
			vqpair->flags.phase = !vqpair->flags.phase;
		}

		tr = &vqpair->tr[cpl->cid];
		/* Prefetch the req's STAILQ_ENTRY since we'll need to access it
		 * as part of putting the req back on the qpair's free list.
		 */
		__builtin_prefetch(&tr->req->stailq);
		vqpair->sq_head = cpl->sqhd;

		if (tr->req) {
			nvme_vfio_qpair_complete_tracker(qpair, tr, cpl, true);
		} else {
			SPDK_ERRLOG("cpl does not map to outstanding cmd\n");
			spdk_nvme_qpair_print_completion(qpair, cpl);
			assert(0);
		}

		if (++num_completions == max_completions) {
			break;
		}
	}

	if (num_completions > 0) {
		nvme_vfio_qpair_ring_cq_doorbell(qpair);
	}

	if (vqpair->flags.delay_cmd_submit) {
		if (vqpair->last_sq_tail != vqpair->sq_tail) {
			nvme_vfio_qpair_ring_sq_doorbell(qpair);
			vqpair->last_sq_tail = vqpair->sq_tail;
		}
	}

	/* Before returning, complete any pending admin request. */
	if (spdk_unlikely(nvme_qpair_is_admin_queue(qpair))) {
		nvme_vfio_qpair_complete_pending_admin_request(qpair);

		nvme_robust_mutex_unlock(&ctrlr->ctrlr_lock);
	}

	return num_completions;
}

int
nvme_vfio_ctrlr_get_migration_region(struct spdk_nvme_ctrlr *ctrlr)
{
	return spdk_vfio_user_get_migration_region(nvme_vfio_ctrlr(ctrlr)->dev);
}

const struct spdk_nvme_transport_ops vfio_ops = {
	.name = "CUSTOM",
	.type = SPDK_NVME_TRANSPORT_CUSTOM,
	.ctrlr_construct = nvme_vfio_ctrlr_construct,
	.ctrlr_scan = nvme_vfio_ctrlr_scan,
	.ctrlr_destruct = nvme_vfio_ctrlr_destruct,
	.ctrlr_enable = nvme_vfio_ctrlr_enable,

	.ctrlr_set_reg_4 = nvme_vfio_ctrlr_set_reg_4,
	.ctrlr_set_reg_8 = nvme_vfio_ctrlr_set_reg_8,
	.ctrlr_get_reg_4 = nvme_vfio_ctrlr_get_reg_4,
	.ctrlr_get_reg_8 = nvme_vfio_ctrlr_get_reg_8,

	.ctrlr_get_max_xfer_size = nvme_vfio_ctrlr_get_max_xfer_size,
	.ctrlr_get_max_sges = nvme_vfio_ctrlr_get_max_sges,

	.ctrlr_create_io_qpair = nvme_vfio_ctrlr_create_io_qpair,
	.ctrlr_delete_io_qpair = nvme_vfio_ctrlr_delete_io_qpair,
	.ctrlr_connect_qpair = nvme_vfio_ctrlr_connect_qpair,
	.ctrlr_disconnect_qpair = nvme_vfio_ctrlr_disconnect_qpair,
	.admin_qpair_abort_aers = nvme_vfio_admin_qpair_abort_aers,

	.qpair_reset = nvme_vfio_qpair_reset,
	.qpair_abort_reqs = nvme_vfio_qpair_abort_reqs,
	.qpair_submit_request = nvme_vfio_qpair_submit_request,
	.qpair_process_completions = nvme_vfio_qpair_process_completions,

	.poll_group_create = nvme_vfio_poll_group_create,
	.poll_group_connect_qpair = nvme_vfio_poll_group_connect_qpair,
	.poll_group_disconnect_qpair = nvme_vfio_poll_group_disconnect_qpair,
	.poll_group_add = nvme_vfio_poll_group_add,
	.poll_group_remove = nvme_vfio_poll_group_remove,
	.poll_group_process_completions = nvme_vfio_poll_group_process_completions,
	.poll_group_destroy = nvme_vfio_poll_group_destroy,
};

SPDK_NVME_TRANSPORT_REGISTER(vfio, &vfio_ops);

SPDK_LOG_REGISTER_COMPONENT(nvme_vfio)
