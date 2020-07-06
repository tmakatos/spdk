/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2019, Nutanix Inc. All rights reserved.
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

#include <muser/muser.h>
#include <muser/caps/pm.h>
#include <muser/caps/px.h>
#include <muser/caps/msix.h>

#include "spdk/barrier.h"
#include "spdk/stdinc.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvmf_transport.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "transport.h"

#include "nvmf_internal.h"

#include "spdk_internal/log.h"

struct nvme_pcie_mlbar {
	uint32_t rte :	1;
	uint32_t tp :	2;
	uint32_t pf :	1;
	uint32_t res1 :	10;
	uint32_t ba :	18;
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_pcie_mlbar) == sizeof(uint32_t), "Invalid size");

struct nvme_pcie_bar2 {
	uint32_t rte :	1;
	uint32_t res1 :	2;
	uint32_t ba :	29;
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_pcie_bar2) == sizeof(uint32_t), "Bad NVMe BAR2 size");

struct spdk_log_flag SPDK_LOG_MUSER = {.enabled = true};

#define PAGE_MASK (~(PAGE_SIZE-1))
#define PAGE_ALIGN(x) ((x + PAGE_SIZE - 1) & PAGE_MASK)

/*
 * Define TRAP_DOORBELLS to disable memory mapping the doorbells and trap instead.
 * This will incur significant performance penalty and is intended for debug
 * purposes.
 */
//#define TRAP_DOORBELLS

#define MUSER_DEFAULT_MAX_QUEUE_DEPTH 256
#define MUSER_DEFAULT_AQ_DEPTH 32
#define MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR 64
#define MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE 0
#define MUSER_DEFAULT_MAX_IO_SIZE 131072
#define MUSER_DEFAULT_IO_UNIT_SIZE 131072
#define MUSER_DEFAULT_NUM_SHARED_BUFFERS 512 /* internal buf size */
#define MUSER_DEFAULT_BUFFER_CACHE_SIZE 0
#define MUSER_DOORBELLS_SIZE PAGE_ALIGN(MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR * sizeof(uint32_t) * 2)
/* TODO: Move to nvmf_internal.h, SPDK NVMf uses fixed 4KiB */
#define NVMF_MEMORY_PAGE_SIZE 4096

#define NVME_REG_CFG_SIZE       0x1000
#define NVME_REG_BAR0_SIZE      0x4000

#define NVME_IRQ_INTX_NUM       1
#define NVME_IRQ_MSI_NUM        2
#define NVME_IRQ_MSIX_NUM       32

#define CC offsetof(struct spdk_nvme_registers, cc)

#define DOORBELLS 0x1000
SPDK_STATIC_ASSERT(DOORBELLS == offsetof(struct spdk_nvme_registers, doorbell[0].sq_tdbl),
		   "Incorrect register offset");

enum muser_nvmf_dir {
	MUSER_NVMF_INVALID,
	MUSER_NVMF_READ,
	MUSER_NVMF_WRITE
};

struct muser_req;
struct muser_qpair;

typedef int (*muser_req_cb_fn)(struct muser_req *req, void *cb_arg);

struct muser_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			rsp;
	struct spdk_nvme_cmd			cmd;
	uint16_t				cid;

	muser_req_cb_fn				cb_fn;
	void					*cb_arg;

	TAILQ_ENTRY(muser_req)			link;
};

struct muser_nvmf_prop_req {
	enum muser_nvmf_dir			dir;
	sem_t					wait;
	/*
	 * TODO either this will be a register access or an internal command
	 * (for now it's only about starting the NVMf subsystem. Convert into a
	 * union.
	 */
	char					*buf;
	size_t					count;
	loff_t					pos;
	ssize_t					ret;
	struct muser_req			muser_req;
};

/*
 * An I/O queue.
 *
 * TODO we use the same struct both for submission and for completion I/O
 * queues because that simplifies queue creation. However we're wasting memory
 * for submission queues, maybe rethink this approach.
 */
struct io_q {
	bool is_cq;

	void *addr;

	dma_sg_t sg;
	struct iovec iov;

	/*
	 * TODO move to parent struct muser_qpair? There's already qsize
	 * there.
	 */
	uint32_t size;

	union {
		struct {
			uint32_t head;
			/* multiple SQs can be mapped to the same CQ */
			uint16_t cqid;
		};
		struct {
			uint32_t tail;
			uint16_t iv;
			bool ien;
		};
	};
};

struct muser_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_transport_poll_group	*group;
	struct muser_ctrlr			*ctrlr;
	struct muser_req			*reqs_internal;
	uint16_t				qsize; /* TODO aren't all queues the same size? */
	struct io_q				cq;
	struct io_q				sq;
	bool					del;

	TAILQ_HEAD(, muser_req)			reqs;
	TAILQ_ENTRY(muser_qpair)		link;
};

struct muser_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	TAILQ_HEAD(, muser_qpair)		qps;
};

struct muser_ctrlr {
	struct muser_endpoint			*endpoint;
	struct muser_transport			*transport;
	char					uuid[SPDK_NVME_NQN_FIELD_SIZE];
	char					*id;
	pthread_t				lm_thr;
	lm_ctx_t				*lm_ctx;
	lm_pci_config_space_t			*pci_config_space;

	/*
	 * TODO variables that are checked by poll_group_poll to see whether
	 * commands need to be executed, in addition to checking the doorbells.
	 * We now have 2 such different commands so we should introduce a queue,
	 * or if we're going to have a single outstanding command we should
	 * group them into a union.
	 */
	sem_t					sem;
	struct muser_nvmf_prop_req		prop_req; /* read/write BAR0 */

	spdk_nvmf_tgt_subsystem_listen_done_fn	cb_fn;
	void					*cb_arg;

	/* PCI capabilities */
	struct pmcap				pmcap;
	struct msixcap				msixcap;
	struct pxcap				pxcap;

	uint16_t				cntlid;

	struct muser_qpair			*qp[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR];

	TAILQ_ENTRY(muser_ctrlr)		link;

	/* even indices are SQ, odd indices are CQ */
	volatile uint32_t			*doorbells;

	/* internal CSTS.CFS register for MUSER fatal errors */
	uint32_t				cfs : 1;

	/* for LM_TRAS_SOCK */
	bool					initialized;
};

struct muser_endpoint {
	lm_ctx_t				*lm_ctx;
	int					fd;
	volatile uint32_t			*doorbells;

	struct spdk_nvme_transport_id		trid;

	/* The current controller. NULL if nothing is
	 * currently attached. */
	struct muser_ctrlr			*ctrlr;

	TAILQ_ENTRY(muser_endpoint)		link;
};

struct muser_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	TAILQ_HEAD(, muser_ctrlr)		ctrlrs;
	TAILQ_HEAD(, muser_endpoint)		endpoints;

	TAILQ_HEAD(, muser_qpair)		new_qps;
};

/*
 * function prototypes
 */
static volatile uint32_t *
hdbl(struct muser_ctrlr *ctrlr, struct io_q *q);

static volatile uint32_t *
tdbl(struct muser_ctrlr *ctrlr, struct io_q *q);

static int
muser_req_free(struct spdk_nvmf_request *req);

static struct muser_req *
get_muser_req(struct muser_qpair *qpair);

static int
post_completion(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
		struct io_q *cq, uint32_t cdw0, uint16_t sc,
		uint16_t sct);

/*
 * XXX We need a way to extract the queue ID from an io_q, which is already
 * available in muser_qpair->qpair.qid. Currently we store the type of the
 * queue within the queue, so retrieving the QID requires a comparison. Rather
 * than duplicating this information in struct io_q, we could store a pointer
 * to parent struct muser_qpair, however we would be using 8 bytes instead of
 * just 2 (uint16_t vs. pointer). This is only per-queue so it's not that bad.
 * Another approach is to define two types: struct io_cq { struct io_q q }; and
 * struct io_sq { struct io_q q; };. The downside would be that we would need
 * two almost identical functions to extract the QID.
 */
static uint16_t
io_q_id(struct io_q *q)
{

	struct muser_qpair *muser_qpair;

	assert(q);

	if (q->is_cq) {
		muser_qpair = SPDK_CONTAINEROF(q, struct muser_qpair, cq);
	} else {
		muser_qpair = SPDK_CONTAINEROF(q, struct muser_qpair, sq);
	}
	assert(muser_qpair);
	return muser_qpair->qpair.qid;
}

static void
fail_ctrlr(struct muser_ctrlr *ctrlr)
{
	assert(ctrlr != NULL);

	SPDK_ERRLOG(":%s failing controller\n", ctrlr->id);

	ctrlr->cfs = 1U;
}

static bool
ctrlr_interrupt_enabled(struct muser_ctrlr *ctrlr)
{
	lm_pci_config_space_t *pci = ctrlr->pci_config_space;

	return (!pci->hdr.cmd.id || ctrlr->msixcap.mxc.mxe);
}

static void
muser_destroy_endpoint(struct muser_endpoint *muser_ep)
{
	assert(muser_ep->ctrlr == NULL);

	if (muser_ep->doorbells) {
#ifdef TRAP_DOORBELLS
		free(muser_ep->doorbells);
#else
		munmap((void *)muser_ep->doorbells, MUSER_DOORBELLS_SIZE);
#endif
	}

	if (muser_ep->fd > 0) {
		close(muser_ep->fd);
	}

	lm_ctx_destroy(muser_ep->lm_ctx);

	free(muser_ep);
}

/* called when process exits */
static int
muser_destroy(struct spdk_nvmf_transport *transport)
{
	struct muser_transport *muser_transport;
	struct muser_endpoint *muser_ep, *tmp;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "destroy transport\n");

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	(void)pthread_mutex_destroy(&muser_transport->lock);

	TAILQ_FOREACH_SAFE(muser_ep, &muser_transport->endpoints, link, tmp) {
		TAILQ_REMOVE(&muser_transport->endpoints, muser_ep, link);
		if (muser_ep->doorbells) {
			munmap((void *)muser_ep->doorbells, MUSER_DOORBELLS_SIZE);
		}

		if (muser_ep->fd != -1) {
			close(muser_ep->fd);
		}

		free(muser_ep);
	}

	free(muser_transport);

	return 0;
}

static struct spdk_nvmf_transport *
muser_create(struct spdk_nvmf_transport_opts *opts)
{
	struct muser_transport *muser_transport;
	int err;

	muser_transport = calloc(1, sizeof(*muser_transport));
	if (muser_transport == NULL) {
		SPDK_ERRLOG("Transport alloc fail: %m\n");
		return NULL;
	}

	err = pthread_mutex_init(&muser_transport->lock, NULL);
	if (err != 0) {
		SPDK_ERRLOG("Pthread initialisation failed (%d)\n", err);
		goto err;
	}

	TAILQ_INIT(&muser_transport->endpoints);
	TAILQ_INIT(&muser_transport->ctrlrs);
	TAILQ_INIT(&muser_transport->new_qps);

	return &muser_transport->transport;

err:
	free(muser_transport);

	return NULL;
}

static int
handle_dbl_access(struct muser_ctrlr *ctrlr, uint32_t *buf,
		  const size_t count, loff_t pos, const bool is_write);

static void
destroy_qp(struct muser_ctrlr *ctrlr, uint16_t qid);

static int
do_prop_req(struct muser_ctrlr *ctrlr, char *buf, size_t count, loff_t pos,
	    bool is_write)
{
	int err;

	assert(ctrlr != NULL);

	err = sem_init(&ctrlr->prop_req.wait, 0, 0);
	if (err != 0) {
		return err;
	}
	ctrlr->prop_req.ret = 0;
	ctrlr->prop_req.buf = buf;
	ctrlr->prop_req.count = count;
	ctrlr->prop_req.pos = pos;
	spdk_wmb();
	ctrlr->prop_req.dir = is_write ? MUSER_NVMF_WRITE : MUSER_NVMF_READ;
	err = sem_wait(&ctrlr->prop_req.wait);
	if (err != 0) {
		return err;
	}
	return ctrlr->prop_req.ret;
}

static uint16_t
max_queue_size(struct muser_ctrlr const *ctrlr)
{
	assert(ctrlr != NULL);
	assert(ctrlr->qp[0] != NULL);
	assert(ctrlr->qp[0]->qpair.ctrlr != NULL);

	return ctrlr->qp[0]->qpair.ctrlr->vcprop.cap.bits.mqes + 1;
}

/* TODO this should be a libmuser public function */
static void *
map_one(void *prv, uint64_t addr, uint64_t len, dma_sg_t *sg, struct iovec *iov)
{
	int ret;
	lm_ctx_t *ctx = (lm_ctx_t *)prv;
	dma_sg_t tmp_sg;
	struct iovec tmp_iov;

	/*
	 * TODO struct muser_ep* == ctx->pvt, but lm_ctx_t is opaque, need
	 * a function to return pvt from lm_ctx_t.
	 */

	ret = lm_addr_to_sg(ctx, addr, len, &tmp_sg, 1);
	if (ret != 1) {
		SPDK_ERRLOG("failed to map 0x%lx-0x%lx\n", addr, addr + len);
		errno = ret;
		return NULL;
	}

	ret = lm_map_sg(ctx, &tmp_sg, &tmp_iov, 1);
	if (ret != 0) {
		SPDK_ERRLOG("failed to map segment: %d\n", ret);
		errno = ret;
		return NULL;
	}

	if (sg) {
		*sg = tmp_sg;
	}

	if (iov) {
		*iov = tmp_iov;
	}

	return tmp_iov.iov_base;
}

static uint32_t
sq_head(struct muser_qpair *qpair)
{
	assert(qpair != NULL);
	return qpair->sq.head;
}

static void
sqhd_advance(struct muser_ctrlr *ctrlr, struct muser_qpair *qpair)
{
	assert(ctrlr != NULL);
	assert(qpair != NULL);
	qpair->sq.head = (qpair->sq.head + 1) % qpair->sq.size;
}

static void
insert_queue(struct muser_ctrlr *ctrlr, struct io_q *q,
	     const bool is_cq, const uint16_t id)
{
	struct io_q *_q;
	struct muser_qpair *qpair;

	assert(ctrlr != NULL);
	assert(q != NULL);

	qpair = ctrlr->qp[id];

	q->is_cq = is_cq;
	if (is_cq) {
		_q = &qpair->cq;
		*_q = *q;
		*hdbl(ctrlr, _q) = 0;
	} else {
		_q = &qpair->sq;
		*_q = *q;
		*tdbl(ctrlr, _q) = 0;
	}
}

static int
asq_map(struct muser_ctrlr *ctrlr)
{
	struct io_q q;
	const struct spdk_nvmf_registers *regs = spdk_nvmf_ctrlr_get_regs(ctrlr->qp[0]->qpair.ctrlr);

	assert(ctrlr != NULL);
	assert(ctrlr->qp[0]->sq.addr == NULL);
	/* XXX ctrlr->asq == 0 is a valid memory address */

	q.size = regs->aqa.bits.asqs + 1;
	q.head = ctrlr->doorbells[0] = 0;
	q.cqid = 0;
	q.addr = map_one(ctrlr->lm_ctx, regs->asq,
			 q.size * sizeof(struct spdk_nvme_cmd), NULL, NULL);
	if (q.addr == NULL) {
		return -1;
	}
	memset(q.addr, 0, q.size * sizeof(struct spdk_nvme_cmd));
	insert_queue(ctrlr, &q, false, 0);
	return 0;
}

static uint16_t
cq_next(struct io_q *q)
{
	assert(q != NULL);
	assert(q->is_cq);
	return (q->tail + 1) % q->size;
}

static int
queue_index(uint16_t qid, int is_cq)
{
	return (qid * 2) + is_cq;
}

static volatile uint32_t *
tdbl(struct muser_ctrlr *ctrlr, struct io_q *q)
{
	assert(ctrlr != NULL);
	assert(q != NULL);
	assert(!q->is_cq);

	return &ctrlr->doorbells[queue_index(io_q_id(q), false)];
}

static volatile uint32_t *
hdbl(struct muser_ctrlr *ctrlr, struct io_q *q)
{
	assert(ctrlr != NULL);
	assert(q != NULL);
	assert(q->is_cq);

	return &ctrlr->doorbells[queue_index(io_q_id(q), true)];
}

static bool
cq_is_full(struct muser_ctrlr *ctrlr, struct io_q *q)
{
	assert(ctrlr != NULL);
	assert(q != NULL);
	return cq_next(q) == *hdbl(ctrlr, q);
}

static void
cq_tail_advance(struct io_q *q)
{
	assert(q != NULL);
	q->tail = cq_next(q);
}

static int
acq_map(struct muser_ctrlr *ctrlr)
{
	struct io_q *q;
	const struct spdk_nvmf_registers *regs = spdk_nvmf_ctrlr_get_regs(ctrlr->qp[0]->qpair.ctrlr);

	assert(ctrlr != NULL);
	assert(ctrlr->qp[0] != NULL);
	assert(ctrlr->qp[0]->cq.addr == NULL);
	assert(regs != NULL);
	assert(regs->acq != 0);

	q = &ctrlr->qp[0]->cq;

	q->size = regs->aqa.bits.acqs + 1;
	q->tail = 0;
	q->addr = map_one(ctrlr->lm_ctx, regs->acq,
			  q->size * sizeof(struct spdk_nvme_cpl), NULL, NULL);
	if (q->addr == NULL) {
		return -1;
	}
	memset(q->addr, 0, q->size * sizeof(struct spdk_nvme_cpl));
	q->is_cq = true;
	q->ien = true;
	insert_queue(ctrlr, q, true, 0);
	return 0;
}

static void *
_map_one(void *prv, uint64_t addr, uint64_t len)
{
	return map_one(prv, addr, len, NULL, NULL);
}

static int
muser_map_prps(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
	       struct iovec *iov, uint32_t length)
{
	return spdk_nvme_map_prps(ctrlr->lm_ctx, cmd, iov, length,
				  NVMF_MEMORY_PAGE_SIZE,
				  _map_one);
}

#ifdef DEBUG
/* TODO does such a function already exist in SPDK? */
static bool
is_prp(struct spdk_nvme_cmd *cmd)
{
	return cmd->psdt == 0;
}
#endif

static struct spdk_nvmf_request *
get_nvmf_req(struct muser_qpair *qp);

static int
handle_cmd_req(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
	       struct spdk_nvmf_request *req);

static void
handle_identify_ctrlr_rsp(struct spdk_nvme_ctrlr_data *data)
{
	assert(data != NULL);

	data->sgls.supported = SPDK_NVME_SGLS_NOT_SUPPORTED;

	/*
	 * Intentionally disabled, otherwise we get a
	 * SPDK_NVME_OPC_DATASET_MANAGEMENT command we don't know how to
	 * properly handle.
	 */
	data->oncs.dsm = 0;

	/*
	 * FIXME disable write zeroes for now.
	 */
	data->oncs.write_zeroes = 0;
}

/*
 * Posts a CQE in the completion queue.
 *
 * @ctrlr: the MUSER controller
 * @cmd: the NVMe command for which the completion is posted
 * @cq: the completion queue
 * @cdw0: cdw0 as reported by NVMf (only for SPDK_NVME_OPC_SET_FEATURES and
 *        SPDK_NVME_OPC_ABORT)
 * @sc: the NVMe CQE status code
 * @sct: the NVMe CQE status code type
 *
 * TODO Does it make sense for this function to fail? Currently it can do so
 * in two ways:
 *   1. lack of CQE: can we make sure there's always space in the CQ by e.g.
 *      making sure it's the same size as the SQ (assuming it's allowed by the
 *      NVMe spec)?
 *   2. triggering IRQ: probably not much we can do here, maybe set the
 *      controller in error state or send an error in the async event request
 *      (or both)?
 */
static int
post_completion(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
		struct io_q *cq, uint32_t cdw0, uint16_t sc,
		uint16_t sct)
{
	struct spdk_nvme_cpl *cpl;
	uint16_t qid;
	int err;

	assert(ctrlr != NULL);
	assert(cmd != NULL);

	qid = io_q_id(cq);

	/* FIXME */
	if (ctrlr->qp[0]->qpair.ctrlr->vcprop.csts.bits.shst != SPDK_NVME_SHST_NORMAL) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER,
			      "%s: ignore completion SQ%d cid=%d status=%#x\n",
			      ctrlr->id, qid, cmd->cid, sc);
		return 0;
	}

	if (cq_is_full(ctrlr, cq)) {
		SPDK_ERRLOG("%s: CQ%d full (tail=%d, head=%d)\n",
			    ctrlr->id, qid, cq->tail, *hdbl(ctrlr, cq));
		return -1;
	}

	cpl = ((struct spdk_nvme_cpl *)cq->addr) + cq->tail;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: request complete SQ%d cid=%d status=%#x SQ head=%#x CQ tail=%#x\n",
		      ctrlr->id, qid, cmd->cid, sc, ctrlr->qp[qid]->sq.head,
		      cq->tail);

	if (qid == 0) {
		switch (cmd->opc) {
		case SPDK_NVME_OPC_ABORT:
		case SPDK_NVME_OPC_SET_FEATURES:
		case SPDK_NVME_OPC_GET_FEATURES:
			cpl->cdw0 = cdw0;
			break;
		}
	}


	assert(ctrlr->qp[qid] != NULL);

	cpl->sqhd = ctrlr->qp[qid]->sq.head;
	cpl->cid = cmd->cid;
	cpl->status.dnr = 0x0;
	cpl->status.m = 0x0;
	cpl->status.sct = sct;
	cpl->status.p = ~cpl->status.p;
	cpl->status.sc = sc;

	cq_tail_advance(cq);

	/*
	 * FIXME this function now executes at SPDK thread context, we
	 * might be triggerring interrupts from MUSER thread context so
	 * check for race conditions.
	 */
	if (ctrlr_interrupt_enabled(ctrlr) && cq->ien) {
		err = lm_irq_trigger(ctrlr->lm_ctx, cq->iv);
		if (err != 0) {
			SPDK_ERRLOG("%s: failed to trigger interrupt: %m\n",
				    ctrlr->id);
			return err;
		}
	}

	return 0;
}

static struct io_q *
lookup_io_q(struct muser_ctrlr *ctrlr, const uint16_t qid, const bool is_cq)
{
	struct io_q *q;

	assert(ctrlr != NULL);

	if (qid > MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		return NULL;
	}

	if (ctrlr->qp[qid] == NULL) {
		return NULL;
	}

	if (is_cq) {
		q = &ctrlr->qp[qid]->cq;
	} else {
		q = &ctrlr->qp[qid]->sq;
	}

	if (q->addr == NULL) {
		return NULL;
	}

	return q;
}

static void
destroy_io_q(lm_ctx_t *lm_ctx, struct io_q *q)
{
	if (q == NULL) {
		return;
	}
	if (q->addr != NULL) {
		lm_unmap_sg(lm_ctx, &q->sg, &q->iov, 1);
		q->addr = NULL;
	}
}

static void
destroy_io_qp(struct muser_qpair *qp)
{
	if (qp->ctrlr == NULL) {
		return;
	}
	destroy_io_q(qp->ctrlr->lm_ctx, &qp->sq);
	destroy_io_q(qp->ctrlr->lm_ctx, &qp->cq);
}

static void
tear_down_qpair(struct muser_qpair *qpair)
{
	free(qpair->reqs_internal);
}

/*
 * TODO we can immediately remove the QP from the list because this function
 * is now executed by the SPDK thread.
 */
static void
destroy_qp(struct muser_ctrlr *ctrlr, uint16_t qid)
{
	struct muser_qpair *qpair;

	if (ctrlr == NULL) {
		return;
	}

	qpair = ctrlr->qp[qid];
	if (qpair == NULL) {
		return;
	}

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "destroy QP%d=%p\n", qid, qpair);

	/*
	 * TODO Is it possible for the pointer to be accessed while we're
	 * tearing down the queue?
	 */
	destroy_io_qp(qpair);
	tear_down_qpair(qpair);
	free(qpair);
	ctrlr->qp[qid] = NULL;
}

/* This function can only fail because of memory allocation errors. */
static int
init_qp(struct muser_ctrlr *ctrlr, struct spdk_nvmf_transport *transport,
	const uint16_t qsize, const uint16_t id)
{
	int err = 0, i;
	struct muser_qpair *qpair;
	struct muser_req *m_req;
	struct spdk_nvmf_request *req;

	assert(ctrlr != NULL);
	assert(transport != NULL);

	qpair = calloc(1, sizeof(*qpair));
	if (qpair == NULL) {
		return -ENOMEM;
	}

	qpair->qpair.qid = id;
	qpair->qpair.transport = transport;
	qpair->ctrlr = ctrlr;
	qpair->qsize = qsize;

	TAILQ_INIT(&qpair->reqs);

	qpair->reqs_internal = calloc(qsize, sizeof(struct muser_req));
	if (qpair->reqs_internal == NULL) {
		SPDK_ERRLOG("%s: error allocating reqs: %m\n", ctrlr->id);
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < qsize; i++) {
		m_req = &qpair->reqs_internal[i];
		req = &m_req->req;

		m_req->cid = i;
		req->qpair = &qpair->qpair;
		req->rsp = (union nvmf_c2h_msg *)&m_req->rsp;
		req->cmd = (union nvmf_h2c_msg *)&m_req->cmd;

		TAILQ_INSERT_TAIL(&qpair->reqs, m_req, link);
	}
	ctrlr->qp[id] = qpair;
out:
	if (err != 0) {
		tear_down_qpair(qpair);
	}
	return err;
}

/* XXX SPDK thread context */
/*
 * TODO adding/removing a QP is complicated, consider moving into a separate
 * file, e.g. start_stop_queue.c
 */
static int
add_qp(struct muser_ctrlr *ctrlr, struct spdk_nvmf_transport *transport,
       const uint16_t qsize, const uint16_t qid)
{
	int err;
	struct muser_transport *muser_transport;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: request add QP%d\n", ctrlr->id, qid);

	err = init_qp(ctrlr, transport, qsize, qid);
	if (err != 0) {
		return err;
	}

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	/*
	 * After we've returned from the muser_poll_group_poll thread, once
	 * muser_accept executes it will pick up this QP and will eventually
	 * call muser_poll_group_add. The rest of the opertions needed to
	 * complete the addition of the queue will be continued at the
	 * completion callback.
	 */
	TAILQ_INSERT_TAIL(&muser_transport->new_qps, ctrlr->qp[qid], link);

	return 0;
}

/*
 * Creates a completion or sumbission I/O queue. Returns 0 on success, -errno
 * on error.
 *
 * XXX SPDK thread context.
 */
static int
handle_create_io_q(struct muser_ctrlr *ctrlr,
		   struct spdk_nvme_cmd *cmd, const bool is_cq)
{
	size_t entry_size;
	uint16_t sc = SPDK_NVME_SC_SUCCESS;
	uint16_t sct = SPDK_NVME_SCT_GENERIC;
	int err = 0;

	/*
	 * XXX don't call io_q_id on this. Maybe operate directly on the
	 * ctrlr->qp[id].cq/sq?
	 */
	struct io_q io_q = { 0 };

	assert(ctrlr != NULL);
	assert(cmd != NULL);

	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: create I/O %cQ%d: QSIZE=%#x\n", ctrlr->id,
		      is_cq ? 'C' : 'S', cmd->cdw10_bits.create_io_q.qid,
		      cmd->cdw10_bits.create_io_q.qsize);

	if (cmd->cdw10_bits.create_io_q.qid >= MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		SPDK_ERRLOG("%s: invalid QID=%d, max=%d\n", ctrlr->id,
			    cmd->cdw10_bits.create_io_q.qid,
			    MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR);
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		goto out;
	}

	if (lookup_io_q(ctrlr, cmd->cdw10_bits.create_io_q.qid, is_cq)) {
		SPDK_ERRLOG("%s: %cQ%d already exists\n", ctrlr->id,
			    is_cq ? 'C' : 'S', cmd->cdw10_bits.create_io_q.qid);
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		goto out;
	}

	/* TODO break rest of this function into smaller functions */
	if (is_cq) {
		entry_size = sizeof(struct spdk_nvme_cpl);
		if (cmd->cdw11_bits.create_io_cq.pc != 0x1) {
			/*
			 * TODO CAP.CMBS is currently set to zero, however we
			 * should zero it out explicitly when CAP is read.
			 * Support for CAP.CMBS is not mentioned in the NVMf
			 * spec.
			 */
			SPDK_ERRLOG("%s: non-PC CQ not supporred\n", ctrlr->id);
			sc = SPDK_NVME_SC_INVALID_CONTROLLER_MEM_BUF;
			goto out;
		}
		io_q.ien = cmd->cdw11_bits.create_io_cq.ien;
		io_q.iv = cmd->cdw11_bits.create_io_cq.iv;
	} else {
		/* CQ must be created before SQ */
		if (!lookup_io_q(ctrlr, cmd->cdw11_bits.create_io_sq.cqid, true)) {
			SPDK_ERRLOG("%s: CQ%d does not exist\n", ctrlr->id,
				    cmd->cdw11_bits.create_io_sq.cqid);
			sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
			sc = SPDK_NVME_SC_COMPLETION_QUEUE_INVALID;
			goto out;
		}

		entry_size = sizeof(struct spdk_nvme_cmd);
		if (cmd->cdw11_bits.create_io_sq.pc != 0x1) {
			SPDK_ERRLOG("%s: non-PC SQ not supported\n", ctrlr->id);
			sc = SPDK_NVME_SC_INVALID_CONTROLLER_MEM_BUF;
			goto out;
		}

		io_q.cqid = cmd->cdw11_bits.create_io_sq.cqid;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: SQ%d CQID=%d\n", ctrlr->id,
			      cmd->cdw10_bits.create_io_q.qid, io_q.cqid);
	}

	io_q.size = cmd->cdw10_bits.create_io_q.qsize + 1;
	if (io_q.size > max_queue_size(ctrlr)) {
		SPDK_ERRLOG("%s: queue too big, want=%d, max=%d\n", ctrlr->id,
			    io_q.size, max_queue_size(ctrlr));
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_SIZE;
		goto out;
	}

	io_q.addr = map_one(ctrlr->lm_ctx, cmd->dptr.prp.prp1,
			    io_q.size * entry_size, &io_q.sg, &io_q.iov);
	if (io_q.addr == NULL) {
		sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
		SPDK_ERRLOG("%s: failed to map I/O queue: %m\n", ctrlr->id);
		goto out;
	}
	memset(io_q.addr, 0, io_q.size * entry_size);

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: mapped %cQ%d IOVA=%#lx vaddr=%#llx\n",
		      ctrlr->id, is_cq ? 'C' : 'S',
		      cmd->cdw10_bits.create_io_q.qid, cmd->dptr.prp.prp1,
		      (unsigned long long)io_q.addr);

	if (is_cq) {
		err = add_qp(ctrlr, ctrlr->qp[0]->qpair.transport, io_q.size,
			     cmd->cdw10_bits.create_io_q.qid);
		if (err != 0) {
			sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
			goto out;
		}
	}

	/* FIXME shouldn't we do this at completion? */
	insert_queue(ctrlr, &io_q, is_cq, cmd->cdw10_bits.create_io_q.qid);

out:
	return post_completion(ctrlr, cmd, &ctrlr->qp[0]->cq, 0, sc, sct);
}

/*
 * Deletes a completion or sumbission I/O queue.
 */
static int
handle_del_io_q(struct muser_ctrlr *ctrlr,
		struct spdk_nvme_cmd *cmd, const bool is_cq)
{
	uint16_t sct = SPDK_NVME_SCT_GENERIC;
	uint16_t sc = SPDK_NVME_SC_SUCCESS;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: delete I/O %cQ: QID=%d\n",
		      ctrlr->id, is_cq ? 'C' : 'S',
		      cmd->cdw10_bits.delete_io_q.qid);

	if (lookup_io_q(ctrlr, cmd->cdw10_bits.delete_io_q.qid, is_cq) == NULL) {
		SPDK_ERRLOG("%s: %cQ%d does not exist\n", ctrlr->id,
			    is_cq ? 'C' : 'S', cmd->cdw10_bits.delete_io_q.qid);
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		goto out;
	}

	if (is_cq) {
		/* SQ must have been deleted first */
		if (!ctrlr->qp[cmd->cdw10_bits.delete_io_q.qid]->del) {
			/* TODO add error message */
			sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
			sc = SPDK_NVME_SC_INVALID_QUEUE_DELETION;
			goto out;
		}
	} else {
		/*
		 * FIXME this doesn't actually delete the I/O queue, we can't
		 * do that anyway because NVMf doesn't support it. We're merely
		 * telling the poll_group_poll function to skip checking this
		 * queue. The only workflow this works is when CC.EN is set to
		 * 0 and we're stopping the subsystem, so we know that the
		 * relevant callbacks to destroy the queues will be called.
		 */
		ctrlr->qp[cmd->cdw10_bits.delete_io_q.qid]->del = true;
	}

out:
	return post_completion(ctrlr, cmd, &ctrlr->qp[0]->cq, 0, sc, sct);
}

/* TODO need to honor the Abort Command Limit field */
static int
handle_abort_cmd(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	assert(ctrlr != NULL);

	/* abort command not yet implemented */
	return post_completion(ctrlr, cmd, &ctrlr->qp[0]->cq, 1,
			       SPDK_NVME_SC_SUCCESS, SPDK_NVME_SCT_GENERIC);
}

/*
 * Returns 0 on success and -errno on error.
 *
 * XXX SPDK thread context
 */
static int
consume_admin_cmd(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	assert(ctrlr != NULL);
	assert(cmd != NULL);

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: handle admin req opc=%#x cid=%d\n",
		      ctrlr->id, cmd->opc, cmd->cid);

	switch (cmd->opc) {
	/* TODO put all cases in order */
	/* FIXME we pass the async event request to NVMf so if we ever need to
	 * send an event to the host we won't be able to. We'll have to somehow
	 * grab this request from NVMf. If we don't forward the request to NVMf
	 * then NVMf won't be able to issue an async event response if it needs
	 * to. One way to solve this problem is to keep the request and then
	 * generate another one for NVMf. If NVMf ever completes it then we copy
	 * it to the one we kept and complete it.
	 */
	case SPDK_NVME_OPC_ASYNC_EVENT_REQUEST:
	case SPDK_NVME_OPC_IDENTIFY:
	case SPDK_NVME_OPC_SET_FEATURES:
	case SPDK_NVME_OPC_GET_FEATURES:
	case SPDK_NVME_OPC_GET_LOG_PAGE:
	/*
	 * NVMf correctly fails this request with sc=0x01 (Invalid Command
	 * Opcode) as it does not advertise support for the namespace management
	 * capability (oacs.ns_manage is set to 0 in the identify response).
	 */
	case SPDK_NVME_OPC_NS_MANAGEMENT:
		return handle_cmd_req(ctrlr, cmd, get_nvmf_req(ctrlr->qp[0]));
	case SPDK_NVME_OPC_CREATE_IO_CQ:
	case SPDK_NVME_OPC_CREATE_IO_SQ:
		return handle_create_io_q(ctrlr, cmd,
					  cmd->opc == SPDK_NVME_OPC_CREATE_IO_CQ);
	case SPDK_NVME_OPC_ABORT:
		return handle_abort_cmd(ctrlr, cmd);
	case SPDK_NVME_OPC_DELETE_IO_SQ:
	case SPDK_NVME_OPC_DELETE_IO_CQ:
		return handle_del_io_q(ctrlr, cmd,
				       cmd->opc == SPDK_NVME_OPC_DELETE_IO_CQ);
	}

	SPDK_NOTICELOG("%s: unsupported command 0x%x\n", ctrlr->id, cmd->opc);
	return post_completion(ctrlr, cmd, &ctrlr->qp[0]->cq, 0,
			       SPDK_NVME_SC_INVALID_OPCODE,
			       SPDK_NVME_SCT_GENERIC);
}

static int
handle_cmd_rsp(struct muser_req *req, void *cb_arg)
{
	struct muser_qpair *qpair = cb_arg;
	struct spdk_nvme_cmd *cmd = &req->req.cmd->nvme_cmd;

	assert(qpair != NULL);
	assert(req != NULL);

	if (nvmf_qpair_is_admin_queue(&qpair->qpair)) {
		switch (cmd->opc) {
		case SPDK_NVME_OPC_IDENTIFY:
			if ((cmd->cdw10 & 0xFF) == SPDK_NVME_IDENTIFY_CTRLR) {
				handle_identify_ctrlr_rsp(req->req.data);
			}
			break;
		default:
			break;
		}
	}

	return post_completion(qpair->ctrlr, &req->req.cmd->nvme_cmd,
			       &qpair->ctrlr->qp[req->req.qpair->qid]->cq,
			       req->req.rsp->nvme_cpl.cdw0,
			       req->req.rsp->nvme_cpl.status.sc,
			       req->req.rsp->nvme_cpl.status.sct);
}

static int
consume_cmd(struct muser_ctrlr *ctrlr, struct muser_qpair *qpair,
	    struct spdk_nvme_cmd *cmd)
{
	assert(qpair != NULL);
	if (nvmf_qpair_is_admin_queue(&qpair->qpair)) {
		return consume_admin_cmd(ctrlr, cmd);
	}

	return handle_cmd_req(ctrlr, cmd, get_nvmf_req(qpair));
}

static ssize_t
handle_sq_tdbl_write(struct muser_ctrlr *ctrlr, const uint32_t new_tail,
		     struct muser_qpair *qpair)
{
	struct spdk_nvme_cmd *queue;

	assert(ctrlr != NULL);
	assert(qpair != NULL);

	/*
	 * TODO operating on an SQ is pretty much the same for admin and I/O
	 * queues. All we need is a callback to replace consume_req,
	 * depending on the type of the queue.
	 *
	 */
	queue = qpair->sq.addr;
	while (sq_head(qpair) != new_tail) {
		int err;
		struct spdk_nvme_cmd *cmd = &queue[sq_head(qpair)];

		/*
		 * SQHD must contain the new head pointer, so we must increase
		 * it before we generate a completion.
		 */
		sqhd_advance(ctrlr, qpair);

		err = consume_cmd(ctrlr, qpair, cmd);
		if (err != 0) {
			return err;
		}
	}

	return 0;
}

/*
 * Handles a write at offset 0x1000 or more.
 *
 * DSTRD is set to fixed value 0 for NVMf.
 *
 * TODO this function won't be called when sparse mapping is used, however it
 * might be used when we dynamically switch off polling, so I'll leave it here
 * for now.
 */
static int
handle_dbl_access(struct muser_ctrlr *ctrlr, uint32_t *buf,
		  const size_t count, loff_t pos, const bool is_write)
{
	assert(ctrlr != NULL);
	assert(buf != NULL);

	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("%s: bad doorbell buffer size %ld\n",
			    ctrlr->id, count);
		return -EINVAL;
	}

	pos -= DOORBELLS;

	/* pos must be dword aligned */
	if ((pos & 0x3) != 0) {
		SPDK_ERRLOG("%s: bad doorbell offset %#lx\n", ctrlr->id, pos);
		return -EINVAL;
	}

	/* convert byte offset to array index */
	pos >>= 2;

	if (pos > MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR * 2) {
		/*
		 * FIXME need to emit a "Write to Invalid Doorbell Register"
		 * asynchronous event
		 */
		SPDK_ERRLOG("%s: bad doorbell index %#lx\n", ctrlr->id, pos);
		return -EINVAL;
	}

	if (is_write) {
		ctrlr->doorbells[pos] = *buf;
		spdk_wmb();
	} else {
		spdk_rmb();
		*buf = ctrlr->doorbells[pos];
	}
	return 0;
}

static ssize_t
access_bar0_fn(void *pvt, char *buf, size_t count, loff_t pos,
	       bool is_write)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;
	int ret;

	ctrlr = muser_ep->ctrlr;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: bar0 %s ctrlr: %p, count=%zu, pos=%"PRIX64"\n",
		      ctrlr->id, is_write ? "write" : "read", ctrlr, count,
		      pos);

	if (is_write) {
		spdk_log_dump(stdout, "muser_write", buf, count);
	}

	if (pos >= DOORBELLS) {
		ret = handle_dbl_access(ctrlr, (uint32_t *)buf, count,
					pos, is_write);
		if (ret == 0) {
			return count;
		}
		assert(ret < 0);
		return ret;
	}

	ret = do_prop_req(ctrlr, buf, count, pos, is_write);
	if (ret != 0) {
		SPDK_WARNLOG("%s: failed to %s %lx@%lx BAR0\n", ctrlr->id,
			     is_write ? "write" : "read", pos, count);
		return -1;
	}

	return count;
}

/*
 * NVMe driver reads 4096 bytes, which is the extended PCI configuration space
 * available on PCI-X 2.0 and PCI Express buses
 */
static ssize_t
access_pci_config(void *pvt, char *buf, size_t count, loff_t offset,
		  const bool is_write)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;

	if (is_write) {
		fprintf(stderr, "writes not supported\n");
		return -EINVAL;
	}

	if (offset + count > PCI_CFG_SPACE_EXP_SIZE) {
		fprintf(stderr, "access past end of extended PCI configuration space, want=%ld+%ld, max=%d\n",
			offset, count, PCI_CFG_SPACE_EXP_SIZE);
		return -ERANGE;
	}

	memcpy(buf, ((unsigned char *)ctrlr->pci_config_space) + offset, count);

	return count;
}

static ssize_t
handle_pc_write(struct muser_ctrlr *ctrlr, const struct pc *const pc)
{
	/* FIXME IIUC these are RO fields, figure out how to handle */
	assert(false);
}

static ssize_t
handle_pmcs_write(struct muser_ctrlr *ctrlr, const struct pmcs *const pmcs)
{

	if (ctrlr->pmcap.pmcs.ps != pmcs->ps) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: power state set to %#x\n",
			      ctrlr->id, pmcs->ps);
	}
	if (ctrlr->pmcap.pmcs.pmee != pmcs->pmee) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: PME enable set to %#x\n",
			      ctrlr->id, pmcs->pmee);
	}
	if (ctrlr->pmcap.pmcs.dse != pmcs->dse) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: data select set to %#x\n",
			      ctrlr->id, pmcs->dse);
	}
	if (ctrlr->pmcap.pmcs.pmes != pmcs->pmes) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: PME status set to %#x\n",
			      ctrlr->id, pmcs->pmes);
	}
	ctrlr->pmcap.pmcs = *pmcs;
	return 0;
}

static ssize_t
handle_pmcap_write(struct muser_ctrlr *ctrlr, char *const buf,
		   const size_t count, const loff_t offset)
{
	switch (offset) {
	case offsetof(struct pmcap, pc):
		if (count != sizeof(struct pc)) {
			return -EINVAL;
		}
		return handle_pc_write(ctrlr, (struct pc *)buf);
	case offsetof(struct pmcap, pmcs):
		if (count != sizeof(struct pmcs)) {
			return -EINVAL;
		}
		return handle_pmcs_write(ctrlr, (struct pmcs *)buf);
	}
	return -EINVAL;
}

static ssize_t
pmcap_access(void *pvt, const uint8_t id, char *const buf, const size_t count,
	     const loff_t offset, const bool is_write)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;

	if (is_write) {
		return handle_pmcap_write(ctrlr, buf, count, offset);
	}

	memcpy(buf, ((char *)&ctrlr->pmcap) + offset, count);

	return count;
}

static ssize_t
handle_mxc_write(struct muser_ctrlr *ctrlr, const struct mxc *const mxc)
{
	assert(ctrlr != NULL);
	assert(mxc != NULL);

	if (mxc->mxe != ctrlr->msixcap.mxc.mxe) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: %s MSI-X\n", ctrlr->id,
			      mxc->mxe ? "enable" : "disable");
		ctrlr->msixcap.mxc.mxe = mxc->mxe;
	}

	if (mxc->fm != ctrlr->msixcap.mxc.fm) {
		if (mxc->fm) {
			SPDK_DEBUGLOG(SPDK_LOG_MUSER,
				      "%s: all MSI-X vectors masked\n",
				      ctrlr->id);
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_MUSER,
				      "%s: vector's mask bit determines whether vector is masked",
				      ctrlr->id);
		}
		ctrlr->msixcap.mxc.fm = mxc->fm;
	}

	return sizeof(struct mxc);
}

static ssize_t
handle_msix_write(struct muser_ctrlr *ctrlr, char *const buf, const size_t count,
		  const loff_t offset)
{
	if (count == sizeof(struct mxc)) {
		switch (offset) {
		case offsetof(struct msixcap, mxc):
			return handle_mxc_write(ctrlr, (struct mxc *)buf);
		default:
			SPDK_ERRLOG("%s: invalid MSI-X write offset %ld\n",
				    ctrlr->id, offset);
			return -EINVAL;
		}
	}
	SPDK_ERRLOG("%s: invalid MSI-X write size %lu\n", ctrlr->id, count);
	return -EINVAL;
}

static ssize_t
msixcap_access(void *pvt, const uint8_t id, char *const buf, size_t count,
	       loff_t offset, const bool is_write)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;

	if (is_write) {
		return handle_msix_write(ctrlr, buf, count, offset);
	}

	memcpy(buf, ((char *)&ctrlr->msixcap) + offset, count);

	return count;
}

static int
handle_pxcap_pxdc_write(struct muser_ctrlr *const c, const union pxdc *const p)
{
	assert(c != NULL);
	assert(p != NULL);

	if (p->cere != c->pxcap.pxdc.cere) {
		c->pxcap.pxdc.cere = p->cere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: CERE %s\n", c->id,
			      p->cere ? "enable" : "disable");
	}

	if (p->nfere != c->pxcap.pxdc.nfere) {
		c->pxcap.pxdc.nfere = p->nfere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: NFERE %s\n", c->id,
			      p->nfere ? "enable" : "disable");
	}

	if (p->fere != c->pxcap.pxdc.fere) {
		c->pxcap.pxdc.fere = p->fere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: FERE %s\n", c->id,
			      p->fere ? "enable" : "disable");
	}

	if (p->urre != c->pxcap.pxdc.urre) {
		c->pxcap.pxdc.urre = p->urre;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: URRE %s\n", c->id,
			      p->urre ? "enable" : "disable");
	}

	if (p->ero != c->pxcap.pxdc.ero) {
		c->pxcap.pxdc.ero = p->ero;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: ERO %s\n", c->id,
			      p->ero ? "enable" : "disable");
	}

	if (p->mps != c->pxcap.pxdc.mps) {
		c->pxcap.pxdc.mps = p->mps;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: MPS set to %d\n", c->id,
			      p->mps);
	}

	if (p->ete != c->pxcap.pxdc.ete) {
		c->pxcap.pxdc.ete = p->ete;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: ETE %s\n", c->id,
			      p->ete ? "enable" : "disable");
	}

	if (p->pfe != c->pxcap.pxdc.pfe) {
		c->pxcap.pxdc.pfe = p->pfe;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: PFE %s\n", c->id,
			      p->pfe ? "enable" : "disable");
	}

	if (p->appme != c->pxcap.pxdc.appme) {
		c->pxcap.pxdc.appme = p->appme;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: APPME %s\n", c->id,
			      p->appme ? "enable" : "disable");
	}

	if (p->ens != c->pxcap.pxdc.ens) {
		c->pxcap.pxdc.ens = p->ens;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: ENS %s\n", c->id,
			      p->ens ? "enable" : "disable");
	}

	if (p->mrrs != c->pxcap.pxdc.mrrs) {
		c->pxcap.pxdc.mrrs = p->mrrs;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: MRRS set to %d\n", c->id,
			      p->mrrs);
	}

	if (p->iflr) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER,
			      "%s: initiate function level reset\n", c->id);
	}

	return 0;
}

static int
handle_pxcap_write_2_bytes(struct muser_ctrlr *c, char *const b, loff_t o)
{
	switch (o) {
	case offsetof(struct pxcap, pxdc):
		return handle_pxcap_pxdc_write(c, (union pxdc *)b);
	}
	return -EINVAL;
}

static ssize_t
handle_pxcap_write(struct muser_ctrlr *ctrlr, char *const buf, size_t count,
		   loff_t offset)
{
	int err = -EINVAL;
	switch (count) {
	case 2:
		err = handle_pxcap_write_2_bytes(ctrlr, buf, offset);
		break;
	}
	if (err != 0) {
		return err;
	}
	return count;
}

static ssize_t
pxcap_access(void *pvt, const uint8_t id, char *const buf, size_t count,
	     loff_t offset, const bool is_write)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;

	if (is_write) {
		return handle_pxcap_write(ctrlr, buf, count, offset);
	}

	memcpy(buf, ((char *)&ctrlr->pxcap) + offset, count);

	return count;
}

#ifndef TRAP_DOORBELLS
static unsigned long
bar0_mmap(void *pvt, unsigned long off, unsigned long len)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;

	assert(ctrlr != NULL);

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: map doorbells %#lx-%#lx\n",
		      ctrlr->id, off, off + len);

	if (off != DOORBELLS || len != MUSER_DOORBELLS_SIZE) {
		SPDK_ERRLOG("%s: bad map region %#lx-%#lx\n", ctrlr->id, off,
			    off + len);
		errno = EINVAL;
		return (unsigned long)MAP_FAILED;
	}

	if (ctrlr->doorbells != NULL) {
		goto out;
	}

	ctrlr->doorbells = lm_mmap(ctrlr->lm_ctx, off, len);
	if (ctrlr->doorbells == MAP_FAILED) {
		SPDK_ERRLOG("%s: failed to allocate device memory: %m\n",
			    ctrlr->id);
	}
out:

	return (unsigned long)ctrlr->endpoint->fd;
}
#endif

static void
muser_log(void *pvt, lm_log_lvl_t lvl, char const *msg)
{
	struct muser_endpoint *muser_ep = pvt;
	struct muser_ctrlr *ctrlr;

	ctrlr = muser_ep->ctrlr;
	assert(ctrlr != NULL);

	if (lvl >= LM_DBG) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: %s", ctrlr->id, msg);
	} else if (lvl >= LM_INF) {
		SPDK_NOTICELOG("%s: %s", ctrlr->id, msg);
	} else {
		SPDK_ERRLOG("%s: %s", ctrlr->id, msg);
	}
}

static void
muser_dev_info_fill(lm_dev_info_t *dev_info)
{
	static const lm_cap_t pm = {.id = PCI_CAP_ID_PM,
				    .size = sizeof(struct pmcap),
				    .fn = pmcap_access
				   };
	static const lm_cap_t px = {.id = PCI_CAP_ID_EXP,
				    .size = sizeof(struct pxcap),
				    .fn = pxcap_access
				   };
	static const lm_cap_t msix = {.id = PCI_CAP_ID_MSIX,
				      .size = sizeof(struct msixcap),
				      .fn = msixcap_access
				     };

	lm_reg_info_t *reg_info;

	assert(dev_info != NULL);

	dev_info->trans = LM_TRANS_SOCK;
	dev_info->flags |= LM_FLAG_ATTACH_NB;

	dev_info->pci_info.id.vid = 0x4e58;     /* TODO: LE ? */
	dev_info->pci_info.id.did = 0x0001;

	/* controller uses the NVM Express programming interface */
	dev_info->pci_info.cc.pi = 0x02;

	/* non-volatile memory controller */
	dev_info->pci_info.cc.scc = 0x08;

	/* mass storage controller */
	dev_info->pci_info.cc.bcc = 0x01;

	dev_info->pci_info.irq_count[LM_DEV_INTX_IRQ_IDX] = NVME_IRQ_INTX_NUM;

	dev_info->caps[dev_info->nr_caps++] = pm;

	dev_info->pci_info.irq_count[LM_DEV_MSIX_IRQ_IDX] = NVME_IRQ_MSIX_NUM;
	dev_info->caps[dev_info->nr_caps++] = msix;

	dev_info->caps[dev_info->nr_caps++] = px;

	dev_info->extended = true;

	dev_info->log = muser_log;

	if (spdk_log_get_print_level() >= SPDK_LOG_DEBUG) {
		dev_info->log_lvl = LM_DBG;
	} else if (spdk_log_get_print_level() >= SPDK_LOG_INFO) {
		dev_info->log_lvl = LM_INF;
	} else {
		dev_info->log_lvl = LM_ERR;
	}

	reg_info = dev_info->pci_info.reg_info;
	memset(reg_info, 0, sizeof(*reg_info) * LM_DEV_NUM_REGS);

	reg_info[LM_DEV_BAR0_REG_IDX].flags = LM_REG_FLAG_RW;
#ifndef TRAP_DOORBELLS
	reg_info[LM_DEV_BAR0_REG_IDX].flags |= LM_REG_FLAG_MMAP;
	reg_info[LM_DEV_BAR0_REG_IDX].map  = bar0_mmap;
	reg_info[LM_DEV_BAR0_REG_IDX].mmap_areas = alloca(sizeof(
				struct lm_sparse_mmap_areas) + sizeof(struct lm_mmap_area));
	reg_info[LM_DEV_BAR0_REG_IDX].mmap_areas->nr_mmap_areas = 1;
	reg_info[LM_DEV_BAR0_REG_IDX].mmap_areas->areas[0].start = DOORBELLS;
	reg_info[LM_DEV_BAR0_REG_IDX].mmap_areas->areas[0].size = PAGE_ALIGN(
				MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR * sizeof(uint32_t) * 2);
#endif
	reg_info[LM_DEV_BAR0_REG_IDX].size  = NVME_REG_BAR0_SIZE;
	reg_info[LM_DEV_BAR0_REG_IDX].fn  = access_bar0_fn;

	reg_info[LM_DEV_BAR4_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_BAR4_REG_IDX].size  = PAGE_SIZE;

	reg_info[LM_DEV_BAR5_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_BAR5_REG_IDX].size  = PAGE_SIZE;

	reg_info[LM_DEV_CFG_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_CFG_REG_IDX].size  = NVME_REG_CFG_SIZE;
	reg_info[LM_DEV_CFG_REG_IDX].fn  = access_pci_config;
}

/*
 * Returns (void*)0 on success, (void*)-errno on error.
 */
static void *
drive(void *arg)
{
	int err;
	lm_ctx_t *lm_ctx = arg;

	assert(arg != NULL);

	/*
	 * TODO need accesor for lm_ctx_t.pvt == struct muser_endpoint*
	 * so that we can include the ID when printing
	 */

	err = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	if (err != 0)  {
		SPDK_ERRLOG("failed to set pthread cancel state: %s\n",
			    strerror(err));
		return (void *)((long) - err);
	}
	err = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	if (err != 0)  {
		SPDK_ERRLOG("failed to set pthread cancel type: %s\n",
			    strerror(err));
		return (void *)((long) - err);
	}

	return (void *)((long)lm_ctx_drive(lm_ctx));
}

static void
init_pci_config_space(lm_pci_config_space_t *p)
{
	struct nvme_pcie_mlbar *mlbar;
	struct nvme_pcie_bar2 *nvme_bar2;

	/* MLBAR */
	mlbar = (struct nvme_pcie_mlbar *)&p->hdr.bars[0];
	memset(mlbar, 0, sizeof(*mlbar));

	/* MUBAR */
	p->hdr.bars[1].raw = 0x0;

	/*
	 * BAR2, index/data pair register base address or vendor specific (optional)
	 */
	nvme_bar2 = (struct nvme_pcie_bar2 *)&p->hdr.bars[2].raw;
	memset(nvme_bar2, 0, sizeof(*nvme_bar2));
	nvme_bar2->rte = 0x1;

	/* vendor specific, let's set them to zero for now */
	p->hdr.bars[3].raw = 0x0;
	p->hdr.bars[4].raw = 0x0;
	p->hdr.bars[5].raw = 0x0;

	/* enable INTx */
	p->hdr.intr.ipin = 0x1;
}

static int
muser_snprintf_subnqn(struct muser_ctrlr *ctrlr, uint8_t *subnqn)
{
	int ret;

	assert(ctrlr != NULL);
	assert(subnqn != NULL);

	ret = snprintf(subnqn, SPDK_NVME_NQN_FIELD_SIZE,
		       "nqn.2019-07.io.spdk.muser:%s", ctrlr->uuid);
	return (size_t)ret >= SPDK_NVME_NQN_FIELD_SIZE ? -1 : 0;
}

static int
destroy_pci_dev(struct muser_ctrlr *ctrlr)
{

	int err;
	void *res;

	if (ctrlr == NULL || ctrlr->lm_ctx == NULL) {
		return 0;
	}
	if (ctrlr->lm_thr != 0) {
		err = pthread_cancel(ctrlr->lm_thr);
		if (err == 0) {
			err = pthread_join(ctrlr->lm_thr, &res);
			if (err != 0) {
				SPDK_ERRLOG("%s: failed to join thread: %s\n",
					    ctrlr->id, strerror(err));
				return -err;
			}
			if (res != PTHREAD_CANCELED) {
				SPDK_ERRLOG("%s: thread exited: %s\n",
					    ctrlr->id, strerror(-(intptr_t)res));
				/* thread died, not much we can do here */
			}
		} else if (err != ESRCH) {
			SPDK_ERRLOG("%s: failed to cancel thread: %s\n",
				    ctrlr->id, strerror(err));
			return -err;
		}
	}

	return 0;
}

static int
destroy_ctrlr(struct muser_ctrlr *ctrlr)
{
	int err;

	if (ctrlr == NULL) {
		return 0;
	}
	destroy_qp(ctrlr, 0);
	err = destroy_pci_dev(ctrlr);
	if (err != 0) {
		SPDK_ERRLOG("%s: failed to tear down PCI device: %s\n",
			    ctrlr->id, strerror(-err));
		return err;
	}

	if (ctrlr->endpoint) {
		ctrlr->endpoint->ctrlr = NULL;
	}

	free(ctrlr);
	return 0;
}

/*
 * TODO this assumes that the last two components are <domain UUID>/<IOMMU group>, e.g.
 * /var/run/muser/domain/49abd9e2-efa1-488f-8d4f-5a5f8e592fe9/2
 * It's a hack, but the way it's implpemented means that it won't break
 * should the above change. We should find a better way of extracting a
 * reasonable length ID.
 */
static const char *
muser_ctrlr_id(const char *s)
{
	const char *p = strrchr(s, '/');
	if (p != NULL) {
		while (p > s && *(p - 1) != '/') {
			p--;
		}
	} else {
		p = s;
	}
	return p;

}

static int
muser_create_ctrlr(struct muser_transport *muser_transport,
		   struct muser_endpoint *muser_ep)
{
	struct muser_ctrlr *muser_ctrlr;
	struct spdk_nvmf_poll_group *pg;
	int err;

	/* First, construct a muser controller */
	muser_ctrlr = calloc(1, sizeof(*muser_ctrlr));
	if (muser_ctrlr == NULL) {
		err = -ENOMEM;
		goto out;
	}
	muser_ctrlr->cntlid = 0xffff;
	muser_ctrlr->transport = muser_transport;
	memcpy(muser_ctrlr->uuid, muser_ep->trid.traddr, sizeof(muser_ctrlr->uuid));
	muser_ctrlr->id = (char *)muser_ctrlr_id(muser_ctrlr->uuid);

	muser_ctrlr->prop_req.muser_req.req.rsp = (union nvmf_c2h_msg *)
			&muser_ctrlr->prop_req.muser_req.rsp;
	muser_ctrlr->prop_req.muser_req.req.cmd = (union nvmf_h2c_msg *)
			&muser_ctrlr->prop_req.muser_req.cmd;

	err = sem_init(&muser_ctrlr->sem, 0, 0);
	if (err != 0) {
		goto out;
	}

	muser_ctrlr->endpoint = muser_ep;
	muser_ctrlr->lm_ctx = muser_ep->lm_ctx;
	muser_ctrlr->doorbells = muser_ep->doorbells;

	muser_ep->ctrlr = muser_ctrlr;

	/* PM */
	muser_ctrlr->pmcap.pmcs.nsfrst = 0x1;

	/*
	 * MSI-X
	 *
	 * TODO for now we put table BIR and PBA BIR in BAR4 because
	 * it's just easier, otherwise in order to put it in BAR0 we'd
	 * have to figure out where exactly doorbells end.
	 */
	muser_ctrlr->msixcap.mxc.ts = NVME_IRQ_MSIX_NUM - 1;
	muser_ctrlr->msixcap.mtab.tbir = 0x4;
	muser_ctrlr->msixcap.mtab.to = 0x0;
	muser_ctrlr->msixcap.mpba.pbir = 0x5;
	muser_ctrlr->msixcap.mpba.pbao = 0x0;

	/* EXP */
	muser_ctrlr->pxcap.pxcaps.ver = 0x2;
	muser_ctrlr->pxcap.pxdcap.per = 0x1;
	muser_ctrlr->pxcap.pxdcap.flrc = 0x1;
	muser_ctrlr->pxcap.pxdcap2.ctds = 0x1;
	/* FIXME check PXCAPS.DPT */

	muser_ctrlr->pci_config_space = lm_get_pci_config_space(muser_ctrlr->lm_ctx);
	init_pci_config_space(muser_ctrlr->pci_config_space);

	/* Then, construct an admin queue pair */
	err = init_qp(muser_ctrlr, &muser_transport->transport, MUSER_DEFAULT_AQ_DEPTH, 0);
	if (err != 0) {
		goto out;
	}

	pg = spdk_nvmf_poll_group_create(muser_transport->transport.tgt);
	assert(pg != NULL);
	/* Add this qpair to our internal poll group, just so that it has one assigned. */
	spdk_nvmf_poll_group_add(pg, &muser_ctrlr->qp[0]->qpair);

	/* Add this controller to the list. The rest of the work will be done
	 * when this is assigned to a subsystem. */
	TAILQ_INSERT_TAIL(&muser_transport->ctrlrs, muser_ctrlr, link);

out:
	if (err != 0) {
		/*
		 * TODO this prints the whole path instead of
		 * <domain UUID>/<IOMMU group>, fix.
		 */
		SPDK_ERRLOG("%s: failed to create MUSER controller: %s\n",
			    muser_ep->trid.traddr, strerror(-err));
		if (destroy_ctrlr(muser_ctrlr) != 0) {
			SPDK_ERRLOG("%s: failed to clean up\n", muser_ep->trid.traddr);
		}
	}

	return err;
}

static int
muser_listen(struct spdk_nvmf_transport *transport,
	     const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_endpoint *muser_ep, *tmp;
	char *path = NULL;
	int fd;
	int err;
	lm_dev_info_t dev_info = { 0 };

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	TAILQ_FOREACH_SAFE(muser_ep, &muser_transport->endpoints, link, tmp) {
		/* Only compare traddr */
		if (strncmp(muser_ep->trid.traddr, trid->traddr, sizeof(muser_ep->trid.traddr)) == 0) {
			return -EEXIST;
		}
	}

	muser_ep = calloc(1, sizeof(*muser_ep));
	if (!muser_ep) {
		return -ENOMEM;
	}

	muser_ep->fd = -1;
	memcpy(&muser_ep->trid, trid, sizeof(muser_ep->trid));

	err = asprintf(&path, "%s/bar0", muser_ep->trid.traddr);
	if (err == -1) {
		goto out;
	}

	fd = open(path, O_RDWR | O_CREAT);
	if (fd == -1) {
		SPDK_ERRLOG("%s: failed to open device memory at %s: %m\n",
			    muser_ep->trid.traddr, path);
		err = fd;
		free(path);
		goto out;
	}

	unlink(path);
	free(path);

	err = ftruncate(fd, DOORBELLS + MUSER_DOORBELLS_SIZE);
	if (err != 0) {
		goto out;
	}

#ifdef TRAP_DOORBELLS
	muser_ep->doorbells = calloc(1, MUSER_DOORBELLS_SIZE);
	if (muser_ep->doorbells == NULL) {
		err = -ENOMEM;
		goto out;
	}
#else
	muser_ep->doorbells = mmap(NULL, MUSER_DOORBELLS_SIZE,
				   PROT_READ | PROT_WRITE, MAP_SHARED, fd, DOORBELLS);
	if (muser_ep->doorbells == MAP_FAILED) {
		muser_ep->doorbells = NULL;
		err = -errno;
		goto out;
	}
#endif

	muser_ep->fd = fd;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: map doorbells %p\n", muser_ep->trid.traddr,
		      muser_ep->doorbells);

	dev_info.pvt = muser_ep;
	dev_info.uuid = muser_ep->trid.traddr;
	muser_dev_info_fill(&dev_info);

	muser_ep->lm_ctx = lm_ctx_create(&dev_info);
	if (muser_ep->lm_ctx == NULL) {
		/* TODO: lm_create doesn't set errno */
		SPDK_ERRLOG("%s: error creating libmuser context: %m\n",
			    muser_ep->trid.traddr);
		err = -1;
		goto out;
	}

	TAILQ_INSERT_TAIL(&muser_transport->endpoints, muser_ep, link);

out:
	if (err != 0) {
		muser_destroy_endpoint(muser_ep);
	}

	return muser_create_ctrlr(muser_transport, muser_ep);
}

static void
muser_stop_listen(struct spdk_nvmf_transport *transport,
		  const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_endpoint *muser_ep, *mtmp;
	char *id;
	int err;

	assert(trid != NULL);
	assert(trid->traddr != NULL);

	id = (char *)muser_ctrlr_id(trid->traddr);

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: stop listen\n", id);

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	/* FIXME should acquire lock */

	TAILQ_FOREACH_SAFE(muser_ep, &muser_transport->endpoints, link, mtmp) {
		if (strcmp(trid->traddr, muser_ep->trid.traddr) == 0) {
			TAILQ_REMOVE(&muser_transport->endpoints, muser_ep, link);
			if (muser_ep->ctrlr) {
				TAILQ_REMOVE(&muser_transport->ctrlrs, muser_ep->ctrlr, link);
				err = destroy_ctrlr(muser_ep->ctrlr);
				if (err != 0) {
					SPDK_ERRLOG("%s: failed destroy controller: %s\n",
						    muser_ep->ctrlr->id, strerror(-err));
				}
				muser_ep->ctrlr = NULL;
			}
			muser_destroy_endpoint(muser_ep);
		}
	}

	if (muser_ep == NULL) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s: not found\n", id);
	}
}

static void
_muser_notify_new_admin_qpair(void *ctx)
{
	struct muser_qpair *mqpair;
	struct spdk_nvmf_qpair *qpair;
	struct muser_ctrlr *mctrlr;

	mctrlr = ctx;
	assert(mctrlr != NULL);

	mqpair = mctrlr->qp[0];
	assert(mqpair != NULL);
	qpair = &mqpair->qpair;

	/* We're ready to show this new qpair to the upper layer. Remove it from
	 * our internal poll group. Currently there's no API to do that.
	 * TODO: Add an API. */
	assert(TAILQ_EMPTY(&qpair->outstanding));
	mctrlr->cntlid = qpair->ctrlr->cntlid;

	/* destroy the internal poll group created in muser_listen */
	spdk_nvmf_poll_group_remove(qpair);
	spdk_nvmf_poll_group_destroy(qpair->group, NULL, NULL);
	/* Queue the admin queue up so that it gets discovered and assigned to
	 * a poll group.
	 */
	pthread_mutex_lock(&mctrlr->transport->lock);
	TAILQ_INSERT_TAIL(&mctrlr->transport->new_qps, mqpair, link);
	pthread_mutex_unlock(&mctrlr->transport->lock);
}

static int
_muser_handle_admin_connect_rsp(struct muser_req *req, void *cb_arg)
{
	struct muser_ctrlr *mctrlr;

	mctrlr = cb_arg;
	assert(mctrlr != NULL);

	free(req->req.data);

	if (spdk_nvme_cpl_is_error(&req->req.rsp->nvme_cpl)) {
		mctrlr->cb_fn(mctrlr->cb_arg, -1);
		return -1;
	}

	mctrlr->cb_fn(mctrlr->cb_arg, 0);

	/* Send a message to ourself to allow the request handling stack
	 * to unwind before continuing. */
	spdk_thread_send_msg(spdk_get_thread(), _muser_notify_new_admin_qpair, mctrlr);

	return 0;
}

static void
muser_listen_associate(struct spdk_nvmf_transport *transport,
		       const struct spdk_nvmf_subsystem *subsystem,
		       const struct spdk_nvme_transport_id *trid,
		       spdk_nvmf_tgt_subsystem_listen_done_fn cb_fn,
		       void *cb_arg)
{
	struct muser_transport *mtransport;
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;
	struct muser_ctrlr *muser_ctrlr;
	struct spdk_nvmf_request *req;
	struct spdk_nvmf_fabric_connect_data *data;

	mtransport = SPDK_CONTAINEROF(transport, struct muser_transport, transport);

	/* Look up the controller using the UUID in the trid */
	TAILQ_FOREACH(muser_ctrlr, &mtransport->ctrlrs, link) {
		if (strncmp(muser_ctrlr->uuid, trid->traddr, sizeof(muser_ctrlr->uuid)) == 0) {
			break;
		}
	}

	if (muser_ctrlr == NULL) {
		cb_fn(cb_arg, -ENOENT);
		return;
	}

	muser_ctrlr->cb_fn = cb_fn;
	muser_ctrlr->cb_arg = cb_arg;

	/* Send a fabric connect */
	muser_qpair = muser_ctrlr->qp[0];

	muser_req = get_muser_req(muser_qpair);
	if (muser_req == NULL) {
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	req = &muser_req->req;
	req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->cmd->connect_cmd.cid = 0;
	req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
	req->cmd->connect_cmd.recfmt = 0;
	req->cmd->connect_cmd.sqsize = muser_qpair->qsize - 1;
	req->cmd->connect_cmd.qid = 0;

	req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
	req->data = calloc(1, req->length);
	if (req->data == NULL) {
		muser_req_free(req);
		cb_fn(cb_arg, -ENOMEM);
		return;
	}

	data = (struct spdk_nvmf_fabric_connect_data *)req->data;
	data->cntlid = 0xFFFF;
	snprintf(data->subnqn, sizeof(data->subnqn), "%s", spdk_nvmf_subsystem_get_nqn(subsystem));

	muser_req->cb_fn = _muser_handle_admin_connect_rsp;
	muser_req->cb_arg = muser_ctrlr;

	spdk_nvmf_ctrlr_connect(req);
}

/*
 * Executed periodically.
 *
 * XXX SPDK thread context.
 */
static uint32_t
muser_accept(struct spdk_nvmf_transport *transport)
{
	int err;
	struct muser_transport *muser_transport;
	struct muser_qpair *qp, *tmp_qp;
	struct muser_ctrlr *ctrlr;

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	err = pthread_mutex_lock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to lock poll group lock: %m\n");
		return -EFAULT;
	}

	/* FIXME this should be done properly using the list_done callback etc */
	TAILQ_FOREACH(ctrlr, &muser_transport->ctrlrs, link) {
		if (!ctrlr->initialized) {
			err = lm_ctx_try_attach(ctrlr->lm_ctx);
			if (err == -1) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) {
					continue;
				}
				SPDK_ERRLOG("%s: failed to attach: %m\n",
					    ctrlr->id);
				assert(false); /* FIXME */
				return -EFAULT;
			}
			err = pthread_create(&ctrlr->lm_thr, NULL, drive, ctrlr->lm_ctx);
			if (err != 0) {
				SPDK_ERRLOG("%s: failed to create lm_drive thread: %s\n",
					    ctrlr->id, strerror(err));
				assert(false); /* FIXME */
				return -EFAULT;
			}
			ctrlr->initialized = true;
		}
	}

	TAILQ_FOREACH_SAFE(qp, &muser_transport->new_qps, link, tmp_qp) {
		TAILQ_REMOVE(&muser_transport->new_qps, qp, link);
		spdk_nvmf_tgt_new_qpair(transport->tgt, &qp->qpair);
	}

	err = pthread_mutex_unlock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to lock poll group lock: %m\n");
		return -EFAULT;
	}

	return 0;
}

/* TODO what does this do? */
static void
muser_discover(struct spdk_nvmf_transport *transport,
	       struct spdk_nvme_transport_id *trid,
	       struct spdk_nvmf_discovery_log_page_entry *entry)
{ }

/* TODO when is this called? */
static struct spdk_nvmf_transport_poll_group *
muser_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct muser_poll_group *muser_group;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "create poll group\n");

	muser_group = calloc(1, sizeof(*muser_group));
	if (muser_group == NULL) {
		SPDK_ERRLOG("Error allocating poll group: %m");
		return NULL;
	}

	TAILQ_INIT(&muser_group->qps);

	return &muser_group->group;
}

/* called when process exits */
static void
muser_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "destroy poll group\n");

	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);

	free(muser_group);
}

static int
handle_io_queue_connect_rsp(struct muser_req *req, void *cb_arg)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *qpair = cb_arg;

	assert(qpair != NULL);
	assert(req != NULL);

	muser_group = SPDK_CONTAINEROF(qpair->group, struct muser_poll_group, group);
	TAILQ_INSERT_TAIL(&muser_group->qps, qpair, link);

	free(req->req.data);
	req->req.data = NULL;

	return 0;
}

/*
 * Called by spdk_nvmf_transport_poll_group_add.
 */
static int
muser_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
		     struct spdk_nvmf_qpair *qpair)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;
	struct muser_ctrlr *muser_ctrlr;
	struct spdk_nvmf_request *req;
	struct spdk_nvmf_fabric_connect_data *data;
	int err;

	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);
	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	muser_qpair->group = group;
	muser_ctrlr = muser_qpair->ctrlr;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: add QP%d=%p(%p) to poll_group=%p\n", muser_ctrlr->id,
		      muser_qpair->qpair.qid, muser_qpair, qpair, muser_group);

	if (nvmf_qpair_is_admin_queue(&muser_qpair->qpair)) {
		TAILQ_INSERT_TAIL(&muser_group->qps, muser_qpair, link);
		return 0;
	}

	muser_req = get_muser_req(muser_qpair);
	if (muser_req == NULL) {
		return -1;
	}

	req = &muser_req->req;
	req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->cmd->connect_cmd.cid = muser_req->cid;
	req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
	req->cmd->connect_cmd.recfmt = 0;
	req->cmd->connect_cmd.sqsize = muser_qpair->qsize - 1;
	req->cmd->connect_cmd.qid = qpair->qid;

	req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
	req->data = calloc(1, req->length);
	if (req->data == NULL) {
		err = -1;
		goto out;
	}

	data = (struct spdk_nvmf_fabric_connect_data *)req->data;
	data->cntlid = muser_ctrlr->cntlid;
	err = muser_snprintf_subnqn(muser_ctrlr, data->subnqn);
	if (err != 0) {
		goto out;
	}

	muser_req->cb_fn = handle_io_queue_connect_rsp;
	muser_req->cb_arg = muser_qpair;

	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: sending connect fabrics command for QID=%#x cntlid=%#x\n",
		      muser_ctrlr->id, qpair->qid, data->cntlid);

	spdk_nvmf_request_exec_fabrics(req);
out:
	if (err != 0) {
		free(req->data);
		muser_req_free(req);
	}
	return err;
}

static int
muser_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	struct muser_qpair *muser_qpair;
	struct muser_poll_group *muser_group;

	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);

	/* TODO maybe this is where we should delete the I/O queue? */
	SPDK_DEBUGLOG(SPDK_LOG_MUSER,
		      "%s: remove NVMf QP%d=%p from NVMf poll_group=%p\n",
		      muser_qpair->ctrlr->id, qpair->qid, qpair, group);


	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);

	TAILQ_REMOVE(&muser_group->qps, muser_qpair, link);

	return 0;
}

static int
map_admin_queue(struct muser_ctrlr *ctrlr)
{
	int err;

	assert(ctrlr != NULL);

	err = acq_map(ctrlr);
	if (err != 0) {
		SPDK_ERRLOG("%s: failed to map CQ0: %d\n", ctrlr->id, err);
		return err;
	}
	err = asq_map(ctrlr);
	if (err != 0) {
		SPDK_ERRLOG("%s: failed to map SQ0: %d\n", ctrlr->id, err);
		return err;
	}
	return 0;
}

static void
unmap_admin_queue(struct muser_ctrlr *ctrlr)
{
	assert(ctrlr->qp[0] != NULL);

	destroy_io_qp(ctrlr->qp[0]);
}

static int
handle_prop_rsp(struct muser_req *req, void *cb_arg)
{
	struct muser_qpair *qpair = cb_arg;
	int err = 0;

	assert(qpair != NULL);
	assert(req != NULL);

	if (qpair->ctrlr->prop_req.dir == MUSER_NVMF_READ) {
		assert(qpair->ctrlr != NULL);
		assert(req != NULL);

		memcpy(qpair->ctrlr->prop_req.buf,
		       &req->req.rsp->prop_get_rsp.value.u64,
		       qpair->ctrlr->prop_req.count);
	} else {
		assert(qpair->ctrlr->prop_req.dir == MUSER_NVMF_WRITE);

		assert(qpair->ctrlr != NULL);

		if (qpair->ctrlr->prop_req.pos == CC) {
			union spdk_nvme_cc_register *cc;

			assert(qpair->ctrlr != NULL);

			spdk_rmb();

			cc = (union spdk_nvme_cc_register *)qpair->ctrlr->prop_req.buf;

			if (cc->bits.en == 1 && cc->bits.shn == 0) {
				SPDK_DEBUGLOG(SPDK_LOG_MUSER,
					      "%s: MAP Admin queue\n",
					      qpair->ctrlr->id);
				qpair->ctrlr->prop_req.ret = map_admin_queue(qpair->ctrlr);
			} else if ((cc->bits.en == 0 && cc->bits.shn == 0) ||
				   (cc->bits.en == 1 && cc->bits.shn != 0)) {
				SPDK_DEBUGLOG(SPDK_LOG_MUSER,
					      "%s: UNMAP Admin queue\n",
					      qpair->ctrlr->id);
				unmap_admin_queue(qpair->ctrlr);
			}
		}
	}

	qpair->ctrlr->prop_req.dir = MUSER_NVMF_INVALID;
	err = sem_post(&qpair->ctrlr->prop_req.wait);

	return err;
}

static int
muser_req_free(struct spdk_nvmf_request *req)
{
	struct muser_qpair *qpair;
	struct muser_req *muser_req;

	assert(req != NULL);

	muser_req = SPDK_CONTAINEROF(req, struct muser_req, req);
	qpair = SPDK_CONTAINEROF(muser_req->req.qpair, struct muser_qpair, qpair);

	TAILQ_INSERT_TAIL(&qpair->reqs, muser_req, link);

	return 0;
}

static int
muser_req_complete(struct spdk_nvmf_request *req)
{
	struct muser_qpair *qpair;
	struct muser_req *muser_req;

	assert(req != NULL);

	muser_req = SPDK_CONTAINEROF(req, struct muser_req, req);
	qpair = SPDK_CONTAINEROF(muser_req->req.qpair, struct muser_qpair, qpair);

	if (muser_req->cb_fn != NULL) {
		if (muser_req->cb_fn(muser_req, muser_req->cb_arg) != 0) {
			fail_ctrlr(qpair->ctrlr);
		}
	}

	TAILQ_INSERT_TAIL(&qpair->reqs, muser_req, link);

	return 0;
}

static void
muser_close_qpair(struct spdk_nvmf_qpair *qpair)
{
	struct muser_qpair *muser_qpair;
	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);

	assert(qpair != NULL);

	/* TODO when is this called? */

	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	destroy_qp(muser_qpair->ctrlr, qpair->qid);
}

/**
 * Returns a preallocated spdk_nvmf_request or NULL if there isn't one available.
 *
 * TODO Since there are as many preallocated requests as slots in the queue, we
 * could avoid checking for empty list (assuming that this function is called
 * responsively), however we use spdk_nvmf_request for passing property requests
 * and we're not sure how many more. It's probably just one.
 */
static struct muser_req *
get_muser_req(struct muser_qpair *qpair)
{
	struct muser_req *req;

	assert(qpair != NULL);

	if (TAILQ_EMPTY(&qpair->reqs)) {
		return NULL;
	}

	req = TAILQ_FIRST(&qpair->reqs);
	TAILQ_REMOVE(&qpair->reqs, req, link);
	memset(&req->cmd, 0, sizeof(req->cmd));
	memset(&req->rsp, 0, sizeof(req->rsp));

	return req;
}

static struct spdk_nvmf_request *
get_nvmf_req(struct muser_qpair *qpair)
{
	struct muser_req *req = get_muser_req(qpair);
	if (req == NULL) {
		return NULL;
	}
	return &req->req;
}

static int
get_nvmf_io_req_length(struct spdk_nvmf_request *req)
{
	uint16_t nlb;
	uint32_t nsid;
	struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;
	struct spdk_nvmf_ctrlr *ctrlr = req->qpair->ctrlr;
	struct spdk_nvmf_ns *ns;

	nsid = cmd->nsid;
	nlb = (cmd->cdw12 & 0x0000ffffu) + 1;
	ns = _nvmf_subsystem_get_ns(ctrlr->subsys, nsid);
	if (ns == NULL || ns->bdev == NULL) {
		/* TODO how do we get struct muser_ctrlr here? */
		SPDK_ERRLOG("unsuccessful query for nsid %u\n",
			    cmd->nsid);
		return -EINVAL;
	}

	return nlb * spdk_bdev_get_block_size(ns->bdev);
}

static int
map_admin_cmd_req(struct muser_ctrlr *ctrlr, struct spdk_nvmf_request *req)
{
	struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;
	uint32_t len = 0;
	int iovcnt;

	req->xfer = cmd->opc & 0x3;
	req->length = 0;
	req->data = NULL;

	switch (cmd->opc) {
	case SPDK_NVME_OPC_IDENTIFY:
		len = 4096;
		break;
	case SPDK_NVME_OPC_GET_LOG_PAGE:
		len = (cmd->cdw10_bits.get_log_page.numdl + 1) * 4;
		break;
	}

	if (!cmd->dptr.prp.prp1 || !len) {
		return 0;
	}

	iovcnt = muser_map_prps(ctrlr, cmd, req->iov, len);
	if (iovcnt < 0) {
		SPDK_ERRLOG("%s: map Admin Opc %x failed\n", ctrlr->id, cmd->opc);
		return -1;
	}

	req->length = len;
	req->data = req->iov[0].iov_base;

	return 0;
}

/*
 * Handles an I/O command.
 *
 * Returns 0 on success and -errno on failure. Sets @submit on whether or not
 * the request must be forwarded to NVMf.
 */
static int
map_io_cmd_req(struct muser_ctrlr *ctrlr, struct spdk_nvmf_request *req)
{
	int err = 0;
	bool remap = true;

	assert(ctrlr != NULL);
	assert(req != NULL);

	switch (req->cmd->nvme_cmd.opc) {
	case SPDK_NVME_OPC_FLUSH:
		req->xfer = SPDK_NVME_DATA_NONE;
		remap = false;
		break;
	case SPDK_NVME_OPC_READ:
		req->xfer = SPDK_NVME_DATA_CONTROLLER_TO_HOST;
		break;
	case SPDK_NVME_OPC_WRITE:
		req->xfer = SPDK_NVME_DATA_HOST_TO_CONTROLLER;
		break;
	default:
		SPDK_ERRLOG("%s: SQ%d invalid I/O request type 0x%x\n",
			    ctrlr->id, req->qpair->qid, req->cmd->nvme_cmd.opc);
		return -EINVAL;
	}

	req->data = NULL;
	if (remap) {
		assert(is_prp(&req->cmd->nvme_cmd));
		err = get_nvmf_io_req_length(req);
		if (err < 0) {
			return -EINVAL;
		}

		req->length = err;
		err = muser_map_prps(ctrlr, &req->cmd->nvme_cmd, req->iov,
				     req->length);
		if (err < 0) {
			SPDK_ERRLOG("%s: failed to map PRP: %d\n", ctrlr->id,
				    err);
			return -EFAULT;
		}
		req->iovcnt = err;
		return 0;
	}

	return 0;
}

/* TODO find better name */
static int
handle_cmd_req(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
	       struct spdk_nvmf_request *req)
{
	int err;
	struct muser_req *muser_req;

	assert(ctrlr != NULL);
	assert(cmd != NULL);

	/*
	 * FIXME this means that there are not free requests available,
	 * returning -1 will fail the controller. Theoretically this error can
	 * be avoided completely by ensuring we have as many requests as slots
	 * in the SQ, plus one for the the property request.
	 */
	if (req == NULL) {
		return -1;
	}

	req->cmd->nvme_cmd = *cmd;
	if (nvmf_qpair_is_admin_queue(req->qpair)) {
		err = map_admin_cmd_req(ctrlr, req);
	} else {
		err = map_io_cmd_req(ctrlr, req);
	}

	if (err < 0) {
		SPDK_ERRLOG("%s: map NVMe command opc 0x%x failed\n",
			    ctrlr->id, cmd->opc);
		goto out;
	}

	muser_req = SPDK_CONTAINEROF(req, struct muser_req, req);
	muser_req->cb_fn = handle_cmd_rsp;
	muser_req->cb_arg = SPDK_CONTAINEROF(req->qpair, struct muser_qpair, qpair);

	spdk_nvmf_request_exec(req);

	return 0;

out:
	return post_completion(ctrlr, cmd, &ctrlr->qp[req->qpair->qid]->cq, 0,
			       SPDK_NVME_SC_INTERNAL_DEVICE_ERROR,
			       SPDK_NVME_SCT_GENERIC);
}

static int
muser_ctrlr_poll(struct muser_ctrlr *ctrlr)
{
	struct spdk_nvmf_request *req;
	struct muser_req *muser_req;
	int err = 0;

	if (ctrlr == NULL) {
		return 0;
	}

	if (ctrlr->prop_req.dir == MUSER_NVMF_INVALID) {
		return err;
	}

	assert(ctrlr != NULL);

	/* TODO: This should examine the prop_req and intercept
	 * register writes that aren't valid for fabrics devices like
	 * AQA. */

	req = get_nvmf_req(ctrlr->qp[0]);
	if (req == NULL) {
		return -1;
	}

	muser_req = SPDK_CONTAINEROF(req, struct muser_req, req);
	muser_req->cb_fn = handle_prop_rsp;
	muser_req->cb_arg = ctrlr->qp[0];

	/* Generate a fake fabrics property set command */
	req->cmd->prop_set_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->cmd->prop_set_cmd.cid = 0;
	req->cmd->prop_set_cmd.attrib.size = (ctrlr->prop_req.count / 4) - 1;
	req->cmd->prop_set_cmd.ofst = ctrlr->prop_req.pos;
	if (ctrlr->prop_req.dir == MUSER_NVMF_WRITE) {
		req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET;
		if (req->cmd->prop_set_cmd.attrib.size) {
			req->cmd->prop_set_cmd.value.u64 = *(uint64_t *)ctrlr->prop_req.buf;
		} else {
			req->cmd->prop_set_cmd.value.u32.high = 0;
			req->cmd->prop_set_cmd.value.u32.low = *(uint32_t *)ctrlr->prop_req.buf;
		}
	} else {
		req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_GET;
	}
	req->length = 0;
	req->data = NULL;

	spdk_nvmf_request_exec_fabrics(req);

	return 0;
}

static void
muser_qpair_poll(struct muser_qpair *qpair)
{
	struct muser_ctrlr *ctrlr;
	uint32_t new_tail;

	assert(qpair != NULL);

	ctrlr = qpair->ctrlr;

	new_tail = *tdbl(ctrlr, &qpair->sq);
	if (sq_head(qpair) != new_tail) {
		int err = handle_sq_tdbl_write(ctrlr, new_tail, qpair);
		if (err != 0) {
			fail_ctrlr(ctrlr);
			return;
		}
	}
}

/*
 * Called unconditionally, periodically, very frequently from SPDK to ask
 * whether there's work to be done.  This functions consumes requests generated
 * from read/write_bar0 by setting ctrlr->prop_req.dir.  read_bar0, and
 * occasionally write_bar0 -- though this may change, synchronously wait. This
 * function also consumes requests by looking at the doorbells.
 */
static int
muser_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair, *tmp;
	struct muser_ctrlr *ctrlr;

	assert(group != NULL);

	spdk_rmb();

	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);

	TAILQ_FOREACH_SAFE(muser_qpair, &muser_group->qps, link, tmp) {

		if (nvmf_qpair_is_admin_queue(&muser_qpair->qpair)) {
			ctrlr = muser_qpair->ctrlr;

			if (muser_ctrlr_poll(ctrlr) != 0) {
				fail_ctrlr(ctrlr);
				return -1;
			}
		}

		/*
		 * TODO In init_qp the last thing we do is to point
		 * ctrlr->qp[qid] to the newly allocated qpair, which isn't
		 * fully initialized yet, and then request NVMf to add it. A
		 * better way to check whether the queue has been initialized
		 * is not to add it to ctrlr->qp[qid], so we'd only have to
		 * check whether ctrlr->qp[qid] is NULL.
		 */
		if (muser_qpair->sq.size == 0) {
			continue;
		}

		/*
		 * TODO queue is being deleted, don't check. Maybe we earlier
		 * check regarding the queue size and this check could be
		 * consolidated into a single flag, e.g. 'active'?
		 */
		if (muser_qpair->del) {
			continue;
		}

		muser_qpair_poll(muser_qpair);

	}

	return 0;
}

static int
muser_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
			   struct spdk_nvme_transport_id *trid)
{
	struct muser_qpair *muser_qpair;
	struct muser_ctrlr *muser_ctrlr;

	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	muser_ctrlr = muser_qpair->ctrlr;

	memcpy(trid, &muser_ctrlr->endpoint->trid, sizeof(*trid));
	return 0;
}

static int
muser_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
			  struct spdk_nvme_transport_id *trid)
{
	return 0;
}

static int
muser_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
			    struct spdk_nvme_transport_id *trid)
{
	struct muser_qpair *muser_qpair;
	struct muser_ctrlr *muser_ctrlr;

	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	muser_ctrlr = muser_qpair->ctrlr;

	memcpy(trid, &muser_ctrlr->endpoint->trid, sizeof(*trid));
	return 0;
}

static void
muser_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth =		MUSER_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size =		MUSER_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		MUSER_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth =		MUSER_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers =	MUSER_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		MUSER_DEFAULT_BUFFER_CACHE_SIZE;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_muser = {
	.name = "muser",
	.type = SPDK_NVME_TRANSPORT_CUSTOM,
	.opts_init = muser_opts_init,
	.create = muser_create,
	.destroy = muser_destroy,

	.listen = muser_listen,
	.stop_listen = muser_stop_listen,
	.accept = muser_accept,
	.listen_associate = muser_listen_associate,

	.listener_discover = muser_discover,

	.poll_group_create = muser_poll_group_create,
	.poll_group_destroy = muser_poll_group_destroy,
	.poll_group_add = muser_poll_group_add,
	.poll_group_remove = muser_poll_group_remove,
	.poll_group_poll = muser_poll_group_poll,

	.req_free = muser_req_free,
	.req_complete = muser_req_complete,

	.qpair_fini = muser_close_qpair,
	.qpair_get_local_trid = muser_qpair_get_local_trid,
	.qpair_get_peer_trid = muser_qpair_get_peer_trid,
	.qpair_get_listen_trid = muser_qpair_get_listen_trid,
};

SPDK_NVMF_TRANSPORT_REGISTER(muser, &spdk_nvmf_transport_muser);
SPDK_LOG_REGISTER_COMPONENT("nvmf_muser", SPDK_LOG_NVMF_MUSER)
