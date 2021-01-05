/*-
 *   BSD LICENSE
 *   Copyright (c) Intel Corporation. All rights reserved.
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

/*
 * NVMe over vfio-user transport
 */

#include <vfio-user/libvfio-user.h>
#include <vfio-user/pci_defs.h>

#include "spdk/barrier.h"
#include "spdk/stdinc.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvmf_transport.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/util.h"
#include "spdk/log.h"

#include "transport.h"

#include "nvmf_internal.h"

#define NVMF_VFIO_USER_DEFAULT_MAX_QUEUE_DEPTH 256
#define NVMF_VFIO_USER_DEFAULT_AQ_DEPTH 32
#define NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR 64
#define NVMF_VFIO_USER_DEFAULT_IN_CAPSULE_DATA_SIZE 0
#define NVMF_VFIO_USER_DEFAULT_MAX_IO_SIZE 131072
#define NVMF_VFIO_USER_DEFAULT_IO_UNIT_SIZE 131072
#define NVMF_VFIO_USER_DEFAULT_NUM_SHARED_BUFFERS 512 /* internal buf size */
#define NVMF_VFIO_USER_DEFAULT_BUFFER_CACHE_SIZE 0

#define NVMF_VFIO_USER_DOORBELLS_OFFSET	0x1000
#define NVMF_VFIO_USER_DOORBELLS_SIZE 0x1000

#define NVME_REG_CFG_SIZE       0x1000
#define NVME_REG_BAR0_SIZE      0x4000
#define NVME_IRQ_INTX_NUM       1
#define NVME_IRQ_MSIX_NUM	NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR

struct nvmf_vfio_user_req;
struct nvmf_vfio_user_qpair;

typedef int (*nvmf_vfio_user_req_cb_fn)(struct nvmf_vfio_user_req *req, void *cb_arg);

#define NVMF_VFIO_USER_MDTS	32
#define NVMF_VFIO_USER_MAX_IOVECS	(NVMF_VFIO_USER_MDTS + 1)

struct nvmf_vfio_user_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			rsp;
	struct spdk_nvme_cmd			cmd;
	uint16_t				cid;

	nvmf_vfio_user_req_cb_fn		cb_fn;
	void					*cb_arg;

	dma_sg_t				sg[NVMF_VFIO_USER_MAX_IOVECS];
	struct iovec				iov[NVMF_VFIO_USER_MAX_IOVECS];
	uint8_t					iovcnt;

	TAILQ_ENTRY(nvmf_vfio_user_req)		link;
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

	uint32_t size;
	uint64_t prp1;

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

enum nvmf_vfio_user_qpair_state {
	VFIO_USER_QPAIR_UNINITIALIZED = 0,
	VFIO_USER_QPAIR_ACTIVE,
	VFIO_USER_QPAIR_DELETED,
	VFIO_USER_QPAIR_INACTIVE,
	VFIO_USER_QPAIR_ERROR,
};

struct nvmf_vfio_user_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_transport_poll_group	*group;
	struct nvmf_vfio_user_ctrlr		*ctrlr;
	struct nvmf_vfio_user_req		*reqs_internal;
	uint16_t				qsize; /* TODO aren't all queues the same size? */
	struct io_q				cq;
	struct io_q				sq;
	enum nvmf_vfio_user_qpair_state		state;

	TAILQ_HEAD(, nvmf_vfio_user_req)	reqs;
	TAILQ_ENTRY(nvmf_vfio_user_qpair)	link;
};

struct nvmf_vfio_user_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	TAILQ_HEAD(, nvmf_vfio_user_qpair)	qps;
};

struct nvmf_vfio_user_ctrlr {
	struct nvmf_vfio_user_endpoint		*endpoint;
	struct nvmf_vfio_user_transport		*transport;

	/* True when the admin queue is connected */
	bool					ready;

	uint16_t				cntlid;

	struct nvmf_vfio_user_qpair		*qp[NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR];

	TAILQ_ENTRY(nvmf_vfio_user_ctrlr)	link;

	/* even indices are SQ, odd indices are CQ */
	/* TODO this already exists in struct nvmf_vfio_user_endpoint */
	volatile uint32_t			*doorbells;

	/* internal CSTS.CFS register for vfio-user fatal errors */
	uint32_t				cfs : 1;
};

struct nvmf_vfio_user_endpoint {
	vfu_ctx_t				*vfu_ctx;
	struct msixcap				*msix;
	vfu_pci_config_space_t			*pci_config_space;
	int					fd;
	volatile uint32_t			*doorbells;

	struct spdk_nvme_transport_id		trid;
	const struct spdk_nvmf_subsystem	*subsystem;

	/* The current controller. NULL if nothing is
	 * currently attached. */
	struct nvmf_vfio_user_ctrlr		*ctrlr;

	TAILQ_ENTRY(nvmf_vfio_user_endpoint)	link;
};

struct nvmf_vfio_user_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	TAILQ_HEAD(, nvmf_vfio_user_endpoint)	endpoints;

	TAILQ_HEAD(, nvmf_vfio_user_qpair)	new_qps;
};

/*
 * function prototypes
 */
static volatile uint32_t *
hdbl(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q);

static volatile uint32_t *
tdbl(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q);

static int
nvmf_vfio_user_req_free(struct spdk_nvmf_request *req);

static struct nvmf_vfio_user_req *
get_nvmf_vfio_user_req(struct nvmf_vfio_user_qpair *qpair);

static int
post_completion(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
		struct io_q *cq, uint32_t cdw0, uint16_t sc,
		uint16_t sct);

static void
map_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len);

static int
unmap_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len);

static char *
endpoint_id(struct nvmf_vfio_user_endpoint *endpoint)
{
	return endpoint->trid.traddr;
}

static char *
ctrlr_id(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	if (!ctrlr || !ctrlr->endpoint) {
		return "Null Ctrlr";
	}

	return endpoint_id(ctrlr->endpoint);
}

/*
 * XXX We need a way to extract the queue ID from an io_q, which is already
 * available in nvmf_vfio_user_qpair->qpair.qid. Currently we store the type of the
 * queue within the queue, so retrieving the QID requires a comparison. Rather
 * than duplicating this information in struct io_q, we could store a pointer
 * to parent struct nvmf_vfio_user_qpair, however we would be using 8 bytes instead of
 * just 2 (uint16_t vs. pointer). This is only per-queue so it's not that bad.
 * Another approach is to define two types: struct io_cq { struct io_q q }; and
 * struct io_sq { struct io_q q; };. The downside would be that we would need
 * two almost identical functions to extract the QID.
 */
static uint16_t
io_q_id(struct io_q *q)
{

	struct nvmf_vfio_user_qpair *vfio_user_qpair;

	assert(q);

	if (q->is_cq) {
		vfio_user_qpair = SPDK_CONTAINEROF(q, struct nvmf_vfio_user_qpair, cq);
	} else {
		vfio_user_qpair = SPDK_CONTAINEROF(q, struct nvmf_vfio_user_qpair, sq);
	}
	assert(vfio_user_qpair);
	return vfio_user_qpair->qpair.qid;
}

static void
fail_ctrlr(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	assert(ctrlr != NULL);

	if (ctrlr->cfs == 0) {
		SPDK_ERRLOG(":%s failing controller\n", ctrlr_id(ctrlr));
	}

	ctrlr->cfs = 1U;
}

static bool
ctrlr_interrupt_enabled(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	assert(ctrlr != NULL);
	assert(ctrlr->endpoint != NULL);

	vfu_pci_config_space_t *pci = ctrlr->endpoint->pci_config_space;

	return (!pci->hdr.cmd.id || ctrlr->endpoint->msix->mxc.mxe);
}

static void
nvmf_vfio_user_destroy_endpoint(struct nvmf_vfio_user_endpoint *endpoint)
{
	if (endpoint->doorbells) {
		munmap((void *)endpoint->doorbells, NVMF_VFIO_USER_DOORBELLS_SIZE);
	}

	if (endpoint->fd > 0) {
		close(endpoint->fd);
	}

	vfu_destroy_ctx(endpoint->vfu_ctx);

	free(endpoint);
}

/* called when process exits */
static int
nvmf_vfio_user_destroy(struct spdk_nvmf_transport *transport,
		       spdk_nvmf_transport_destroy_done_cb cb_fn, void *cb_arg)
{
	struct nvmf_vfio_user_transport *vu_transport;
	struct nvmf_vfio_user_endpoint *endpoint, *tmp;

	SPDK_DEBUGLOG(nvmf_vfio, "destroy transport\n");

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport,
					transport);

	(void)pthread_mutex_destroy(&vu_transport->lock);

	TAILQ_FOREACH_SAFE(endpoint, &vu_transport->endpoints, link, tmp) {
		TAILQ_REMOVE(&vu_transport->endpoints, endpoint, link);
		nvmf_vfio_user_destroy_endpoint(endpoint);
	}

	free(vu_transport);

	if (cb_fn) {
		cb_fn(cb_arg);
	}

	return 0;
}

static struct spdk_nvmf_transport *
nvmf_vfio_user_create(struct spdk_nvmf_transport_opts *opts)
{
	struct nvmf_vfio_user_transport *vu_transport;
	int err;

	vu_transport = calloc(1, sizeof(*vu_transport));
	if (vu_transport == NULL) {
		SPDK_ERRLOG("Transport alloc fail: %m\n");
		return NULL;
	}

	err = pthread_mutex_init(&vu_transport->lock, NULL);
	if (err != 0) {
		SPDK_ERRLOG("Pthread initialisation failed (%d)\n", err);
		goto err;
	}

	TAILQ_INIT(&vu_transport->endpoints);
	TAILQ_INIT(&vu_transport->new_qps);

	return &vu_transport->transport;

err:
	free(vu_transport);

	return NULL;
}

static void
destroy_qp(struct nvmf_vfio_user_ctrlr *ctrlr, uint16_t qid);

static uint16_t
max_queue_size(struct nvmf_vfio_user_ctrlr const *ctrlr)
{
	assert(ctrlr != NULL);
	assert(ctrlr->qp[0] != NULL);
	assert(ctrlr->qp[0]->qpair.ctrlr != NULL);

	return ctrlr->qp[0]->qpair.ctrlr->vcprop.cap.bits.mqes + 1;
}

/* TODO this should be a libmuser public function */
static void *
map_one(vfu_ctx_t *ctx, uint64_t addr, uint64_t len, dma_sg_t *sg, struct iovec *iov)
{
	int ret;

	assert(ctx != NULL);
	assert(sg != NULL);
	assert(iov != NULL);

	ret = vfu_addr_to_sg(ctx, addr, len, sg, 1, PROT_READ | PROT_WRITE);
	if (ret != 1) {
		errno = ret;
		return NULL;
	}

	ret = vfu_map_sg(ctx, sg, iov, 1);
	if (ret != 0) {
		errno = ret;
		return NULL;
	}

	/* FIXME 0 might be a legitimate address, right? */
	assert(iov->iov_base != NULL);
	return iov->iov_base;
}

static uint32_t
sq_head(struct nvmf_vfio_user_qpair *qpair)
{
	assert(qpair != NULL);
	return qpair->sq.head;
}

static void
sqhd_advance(struct nvmf_vfio_user_ctrlr *ctrlr, struct nvmf_vfio_user_qpair *qpair)
{
	assert(ctrlr != NULL);
	assert(qpair != NULL);
	qpair->sq.head = (qpair->sq.head + 1) % qpair->sq.size;
}

static void
insert_queue(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q,
	     const bool is_cq, const uint16_t id)
{
	struct io_q *_q;
	struct nvmf_vfio_user_qpair *qpair;

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
asq_map(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	struct io_q q;
	const struct spdk_nvmf_registers *regs = spdk_nvmf_ctrlr_get_regs(ctrlr->qp[0]->qpair.ctrlr);

	assert(ctrlr != NULL);
	assert(ctrlr->qp[0]->sq.addr == NULL);
	/* XXX ctrlr->asq == 0 is a valid memory address */

	q.size = regs->aqa.bits.asqs + 1;
	q.head = ctrlr->doorbells[0] = 0;
	q.cqid = 0;
	q.addr = map_one(ctrlr->endpoint->vfu_ctx, regs->asq,
			 q.size * sizeof(struct spdk_nvme_cmd), &q.sg, &q.iov);
	if (q.addr == NULL) {
		SPDK_ERRLOG("Map ASQ failed, ASQ %"PRIx64", errno %d\n", regs->asq, errno);
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
tdbl(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q)
{
	assert(ctrlr != NULL);
	assert(q != NULL);
	assert(!q->is_cq);

	return &ctrlr->doorbells[queue_index(io_q_id(q), false)];
}

static volatile uint32_t *
hdbl(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q)
{
	assert(ctrlr != NULL);
	assert(q != NULL);
	assert(q->is_cq);

	return &ctrlr->doorbells[queue_index(io_q_id(q), true)];
}

static bool
cq_is_full(struct nvmf_vfio_user_ctrlr *ctrlr, struct io_q *q)
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
acq_map(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	struct io_q *q;
	const struct spdk_nvmf_registers *regs;

	assert(ctrlr != NULL);
	assert(ctrlr->qp[0] != NULL);
	assert(ctrlr->qp[0]->cq.addr == NULL);

	q = &ctrlr->qp[0]->cq;
	regs = spdk_nvmf_ctrlr_get_regs(ctrlr->qp[0]->qpair.ctrlr);
	assert(regs != NULL);
	assert(regs->acq != 0);

	q->size = regs->aqa.bits.acqs + 1;
	q->tail = 0;
	q->addr = map_one(ctrlr->endpoint->vfu_ctx, regs->acq,
			  q->size * sizeof(struct spdk_nvme_cpl), &q->sg, &q->iov);
	if (q->addr == NULL) {
		SPDK_ERRLOG("Map ACQ failed, ACQ %"PRIx64", errno %d\n", regs->acq, errno);
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
	struct nvmf_vfio_user_req *vu_req;
	struct nvmf_vfio_user_qpair *vu_qpair;
	void *ret;

	assert(prv != NULL);

	vu_req = SPDK_CONTAINEROF(prv, struct nvmf_vfio_user_req, cmd);
	vu_qpair = SPDK_CONTAINEROF(vu_req->req.qpair, struct nvmf_vfio_user_qpair, qpair);

	assert(vu_req->iovcnt < NVMF_VFIO_USER_MAX_IOVECS);
	ret = map_one(vu_qpair->ctrlr->endpoint->vfu_ctx, addr, len,
		      &vu_req->sg[vu_req->iovcnt],
		      &vu_req->iov[vu_req->iovcnt]);
	if (spdk_likely(ret != NULL)) {
		vu_req->iovcnt++;
	}
	return ret;
}

static int
vfio_user_map_prps(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
		   struct iovec *iov, uint32_t length)
{
	return spdk_nvme_map_prps(cmd, cmd, iov, length,
				  4096,
				  _map_one);
}

static struct spdk_nvmf_request *
get_nvmf_req(struct nvmf_vfio_user_qpair *qp);

static int
handle_cmd_req(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
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
 * @ctrlr: the vfio-user controller
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
post_completion(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
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
		SPDK_DEBUGLOG(nvmf_vfio,
			      "%s: ignore completion SQ%d cid=%d status=%#x\n",
			      ctrlr_id(ctrlr), qid, cmd->cid, sc);
		return 0;
	}

	if (cq_is_full(ctrlr, cq)) {
		SPDK_ERRLOG("%s: CQ%d full (tail=%d, head=%d)\n",
			    ctrlr_id(ctrlr), qid, cq->tail, *hdbl(ctrlr, cq));
		return -1;
	}

	cpl = ((struct spdk_nvme_cpl *)cq->addr) + cq->tail;

	SPDK_DEBUGLOG(nvmf_vfio,
		      "%s: request complete SQ%d cid=%d status=%#x SQ head=%#x CQ tail=%#x\n",
		      ctrlr_id(ctrlr), qid, cmd->cid, sc, ctrlr->qp[qid]->sq.head,
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
	 * might be triggerring interrupts from vfio-user thread context so
	 * check for race conditions.
	 */
	if (ctrlr_interrupt_enabled(ctrlr) && cq->ien) {
		err = vfu_irq_trigger(ctrlr->endpoint->vfu_ctx, cq->iv);
		if (err != 0) {
			SPDK_ERRLOG("%s: failed to trigger interrupt: %m\n",
				    ctrlr_id(ctrlr));
			return err;
		}
	}

	return 0;
}

static struct io_q *
lookup_io_q(struct nvmf_vfio_user_ctrlr *ctrlr, const uint16_t qid, const bool is_cq)
{
	struct io_q *q;

	assert(ctrlr != NULL);

	if (qid > NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
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
destroy_io_q(vfu_ctx_t *vfu_ctx, struct io_q *q)
{
	if (q == NULL) {
		return;
	}
	if (q->addr != NULL) {
		vfu_unmap_sg(vfu_ctx, &q->sg, &q->iov, 1);
		q->addr = NULL;
	}
}

static void
destroy_io_qp(struct nvmf_vfio_user_qpair *qp)
{
	if (qp->ctrlr == NULL) {
		return;
	}

	SPDK_DEBUGLOG(nvmf_vfio, "%s: destroy I/O QP%d\n",
		      ctrlr_id(qp->ctrlr), qp->qpair.qid);

	destroy_io_q(qp->ctrlr->endpoint->vfu_ctx, &qp->sq);
	destroy_io_q(qp->ctrlr->endpoint->vfu_ctx, &qp->cq);
}

static void
tear_down_qpair(struct nvmf_vfio_user_qpair *qpair)
{
	free(qpair->reqs_internal);
}

/*
 * TODO we can immediately remove the QP from the list because this function
 * is now executed by the SPDK thread.
 */
static void
destroy_qp(struct nvmf_vfio_user_ctrlr *ctrlr, uint16_t qid)
{
	struct nvmf_vfio_user_qpair *qpair;

	if (ctrlr == NULL) {
		return;
	}

	qpair = ctrlr->qp[qid];
	if (qpair == NULL) {
		return;
	}

	SPDK_DEBUGLOG(nvmf_vfio, "%s: destroy QP%d=%p\n", ctrlr_id(ctrlr),
		      qid, qpair);

	/*
	 * TODO Is it possible for the pointer to be accessed while we're
	 * tearing down the queue?
	 */
	destroy_io_qp(qpair);
	tear_down_qpair(qpair);
	ctrlr->qp[qid] = NULL;
}

/* This function can only fail because of memory allocation errors. */
static int
init_qp(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvmf_transport *transport,
	const uint16_t qsize, const uint16_t id)
{
	int err = 0, i;
	struct nvmf_vfio_user_qpair *qpair;
	struct nvmf_vfio_user_req *vu_req;
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

	qpair->reqs_internal = calloc(qsize, sizeof(struct nvmf_vfio_user_req));
	if (qpair->reqs_internal == NULL) {
		SPDK_ERRLOG("%s: error allocating reqs: %m\n", ctrlr_id(ctrlr));
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < qsize; i++) {
		vu_req = &qpair->reqs_internal[i];
		req = &vu_req->req;

		vu_req->cid = i;
		req->qpair = &qpair->qpair;
		req->rsp = (union nvmf_c2h_msg *)&vu_req->rsp;
		req->cmd = (union nvmf_h2c_msg *)&vu_req->cmd;

		TAILQ_INSERT_TAIL(&qpair->reqs, vu_req, link);
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
add_qp(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvmf_transport *transport,
       const uint16_t qsize, const uint16_t qid)
{
	int err;
	struct nvmf_vfio_user_transport *vu_transport;

	SPDK_DEBUGLOG(nvmf_vfio, "%s: request add QP%d\n",
		      ctrlr_id(ctrlr), qid);

	err = init_qp(ctrlr, transport, qsize, qid);
	if (err != 0) {
		return err;
	}

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport,
					transport);

	/*
	 * After we've returned from the nvmf_vfio_user_poll_group_poll thread, once
	 * nvmf_vfio_user_accept executes it will pick up this QP and will eventually
	 * call nvmf_vfio_user_poll_group_add. The rest of the opertions needed to
	 * complete the addition of the queue will be continued at the
	 * completion callback.
	 */
	TAILQ_INSERT_TAIL(&vu_transport->new_qps, ctrlr->qp[qid], link);

	return 0;
}

/*
 * Creates a completion or sumbission I/O queue. Returns 0 on success, -errno
 * on error.
 *
 * XXX SPDK thread context.
 */
static int
handle_create_io_q(struct nvmf_vfio_user_ctrlr *ctrlr,
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

	SPDK_DEBUGLOG(nvmf_vfio,
		      "%s: create I/O %cQ%d: QSIZE=%#x\n", ctrlr_id(ctrlr),
		      is_cq ? 'C' : 'S', cmd->cdw10_bits.create_io_q.qid,
		      cmd->cdw10_bits.create_io_q.qsize);

	if (cmd->cdw10_bits.create_io_q.qid >= NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		SPDK_ERRLOG("%s: invalid QID=%d, max=%d\n", ctrlr_id(ctrlr),
			    cmd->cdw10_bits.create_io_q.qid,
			    NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR);
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		goto out;
	}

	if (lookup_io_q(ctrlr, cmd->cdw10_bits.create_io_q.qid, is_cq)) {
		SPDK_ERRLOG("%s: %cQ%d already exists\n", ctrlr_id(ctrlr),
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
			SPDK_ERRLOG("%s: non-PC CQ not supporred\n", ctrlr_id(ctrlr));
			sc = SPDK_NVME_SC_INVALID_CONTROLLER_MEM_BUF;
			goto out;
		}
		io_q.ien = cmd->cdw11_bits.create_io_cq.ien;
		io_q.iv = cmd->cdw11_bits.create_io_cq.iv;
	} else {
		/* CQ must be created before SQ */
		if (!lookup_io_q(ctrlr, cmd->cdw11_bits.create_io_sq.cqid, true)) {
			SPDK_ERRLOG("%s: CQ%d does not exist\n", ctrlr_id(ctrlr),
				    cmd->cdw11_bits.create_io_sq.cqid);
			sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
			sc = SPDK_NVME_SC_COMPLETION_QUEUE_INVALID;
			goto out;
		}

		entry_size = sizeof(struct spdk_nvme_cmd);
		if (cmd->cdw11_bits.create_io_sq.pc != 0x1) {
			SPDK_ERRLOG("%s: non-PC SQ not supported\n", ctrlr_id(ctrlr));
			sc = SPDK_NVME_SC_INVALID_CONTROLLER_MEM_BUF;
			goto out;
		}

		io_q.cqid = cmd->cdw11_bits.create_io_sq.cqid;
		SPDK_DEBUGLOG(nvmf_vfio, "%s: SQ%d CQID=%d\n", ctrlr_id(ctrlr),
			      cmd->cdw10_bits.create_io_q.qid, io_q.cqid);
	}

	io_q.size = cmd->cdw10_bits.create_io_q.qsize + 1;
	if (io_q.size > max_queue_size(ctrlr)) {
		SPDK_ERRLOG("%s: queue too big, want=%d, max=%d\n", ctrlr_id(ctrlr),
			    io_q.size, max_queue_size(ctrlr));
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_SIZE;
		goto out;
	}

	io_q.addr = map_one(ctrlr->endpoint->vfu_ctx, cmd->dptr.prp.prp1,
			    io_q.size * entry_size, &io_q.sg, &io_q.iov);
	if (io_q.addr == NULL) {
		sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
		SPDK_ERRLOG("%s: failed to map I/O queue: %m\n", ctrlr_id(ctrlr));
		goto out;
	}
	io_q.prp1 = cmd->dptr.prp.prp1;
	memset(io_q.addr, 0, io_q.size * entry_size);

	SPDK_DEBUGLOG(nvmf_vfio, "%s: mapped %cQ%d IOVA=%#lx vaddr=%#llx\n",
		      ctrlr_id(ctrlr), is_cq ? 'C' : 'S',
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
handle_del_io_q(struct nvmf_vfio_user_ctrlr *ctrlr,
		struct spdk_nvme_cmd *cmd, const bool is_cq)
{
	uint16_t sct = SPDK_NVME_SCT_GENERIC;
	uint16_t sc = SPDK_NVME_SC_SUCCESS;

	SPDK_DEBUGLOG(nvmf_vfio, "%s: delete I/O %cQ: QID=%d\n",
		      ctrlr_id(ctrlr), is_cq ? 'C' : 'S',
		      cmd->cdw10_bits.delete_io_q.qid);

	if (lookup_io_q(ctrlr, cmd->cdw10_bits.delete_io_q.qid, is_cq) == NULL) {
		SPDK_ERRLOG("%s: %cQ%d does not exist\n", ctrlr_id(ctrlr),
			    is_cq ? 'C' : 'S', cmd->cdw10_bits.delete_io_q.qid);
		sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
		sc = SPDK_NVME_SC_INVALID_QUEUE_IDENTIFIER;
		goto out;
	}

	if (is_cq) {
		/* SQ must have been deleted first */
		if (ctrlr->qp[cmd->cdw10_bits.delete_io_q.qid]->state != VFIO_USER_QPAIR_DELETED) {
			SPDK_ERRLOG("%s: the associated SQ must be deleted first\n", ctrlr_id(ctrlr));
			sct = SPDK_NVME_SCT_COMMAND_SPECIFIC;
			sc = SPDK_NVME_SC_INVALID_QUEUE_DELETION;
			goto out;
		}
	} else {
		/*
		 * This doesn't actually delete the I/O queue, we can't
		 * do that anyway because NVMf doesn't support it. We're merely
		 * telling the poll_group_poll function to skip checking this
		 * queue. The only workflow this works is when CC.EN is set to
		 * 0 and we're stopping the subsystem, so we know that the
		 * relevant callbacks to destroy the queues will be called.
		 */
		assert(ctrlr->qp[cmd->cdw10_bits.delete_io_q.qid]->state == VFIO_USER_QPAIR_ACTIVE);
		ctrlr->qp[cmd->cdw10_bits.delete_io_q.qid]->state = VFIO_USER_QPAIR_DELETED;
	}

out:
	return post_completion(ctrlr, cmd, &ctrlr->qp[0]->cq, 0, sc, sct);
}

/* TODO need to honor the Abort Command Limit field */
static int
handle_abort_cmd(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	assert(ctrlr != NULL);

	SPDK_DEBUGLOG(nvmf_vfio, "%s: abort CID %u in SQID %u\n", ctrlr_id(ctrlr),
		      cmd->cdw10_bits.abort.cid, cmd->cdw10_bits.abort.sqid);

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
consume_admin_cmd(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	assert(ctrlr != NULL);
	assert(cmd != NULL);

	SPDK_DEBUGLOG(nvmf_vfio, "%s: handle admin req opc=%#x cid=%d\n",
		      ctrlr_id(ctrlr), cmd->opc, cmd->cid);

	switch (cmd->opc) {
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
	default:
		return handle_cmd_req(ctrlr, cmd, get_nvmf_req(ctrlr->qp[0]));
	}
}

static int
handle_cmd_rsp(struct nvmf_vfio_user_req *req, void *cb_arg)
{
	struct nvmf_vfio_user_qpair *qpair = cb_arg;
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

	vfu_unmap_sg(qpair->ctrlr->endpoint->vfu_ctx, req->sg, req->iov, req->iovcnt);

	return post_completion(qpair->ctrlr, &req->req.cmd->nvme_cmd,
			       &qpair->ctrlr->qp[req->req.qpair->qid]->cq,
			       req->req.rsp->nvme_cpl.cdw0,
			       req->req.rsp->nvme_cpl.status.sc,
			       req->req.rsp->nvme_cpl.status.sct);
}

static int
consume_cmd(struct nvmf_vfio_user_ctrlr *ctrlr, struct nvmf_vfio_user_qpair *qpair,
	    struct spdk_nvme_cmd *cmd)
{
	assert(qpair != NULL);
	if (nvmf_qpair_is_admin_queue(&qpair->qpair)) {
		return consume_admin_cmd(ctrlr, cmd);
	}

	return handle_cmd_req(ctrlr, cmd, get_nvmf_req(qpair));
}

static ssize_t
handle_sq_tdbl_write(struct nvmf_vfio_user_ctrlr *ctrlr, const uint32_t new_tail,
		     struct nvmf_vfio_user_qpair *qpair)
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

static int
map_admin_queue(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	int err;

	assert(ctrlr != NULL);

	err = acq_map(ctrlr);
	if (err != 0) {
		SPDK_ERRLOG("%s: failed to map CQ0: %d\n", ctrlr_id(ctrlr), err);
		return err;
	}
	err = asq_map(ctrlr);
	if (err != 0) {
		SPDK_ERRLOG("%s: failed to map SQ0: %d\n", ctrlr_id(ctrlr), err);
		return err;
	}
	return 0;
}

static void
unmap_admin_queue(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	assert(ctrlr->qp[0] != NULL);

	destroy_io_qp(ctrlr->qp[0]);
}

static int
nvmf_vfio_user_prop_req_rsp(struct nvmf_vfio_user_req *req, void *cb_arg)
{
	struct nvmf_vfio_user_qpair *qpair = cb_arg;

	assert(qpair != NULL);
	assert(req != NULL);

	if (req->req.cmd->prop_get_cmd.fctype == SPDK_NVMF_FABRIC_COMMAND_PROPERTY_GET) {
		assert(qpair->ctrlr != NULL);
		assert(req != NULL);

		memcpy(req->req.data,
		       &req->req.rsp->prop_get_rsp.value.u64,
		       req->req.length);
	} else {
		assert(req->req.cmd->prop_set_cmd.fctype == SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET);
		assert(qpair->ctrlr != NULL);

		if (req->req.cmd->prop_set_cmd.ofst == offsetof(struct spdk_nvme_registers, cc)) {
			union spdk_nvme_cc_register *cc;

			cc = (union spdk_nvme_cc_register *)&req->req.cmd->prop_set_cmd.value.u64;

			if (cc->bits.en == 1 && cc->bits.shn == 0) {
				SPDK_DEBUGLOG(nvmf_vfio,
					      "%s: MAP Admin queue\n",
					      ctrlr_id(qpair->ctrlr));
				map_admin_queue(qpair->ctrlr);
			} else if ((cc->bits.en == 0 && cc->bits.shn == 0) ||
				   (cc->bits.en == 1 && cc->bits.shn != 0)) {
				SPDK_DEBUGLOG(nvmf_vfio,
					      "%s: UNMAP Admin queue\n",
					      ctrlr_id(qpair->ctrlr));
				unmap_admin_queue(qpair->ctrlr);
			}
		}
	}

	qpair->ctrlr->ready = true;
	return 0;
}

/*
 * XXX Do NOT remove, see comment in access_bar0_fn.
 *
 * Handles a write at offset 0x1000 or more.
 *
 * DSTRD is set to fixed value 0 for NVMf.
 *
 */
static int
handle_dbl_access(struct nvmf_vfio_user_ctrlr *ctrlr, uint32_t *buf,
		  const size_t count, loff_t pos, const bool is_write)
{
	assert(ctrlr != NULL);
	assert(buf != NULL);

	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("%s: bad doorbell buffer size %ld\n",
			    ctrlr_id(ctrlr), count);
		return -EINVAL;
	}

	pos -= NVMF_VFIO_USER_DOORBELLS_OFFSET;

	/* pos must be dword aligned */
	if ((pos & 0x3) != 0) {
		SPDK_ERRLOG("%s: bad doorbell offset %#lx\n", ctrlr_id(ctrlr), pos);
		return -EINVAL;
	}

	/* convert byte offset to array index */
	pos >>= 2;

	if (pos > NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR * 2) {
		/*
		 * FIXME need to emit a "Write to Invalid Doorbell Register"
		 * asynchronous event
		 */
		SPDK_ERRLOG("%s: bad doorbell index %#lx\n", ctrlr_id(ctrlr), pos);
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
access_bar0_fn(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t pos,
	       bool is_write)
{
	struct nvmf_vfio_user_endpoint *endpoint = vfu_get_private(vfu_ctx);
	struct nvmf_vfio_user_ctrlr *ctrlr;
	struct nvmf_vfio_user_req *req;
	int ret;

	ctrlr = endpoint->ctrlr;

	SPDK_DEBUGLOG(nvmf_vfio,
		      "%s: bar0 %s ctrlr: %p, count=%zu, pos=%"PRIX64"\n",
		      endpoint_id(endpoint), is_write ? "write" : "read",
		      ctrlr, count, pos);

	if (pos >= NVMF_VFIO_USER_DOORBELLS_OFFSET) {
		/*
		 * XXX The fact that the doorbells can be memory mapped doesn't
		 * mean thath the client (VFIO in QEMU) is obliged to memory
		 * map them, it might still elect to access them via regular
		 * read/write.
		 */
		ret = handle_dbl_access(ctrlr, (uint32_t *)buf, count,
					pos, is_write);
		if (ret == 0) {
			return count;
		}
		assert(ret < 0);
		return ret;
	}

	/* Construct a Fabric Property Get/Set command and send it */
	req = get_nvmf_vfio_user_req(ctrlr->qp[0]);
	if (req == NULL) {
		return -1;
	}

	req->cb_fn = nvmf_vfio_user_prop_req_rsp;
	req->cb_arg = ctrlr->qp[0];
	req->req.cmd->prop_set_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->req.cmd->prop_set_cmd.cid = 0;
	req->req.cmd->prop_set_cmd.attrib.size = (count / 4) - 1;
	req->req.cmd->prop_set_cmd.ofst = pos;
	if (is_write) {
		req->req.cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET;
		if (req->req.cmd->prop_set_cmd.attrib.size) {
			req->req.cmd->prop_set_cmd.value.u64 = *(uint64_t *)buf;
		} else {
			req->req.cmd->prop_set_cmd.value.u32.high = 0;
			req->req.cmd->prop_set_cmd.value.u32.low = *(uint32_t *)buf;
		}
	} else {
		req->req.cmd->prop_get_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_GET;
	}
	req->req.length = count;
	req->req.data = buf;

	/* Mark the controller as busy to limit the queue depth for fabric get/set to 1 */
	ctrlr->ready = false;

	spdk_nvmf_request_exec_fabrics(&req->req);

	return count;
}

/*
 * NVMe driver reads 4096 bytes, which is the extended PCI configuration space
 * available on PCI-X 2.0 and PCI Express buses
 */
static ssize_t
access_pci_config(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
		  bool is_write)
{
	struct nvmf_vfio_user_endpoint *endpoint = vfu_get_private(vfu_ctx);

	if (is_write) {
		SPDK_ERRLOG("%s: write %#lx-%#lx not supported\n",
			    endpoint_id(endpoint), offset, offset + count);
		return -EINVAL;
	}

	if (offset + count > PCI_CFG_SPACE_EXP_SIZE) {
		SPDK_ERRLOG("%s: access past end of extended PCI configuration space, want=%ld+%ld, max=%d\n",
			    endpoint_id(endpoint), offset, count,
			    PCI_CFG_SPACE_EXP_SIZE);
		return -ERANGE;
	}

	memcpy(buf, ((unsigned char *)endpoint->pci_config_space) + offset, count);

	return count;
}

static void
vfio_user_log(vfu_ctx_t *vfu_ctx, int level, char const *msg)
{
	struct nvmf_vfio_user_endpoint *endpoint = vfu_get_private(vfu_ctx);

	if (level >= SPDK_LOG_DEBUG) {
		SPDK_DEBUGLOG(nvmf_vfio, "%s: %s", endpoint_id(endpoint), msg);
	} else if (level >= SPDK_LOG_NOTICE) {
		SPDK_NOTICELOG("%s: %s", endpoint_id(endpoint), msg);
	} else {
		SPDK_ERRLOG("%s: %s", endpoint_id(endpoint), msg);
	}
}

static void
init_pci_config_space(vfu_pci_config_space_t *p)
{
	/* MLBAR */
	p->hdr.bars[0].raw = 0x0;
	/* MUBAR */
	p->hdr.bars[1].raw = 0x0;

	/* vendor specific, let's set them to zero for now */
	p->hdr.bars[3].raw = 0x0;
	p->hdr.bars[4].raw = 0x0;
	p->hdr.bars[5].raw = 0x0;

	/* enable INTx */
	p->hdr.intr.ipin = 0x1;
}

static int
vfio_user_dev_info_fill(struct nvmf_vfio_user_endpoint *endpoint)
{
	int ret;
	vfu_ctx_t *vfu_ctx = endpoint->vfu_ctx;

	static vfu_cap_t pm = {
		.pm = {
			.hdr.id = PCI_CAP_ID_PM,
			.pmcs.nsfrst = 0x1
		}
	};
	static vfu_cap_t px = {
		.px = {
			.hdr.id = PCI_CAP_ID_EXP,
			.pxcaps.ver = 0x2,
			.pxdcap = {.per = 0x1, .flrc = 0x1},
			.pxdcap2.ctds = 0x1
		}
	};
	static vfu_cap_t msix = {
		.msix = {
			.hdr.id = PCI_CAP_ID_MSIX,
			.mxc.ts = NVME_IRQ_MSIX_NUM - 1,
			.mtab = {.tbir = 0x4, .to = 0x0},
			.mpba = {.pbir = 0x5, .pbao = 0x0}
		}
	};

	/* FIXME reversing the order of msix and px breaks it, figure out why */
	static vfu_cap_t *caps[] = {&pm, &msix, &px};
	static struct iovec sparse_mmap[] = {
		{
			.iov_base = (void *)NVMF_VFIO_USER_DOORBELLS_OFFSET,
			.iov_len = NVMF_VFIO_USER_DOORBELLS_SIZE,
		},
	};

	ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_EXPRESS, PCI_HEADER_TYPE_NORMAL, 0);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to initialize PCI\n", vfu_ctx);
		return ret;
	}
	vfu_pci_set_id(vfu_ctx, 0x4e58, 0x0001, 0, 0);
	/*
	 * 0x02, controller uses the NVM Express programming interface
	 * 0x08, non-volatile memory controller
	 * 0x01, mass storage controller
	 */
	vfu_pci_set_class(vfu_ctx, 0x01, 0x08, 0x02);

	ret = vfu_pci_setup_caps(vfu_ctx, caps, 3);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup cap list\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX, NVME_REG_CFG_SIZE,
			       access_pci_config, VFU_REGION_FLAG_RW, NULL, 0, -1);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup cfg\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX, NVME_REG_BAR0_SIZE,
			       access_bar0_fn, VFU_REGION_FLAG_RW | VFU_REGION_FLAG_MMAP,
			       sparse_mmap, 1, endpoint->fd);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup bar 0\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR4_REGION_IDX, PAGE_SIZE,
			       NULL, VFU_REGION_FLAG_RW, NULL, 0, -1);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup bar 4\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR5_REGION_IDX, PAGE_SIZE,
			       NULL, VFU_REGION_FLAG_RW, NULL, 0, -1);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup bar 5\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_device_dma_cb(vfu_ctx, map_dma, unmap_dma);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup dma callback\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup INTX\n", vfu_ctx);
		return ret;
	}

	ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_MSIX_IRQ, NVME_IRQ_MSIX_NUM);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to setup MSIX\n", vfu_ctx);
		return ret;
	}

	ret = vfu_realize_ctx(vfu_ctx);
	if (ret < 0) {
		SPDK_ERRLOG("vfu_ctx %p failed to realize\n", vfu_ctx);
		return ret;
	}

	endpoint->msix = (struct msixcap *)vfu_ctx_get_cap(endpoint->vfu_ctx,
			 PCI_CAP_ID_MSIX);
	assert(endpoint->msix != NULL);

	endpoint->pci_config_space = vfu_pci_get_config_space(endpoint->vfu_ctx);
	assert(endpoint->pci_config_space != NULL);
	init_pci_config_space(endpoint->pci_config_space);

	return 0;
}

static int
destroy_ctrlr(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	int i;

	if (ctrlr == NULL) {
		return 0;
	}

	for (i = 0; i < NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR; i++) {
		destroy_qp(ctrlr, i);
	}

	if (ctrlr->endpoint) {
		ctrlr->endpoint->ctrlr = NULL;
	}

	free(ctrlr);
	return 0;
}

static void
map_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len)
{
	struct nvmf_vfio_user_endpoint *endpoint = vfu_get_private(vfu_ctx);
	struct nvmf_vfio_user_ctrlr *ctrlr;
	struct nvmf_vfio_user_qpair *qpair;
	int i, ret;

	assert(endpoint != NULL);

	if (endpoint->ctrlr == NULL) {
		return;
	}

	ctrlr = endpoint->ctrlr;

	SPDK_DEBUGLOG(nvmf_vfio, "%s: map IOVA %#lx-%#lx\n",
		      ctrlr_id(ctrlr), iova, len);

	for (i = 0; i < NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR; i++) {
		qpair = ctrlr->qp[i];
		if (qpair == NULL) {
			continue;
		}

		if (qpair->state != VFIO_USER_QPAIR_INACTIVE) {
			continue;
		}

		if (nvmf_qpair_is_admin_queue(&qpair->qpair)) {
			ret = map_admin_queue(ctrlr);
			if (ret) {
				continue;
			}
			qpair->state = VFIO_USER_QPAIR_ACTIVE;
		} else {
			struct io_q *sq = &qpair->sq;
			struct io_q *cq = &qpair->cq;

			sq->addr = map_one(ctrlr->endpoint->vfu_ctx, sq->prp1, sq->size * 64, &sq->sg, &sq->iov);
			if (!sq->addr) {
				SPDK_NOTICELOG("Failed to map SQID %d %#lx-%#lx, will try again in next poll\n",
					       i, sq->prp1, sq->prp1 + sq->size * 64);
				continue;
			}
			cq->addr = map_one(ctrlr->endpoint->vfu_ctx, cq->prp1, cq->size * 16, &cq->sg, &cq->iov);
			if (!cq->addr) {
				SPDK_NOTICELOG("Failed to map CQID %d %#lx-%#lx, will try again in next poll\n",
					       i, cq->prp1, cq->prp1 + cq->size * 16);
				continue;
			}

			qpair->state = VFIO_USER_QPAIR_ACTIVE;
		}
	}
}

static int
unmap_dma(vfu_ctx_t *vfu_ctx, uint64_t iova, uint64_t len)
{

	struct nvmf_vfio_user_endpoint *endpoint = vfu_get_private(vfu_ctx);
	struct nvmf_vfio_user_ctrlr *ctrlr;
	int i;

	assert(endpoint != NULL);

	if (endpoint->ctrlr == NULL) {
		return 0;
	}

	ctrlr = endpoint->ctrlr;

	SPDK_DEBUGLOG(nvmf_vfio, "%s: unmap IOVA %#lx\n",
		      ctrlr_id(ctrlr), iova);

	for (i = 0; i < NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR; i++) {
		if (ctrlr->qp[i] == NULL) {
			continue;
		}
		if (ctrlr->qp[i]->cq.sg.dma_addr == iova ||
		    ctrlr->qp[i]->sq.sg.dma_addr == iova) {
			destroy_io_qp(ctrlr->qp[i]);
			ctrlr->qp[i]->state = VFIO_USER_QPAIR_INACTIVE;
		}
	}

	return 0;
}

static void
nvmf_vfio_user_create_ctrlr(struct nvmf_vfio_user_transport *transport,
			    struct nvmf_vfio_user_endpoint *endpoint)
{
	struct nvmf_vfio_user_ctrlr *ctrlr;
	int err;

	/* First, construct a vfio-user CUSTOM transport controller */
	ctrlr = calloc(1, sizeof(*ctrlr));
	if (ctrlr == NULL) {
		err = -ENOMEM;
		goto out;
	}
	ctrlr->cntlid = 0xffff;
	ctrlr->transport = transport;
	ctrlr->endpoint = endpoint;
	ctrlr->doorbells = endpoint->doorbells;

	endpoint->ctrlr = ctrlr;

	/* Then, construct an admin queue pair */
	err = init_qp(ctrlr, &transport->transport, NVMF_VFIO_USER_DEFAULT_AQ_DEPTH, 0);
	if (err != 0) {
		goto out;
	}

	/* Notify the generic layer about the new admin queue pair */
	TAILQ_INSERT_TAIL(&ctrlr->transport->new_qps, ctrlr->qp[0], link);

out:
	if (err != 0) {
		/*
		 * TODO this prints the whole path instead of
		 * <domain UUID>/<IOMMU group>, fix.
		 */
		SPDK_ERRLOG("%s: failed to create vfio-user controller: %s\n",
			    endpoint_id(endpoint), strerror(-err));
		if (destroy_ctrlr(ctrlr) != 0) {
			SPDK_ERRLOG("%s: failed to clean up\n",
				    endpoint_id(endpoint));
		}
	}
}

static int
nvmf_vfio_user_listen(struct spdk_nvmf_transport *transport,
		      const struct spdk_nvme_transport_id *trid,
		      struct spdk_nvmf_listen_opts *listen_opts)
{
	struct nvmf_vfio_user_transport *vu_transport;
	struct nvmf_vfio_user_endpoint *endpoint, *tmp;
	char *path = NULL;
	char uuid[PATH_MAX] = {};
	int fd;
	int err;

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport,
					transport);

	TAILQ_FOREACH_SAFE(endpoint, &vu_transport->endpoints, link, tmp) {
		/* Only compare traddr */
		if (strncmp(endpoint->trid.traddr, trid->traddr, sizeof(endpoint->trid.traddr)) == 0) {
			return -EEXIST;
		}
	}

	endpoint = calloc(1, sizeof(*endpoint));
	if (!endpoint) {
		return -ENOMEM;
	}

	endpoint->fd = -1;
	memcpy(&endpoint->trid, trid, sizeof(endpoint->trid));

	err = asprintf(&path, "%s/bar0", endpoint_id(endpoint));
	if (err == -1) {
		goto out;
	}

	fd = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd == -1) {
		SPDK_ERRLOG("%s: failed to open device memory at %s: %m\n",
			    endpoint_id(endpoint), path);
		err = fd;
		free(path);
		goto out;
	}
	free(path);

	err = ftruncate(fd, NVMF_VFIO_USER_DOORBELLS_OFFSET + NVMF_VFIO_USER_DOORBELLS_SIZE);
	if (err != 0) {
		goto out;
	}

	endpoint->doorbells = mmap(NULL, NVMF_VFIO_USER_DOORBELLS_SIZE,
				   PROT_READ | PROT_WRITE, MAP_SHARED, fd, NVMF_VFIO_USER_DOORBELLS_OFFSET);
	if (endpoint->doorbells == MAP_FAILED) {
		endpoint->doorbells = NULL;
		err = -errno;
		goto out;
	}

	endpoint->fd = fd;

	snprintf(uuid, PATH_MAX, "%s/cntrl", endpoint_id(endpoint));
	SPDK_DEBUGLOG(nvmf_vfio, "%s: doorbells %p\n", uuid, endpoint->doorbells);

	endpoint->vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, uuid, LIBVFIO_USER_FLAG_ATTACH_NB,
					   endpoint, VFU_DEV_TYPE_PCI);
	if (endpoint->vfu_ctx == NULL) {
		SPDK_ERRLOG("%s: error creating libmuser context: %m\n",
			    endpoint_id(endpoint));
		err = -1;
		goto out;
	}
	vfu_setup_log(endpoint->vfu_ctx, vfio_user_log,
		      SPDK_DEBUGLOG_FLAG_ENABLED("nvmf_vfio") ? SPDK_LOG_DEBUG : SPDK_LOG_ERROR);

	err = vfio_user_dev_info_fill(endpoint);
	if (err < 0) {
		goto out;
	}

	TAILQ_INSERT_TAIL(&vu_transport->endpoints, endpoint, link);

out:
	if (err != 0) {
		nvmf_vfio_user_destroy_endpoint(endpoint);
	}

	return err;
}

static void
nvmf_vfio_user_stop_listen(struct spdk_nvmf_transport *transport,
			   const struct spdk_nvme_transport_id *trid)
{
	struct nvmf_vfio_user_transport *vu_transport;
	struct nvmf_vfio_user_endpoint *endpoint, *tmp;
	int err;

	assert(trid != NULL);
	assert(trid->traddr != NULL);

	SPDK_DEBUGLOG(nvmf_vfio, "%s: stop listen\n", trid->traddr);

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport,
					transport);

	pthread_mutex_lock(&vu_transport->lock);
	TAILQ_FOREACH_SAFE(endpoint, &vu_transport->endpoints, link, tmp) {
		if (strcmp(trid->traddr, endpoint->trid.traddr) == 0) {
			TAILQ_REMOVE(&vu_transport->endpoints, endpoint, link);
			if (endpoint->ctrlr) {
				err = destroy_ctrlr(endpoint->ctrlr);
				if (err != 0) {
					SPDK_ERRLOG("%s: failed destroy controller: %s\n",
						    endpoint_id(endpoint), strerror(-err));
				}
			}
			nvmf_vfio_user_destroy_endpoint(endpoint);
			pthread_mutex_unlock(&vu_transport->lock);

			return;
		}
	}
	pthread_mutex_unlock(&vu_transport->lock);

	SPDK_DEBUGLOG(nvmf_vfio, "%s: not found\n", trid->traddr);
}

static int
nvmf_vfio_user_listen_associate(struct spdk_nvmf_transport *transport,
				const struct spdk_nvmf_subsystem *subsystem,
				const struct spdk_nvme_transport_id *trid)
{
	struct nvmf_vfio_user_transport *vu_transport;
	struct nvmf_vfio_user_endpoint *endpoint;

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport, transport);

	TAILQ_FOREACH(endpoint, &vu_transport->endpoints, link) {
		if (strncmp(endpoint->trid.traddr, trid->traddr, sizeof(endpoint->trid.traddr)) == 0) {
			break;
		}
	}

	if (endpoint == NULL) {
		return -ENOENT;
	}

	endpoint->subsystem = subsystem;

	return 0;
}

/*
 * Executed periodically.
 *
 * XXX SPDK thread context.
 */
static uint32_t
nvmf_vfio_user_accept(struct spdk_nvmf_transport *transport)
{
	int err;
	struct nvmf_vfio_user_transport *vu_transport;
	struct nvmf_vfio_user_qpair *qp, *tmp_qp;
	struct nvmf_vfio_user_endpoint *endpoint;

	vu_transport = SPDK_CONTAINEROF(transport, struct nvmf_vfio_user_transport,
					transport);

	pthread_mutex_lock(&vu_transport->lock);

	TAILQ_FOREACH(endpoint, &vu_transport->endpoints, link) {
		/* we need try to attach the controller again after reset or shutdown */
		if (endpoint->ctrlr != NULL && endpoint->ctrlr->ready) {
			continue;
		}

		err = vfu_attach_ctx(endpoint->vfu_ctx);
		if (err == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				continue;
			}

			pthread_mutex_unlock(&vu_transport->lock);
			return -EFAULT;
		}

		/* Construct a controller */
		nvmf_vfio_user_create_ctrlr(vu_transport, endpoint);
	}

	TAILQ_FOREACH_SAFE(qp, &vu_transport->new_qps, link, tmp_qp) {
		TAILQ_REMOVE(&vu_transport->new_qps, qp, link);
		spdk_nvmf_tgt_new_qpair(transport->tgt, &qp->qpair);
	}

	pthread_mutex_unlock(&vu_transport->lock);

	return 0;
}

static void
nvmf_vfio_user_discover(struct spdk_nvmf_transport *transport,
			struct spdk_nvme_transport_id *trid,
			struct spdk_nvmf_discovery_log_page_entry *entry)
{ }

static struct spdk_nvmf_transport_poll_group *
nvmf_vfio_user_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct nvmf_vfio_user_poll_group *vu_group;

	SPDK_DEBUGLOG(nvmf_vfio, "create poll group\n");

	vu_group = calloc(1, sizeof(*vu_group));
	if (vu_group == NULL) {
		SPDK_ERRLOG("Error allocating poll group: %m");
		return NULL;
	}

	TAILQ_INIT(&vu_group->qps);

	return &vu_group->group;
}

/* called when process exits */
static void
nvmf_vfio_user_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct nvmf_vfio_user_poll_group *vu_group;

	SPDK_DEBUGLOG(nvmf_vfio, "destroy poll group\n");

	vu_group = SPDK_CONTAINEROF(group, struct nvmf_vfio_user_poll_group, group);

	free(vu_group);
}

static int
handle_queue_connect_rsp(struct nvmf_vfio_user_req *req, void *cb_arg)
{
	struct nvmf_vfio_user_poll_group *vu_group;
	struct nvmf_vfio_user_qpair *qpair = cb_arg;
	struct nvmf_vfio_user_ctrlr *ctrlr;

	assert(qpair != NULL);
	assert(req != NULL);

	vu_group = SPDK_CONTAINEROF(qpair->group, struct nvmf_vfio_user_poll_group, group);
	TAILQ_INSERT_TAIL(&vu_group->qps, qpair, link);
	qpair->state = VFIO_USER_QPAIR_ACTIVE;

	ctrlr = qpair->ctrlr;
	assert(ctrlr != NULL);

	if (spdk_nvme_cpl_is_error(&req->req.rsp->nvme_cpl)) {
		SPDK_ERRLOG("SC %u, SCT %u\n", req->req.rsp->nvme_cpl.status.sc, req->req.rsp->nvme_cpl.status.sct);
		destroy_qp(ctrlr, qpair->qpair.qid);
		destroy_ctrlr(ctrlr);
		return -1;
	}

	if (nvmf_qpair_is_admin_queue(&qpair->qpair)) {
		ctrlr->cntlid = qpair->qpair.ctrlr->cntlid;
		ctrlr->ready = true;
	}

	free(req->req.data);
	req->req.data = NULL;

	return 0;
}

/*
 * Called by spdk_nvmf_transport_poll_group_add.
 */
static int
nvmf_vfio_user_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
			      struct spdk_nvmf_qpair *qpair)
{
	struct nvmf_vfio_user_qpair *vu_qpair;
	struct nvmf_vfio_user_req *vu_req;
	struct nvmf_vfio_user_ctrlr *ctrlr;
	struct spdk_nvmf_request *req;
	struct spdk_nvmf_fabric_connect_data *data;
	bool admin;

	vu_qpair = SPDK_CONTAINEROF(qpair, struct nvmf_vfio_user_qpair, qpair);
	vu_qpair->group = group;
	ctrlr = vu_qpair->ctrlr;

	SPDK_DEBUGLOG(nvmf_vfio, "%s: add QP%d=%p(%p) to poll_group=%p\n",
		      ctrlr_id(ctrlr), vu_qpair->qpair.qid,
		      vu_qpair, qpair, group);

	admin = nvmf_qpair_is_admin_queue(&vu_qpair->qpair);

	vu_req = get_nvmf_vfio_user_req(vu_qpair);
	if (vu_req == NULL) {
		return -1;
	}

	req = &vu_req->req;
	req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->cmd->connect_cmd.cid = vu_req->cid;
	req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
	req->cmd->connect_cmd.recfmt = 0;
	req->cmd->connect_cmd.sqsize = vu_qpair->qsize - 1;
	req->cmd->connect_cmd.qid = admin ? 0 : qpair->qid;

	req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
	req->data = calloc(1, req->length);
	if (req->data == NULL) {
		nvmf_vfio_user_req_free(req);
		return -ENOMEM;
	}

	data = (struct spdk_nvmf_fabric_connect_data *)req->data;
	data->cntlid = admin ? 0xFFFF : ctrlr->cntlid;
	snprintf(data->subnqn, sizeof(data->subnqn), "%s",
		 spdk_nvmf_subsystem_get_nqn(ctrlr->endpoint->subsystem));

	vu_req->cb_fn = handle_queue_connect_rsp;
	vu_req->cb_arg = vu_qpair;

	SPDK_DEBUGLOG(nvmf_vfio,
		      "%s: sending connect fabrics command for QID=%#x cntlid=%#x\n",
		      ctrlr_id(ctrlr), qpair->qid, data->cntlid);

	spdk_nvmf_request_exec_fabrics(req);
	return 0;
}

static int
nvmf_vfio_user_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
				 struct spdk_nvmf_qpair *qpair)
{
	struct nvmf_vfio_user_qpair *vu_qpair;
	struct nvmf_vfio_user_poll_group *vu_group;

	vu_qpair = SPDK_CONTAINEROF(qpair, struct nvmf_vfio_user_qpair, qpair);

	/* TODO maybe this is where we should delete the I/O queue? */
	SPDK_DEBUGLOG(nvmf_vfio,
		      "%s: remove NVMf QP%d=%p from NVMf poll_group=%p\n",
		      ctrlr_id(vu_qpair->ctrlr), qpair->qid, qpair, group);


	vu_group = SPDK_CONTAINEROF(group, struct nvmf_vfio_user_poll_group, group);

	TAILQ_REMOVE(&vu_group->qps, vu_qpair, link);

	return 0;
}

static int
nvmf_vfio_user_req_free(struct spdk_nvmf_request *req)
{
	struct nvmf_vfio_user_qpair *qpair;
	struct nvmf_vfio_user_req *vfio_user_req;

	assert(req != NULL);

	vfio_user_req = SPDK_CONTAINEROF(req, struct nvmf_vfio_user_req, req);
	qpair = SPDK_CONTAINEROF(vfio_user_req->req.qpair, struct nvmf_vfio_user_qpair, qpair);

	TAILQ_INSERT_TAIL(&qpair->reqs, vfio_user_req, link);

	return 0;
}

static int
nvmf_vfio_user_req_complete(struct spdk_nvmf_request *req)
{
	struct nvmf_vfio_user_qpair *qpair;
	struct nvmf_vfio_user_req *vfio_user_req;

	assert(req != NULL);

	vfio_user_req = SPDK_CONTAINEROF(req, struct nvmf_vfio_user_req, req);
	qpair = SPDK_CONTAINEROF(vfio_user_req->req.qpair, struct nvmf_vfio_user_qpair, qpair);

	if (vfio_user_req->cb_fn != NULL) {
		if (vfio_user_req->cb_fn(vfio_user_req, vfio_user_req->cb_arg) != 0) {
			fail_ctrlr(qpair->ctrlr);
		}
	}

	TAILQ_INSERT_TAIL(&qpair->reqs, vfio_user_req, link);

	return 0;
}

static void
nvmf_vfio_user_close_qpair(struct spdk_nvmf_qpair *qpair,
			   spdk_nvmf_transport_qpair_fini_cb cb_fn, void *cb_arg)
{
	struct nvmf_vfio_user_qpair *vu_qpair;

	assert(qpair != NULL);
	/* TODO when is this called? */
	vu_qpair = SPDK_CONTAINEROF(qpair, struct nvmf_vfio_user_qpair, qpair);
	destroy_qp(vu_qpair->ctrlr, qpair->qid);

	if (cb_fn) {
		cb_fn(cb_arg);
	}
}

/**
 * Returns a preallocated spdk_nvmf_request or NULL if there isn't one available.
 *
 * TODO Since there are as many preallocated requests as slots in the queue, we
 * could avoid checking for empty list (assuming that this function is called
 * responsively), however we use spdk_nvmf_request for passing property requests
 * and we're not sure how many more. It's probably just one.
 */
static struct nvmf_vfio_user_req *
get_nvmf_vfio_user_req(struct nvmf_vfio_user_qpair *qpair)
{
	struct nvmf_vfio_user_req *req;

	assert(qpair != NULL);

	if (TAILQ_EMPTY(&qpair->reqs)) {
		return NULL;
	}

	req = TAILQ_FIRST(&qpair->reqs);
	TAILQ_REMOVE(&qpair->reqs, req, link);
	memset(&req->cmd, 0, sizeof(req->cmd));
	memset(&req->rsp, 0, sizeof(req->rsp));
	req->iovcnt = 0;

	return req;
}

static struct spdk_nvmf_request *
get_nvmf_req(struct nvmf_vfio_user_qpair *qpair)
{
	struct nvmf_vfio_user_req *req = get_nvmf_vfio_user_req(qpair);
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
		/* TODO how do we get struct nvmf_vfio_user_ctrlr here? */
		SPDK_ERRLOG("unsuccessful query for nsid %u\n",
			    cmd->nsid);
		return -EINVAL;
	}

	return nlb * spdk_bdev_get_block_size(ns->bdev);
}

static int
map_admin_cmd_req(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvmf_request *req)
{
	struct spdk_nvme_cmd *cmd = &req->cmd->nvme_cmd;
	uint32_t len = 0;
	int iovcnt;

	req->xfer = cmd->opc & 0x3;
	req->length = 0;
	req->data = NULL;

	switch (cmd->opc) {
	case SPDK_NVME_OPC_IDENTIFY:
		len = 4096; /* FIXME there should be a define somewhere for this */
		break;
	case SPDK_NVME_OPC_GET_LOG_PAGE:
		len = (cmd->cdw10_bits.get_log_page.numdl + 1) * 4;
		break;
	}

	if (!cmd->dptr.prp.prp1 || !len) {
		return 0;
	}

	iovcnt = vfio_user_map_prps(ctrlr, cmd, req->iov, len);
	if (iovcnt < 0) {
		SPDK_ERRLOG("%s: map Admin Opc %x failed\n",
			    ctrlr_id(ctrlr), cmd->opc);
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
map_io_cmd_req(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvmf_request *req)
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
			    ctrlr_id(ctrlr), req->qpair->qid,
			    req->cmd->nvme_cmd.opc);
		return -EINVAL;
	}

	req->data = NULL;
	if (remap) {
		assert(req->cmd->nvme_cmd.psdt == 0);
		err = get_nvmf_io_req_length(req);
		if (err < 0) {
			return -EINVAL;
		}

		req->length = err;
		err = vfio_user_map_prps(ctrlr, &req->cmd->nvme_cmd, req->iov,
					 req->length);
		if (err < 0) {
			SPDK_ERRLOG("%s: failed to map PRP: %d\n",
				    ctrlr_id(ctrlr), err);
			return -EFAULT;
		}
		req->iovcnt = err;
	}

	return 0;
}

/* TODO find better name */
static int
handle_cmd_req(struct nvmf_vfio_user_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
	       struct spdk_nvmf_request *req)
{
	int err;
	struct nvmf_vfio_user_req *vfio_user_req;

	assert(ctrlr != NULL);
	assert(cmd != NULL);

	/*
	 * FIXME this means that there are no free requests available,
	 * returning -1 will fail the controller. Theoretically this error can
	 * be avoided completely by ensuring we have as many requests as slots
	 * in the SQ, plus one for the the property request.
	 */
	if (spdk_unlikely(req == NULL)) {
		return -1;
	}

	vfio_user_req = SPDK_CONTAINEROF(req, struct nvmf_vfio_user_req, req);
	vfio_user_req->cb_fn = handle_cmd_rsp;
	vfio_user_req->cb_arg = SPDK_CONTAINEROF(req->qpair, struct nvmf_vfio_user_qpair, qpair);
	req->cmd->nvme_cmd = *cmd;
	if (nvmf_qpair_is_admin_queue(req->qpair)) {
		err = map_admin_cmd_req(ctrlr, req);
	} else {
		err = map_io_cmd_req(ctrlr, req);
	}

	if (spdk_unlikely(err < 0)) {
		SPDK_ERRLOG("%s: map NVMe command opc 0x%x failed\n",
			    ctrlr_id(ctrlr), cmd->opc);
		req->rsp->nvme_cpl.status.sc = SPDK_NVME_SC_INTERNAL_DEVICE_ERROR;
		req->rsp->nvme_cpl.status.sct = SPDK_NVME_SCT_GENERIC;
		return handle_cmd_rsp(vfio_user_req, vfio_user_req->cb_arg);
	}

	spdk_nvmf_request_exec(req);

	return 0;
}

static int
nvmf_vfio_user_ctrlr_poll(struct nvmf_vfio_user_ctrlr *ctrlr)
{
	if (ctrlr == NULL) {
		return 0;
	}

	/* This will call access_bar0_fn() if there are any writes
	 * to the portion of the BAR that is not mmap'd */
	return vfu_run_ctx(ctrlr->endpoint->vfu_ctx);
}

static void
nvmf_vfio_user_qpair_poll(struct nvmf_vfio_user_qpair *qpair)
{
	struct nvmf_vfio_user_ctrlr *ctrlr;
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
nvmf_vfio_user_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct nvmf_vfio_user_poll_group *vu_group;
	struct nvmf_vfio_user_qpair *vu_qpair, *tmp;
	struct nvmf_vfio_user_ctrlr *ctrlr;

	assert(group != NULL);

	spdk_rmb();

	vu_group = SPDK_CONTAINEROF(group, struct nvmf_vfio_user_poll_group, group);

	TAILQ_FOREACH_SAFE(vu_qpair, &vu_group->qps, link, tmp) {
		ctrlr = vu_qpair->ctrlr;
		if (!ctrlr->ready) {
			continue;
		}

		if (nvmf_qpair_is_admin_queue(&vu_qpair->qpair)) {
			int err;

			err = nvmf_vfio_user_ctrlr_poll(ctrlr);
			if (spdk_unlikely(err) != 0) {
				if (err == -ENOTCONN) {
					TAILQ_REMOVE(&vu_group->qps, vu_qpair, link);
					ctrlr->ready = false;
					continue;
				}

				/*
				 * FIXME now that the controller has failed, do
				 * we just remove from this list all queue pairs
				 * that belong to this controller? Or do we
				 * completely destroy the controller? Or do we
				 * just destroy the queues?
				 */
				fail_ctrlr(ctrlr);
				return -1;
			}
		}

		if (vu_qpair->state != VFIO_USER_QPAIR_ACTIVE || !vu_qpair->sq.size) {
			continue;
		}

		nvmf_vfio_user_qpair_poll(vu_qpair);
	}

	return 0;
}

static int
nvmf_vfio_user_qpair_get_local_trid(struct spdk_nvmf_qpair *qpair,
				    struct spdk_nvme_transport_id *trid)
{
	struct nvmf_vfio_user_qpair *vu_qpair;
	struct nvmf_vfio_user_ctrlr *ctrlr;

	vu_qpair = SPDK_CONTAINEROF(qpair, struct nvmf_vfio_user_qpair, qpair);
	ctrlr = vu_qpair->ctrlr;

	memcpy(trid, &ctrlr->endpoint->trid, sizeof(*trid));
	return 0;
}

static int
nvmf_vfio_user_qpair_get_peer_trid(struct spdk_nvmf_qpair *qpair,
				   struct spdk_nvme_transport_id *trid)
{
	return 0;
}

static int
nvmf_vfio_user_qpair_get_listen_trid(struct spdk_nvmf_qpair *qpair,
				     struct spdk_nvme_transport_id *trid)
{
	struct nvmf_vfio_user_qpair *vu_qpair;
	struct nvmf_vfio_user_ctrlr *ctrlr;

	vu_qpair = SPDK_CONTAINEROF(qpair, struct nvmf_vfio_user_qpair, qpair);
	ctrlr = vu_qpair->ctrlr;

	memcpy(trid, &ctrlr->endpoint->trid, sizeof(*trid));
	return 0;
}

static void
nvmf_vfio_user_opts_init(struct spdk_nvmf_transport_opts *opts)
{
	opts->max_queue_depth =		NVMF_VFIO_USER_DEFAULT_MAX_QUEUE_DEPTH;
	opts->max_qpairs_per_ctrlr =	NVMF_VFIO_USER_DEFAULT_MAX_QPAIRS_PER_CTRLR;
	opts->in_capsule_data_size =	NVMF_VFIO_USER_DEFAULT_IN_CAPSULE_DATA_SIZE;
	opts->max_io_size =		NVMF_VFIO_USER_DEFAULT_MAX_IO_SIZE;
	opts->io_unit_size =		NVMF_VFIO_USER_DEFAULT_IO_UNIT_SIZE;
	opts->max_aq_depth =		NVMF_VFIO_USER_DEFAULT_AQ_DEPTH;
	opts->num_shared_buffers =	NVMF_VFIO_USER_DEFAULT_NUM_SHARED_BUFFERS;
	opts->buf_cache_size =		NVMF_VFIO_USER_DEFAULT_BUFFER_CACHE_SIZE;
}

const struct spdk_nvmf_transport_ops spdk_nvmf_transport_vfio_user = {
	.name = "vfio-user",
	.type = SPDK_NVME_TRANSPORT_CUSTOM,
	.opts_init = nvmf_vfio_user_opts_init,
	.create = nvmf_vfio_user_create,
	.destroy = nvmf_vfio_user_destroy,

	.listen = nvmf_vfio_user_listen,
	.stop_listen = nvmf_vfio_user_stop_listen,
	.accept = nvmf_vfio_user_accept,
	.listen_associate = nvmf_vfio_user_listen_associate,

	.listener_discover = nvmf_vfio_user_discover,

	.poll_group_create = nvmf_vfio_user_poll_group_create,
	.poll_group_destroy = nvmf_vfio_user_poll_group_destroy,
	.poll_group_add = nvmf_vfio_user_poll_group_add,
	.poll_group_remove = nvmf_vfio_user_poll_group_remove,
	.poll_group_poll = nvmf_vfio_user_poll_group_poll,

	.req_free = nvmf_vfio_user_req_free,
	.req_complete = nvmf_vfio_user_req_complete,

	.qpair_fini = nvmf_vfio_user_close_qpair,
	.qpair_get_local_trid = nvmf_vfio_user_qpair_get_local_trid,
	.qpair_get_peer_trid = nvmf_vfio_user_qpair_get_peer_trid,
	.qpair_get_listen_trid = nvmf_vfio_user_qpair_get_listen_trid,
};

SPDK_NVMF_TRANSPORT_REGISTER(muser, &spdk_nvmf_transport_vfio_user);
SPDK_LOG_REGISTER_COMPONENT(nvmf_vfio)
