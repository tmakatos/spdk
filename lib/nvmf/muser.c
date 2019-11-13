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
#include <muser/caps/msi.h>
#include <muser/caps/msix.h>

#include "spdk/barrier.h"
#include "spdk/stdinc.h"
#include "spdk/assert.h"
#include "spdk/thread.h"
#include "spdk/nvme_spec.h"
#include "spdk/nvmf.h"
#include "spdk/nvmf_spec.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/util.h"

#include "nvmf_internal.h"
#include "transport.h"

#include "spdk_internal/log.h"

struct nvme_pcie_mlbar {
	uint32_t rte :	1;
	uint32_t tp :	2;
	uint32_t pf :	1;
	uint32_t res1 :	10;
	uint32_t ba :	16;
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_pcie_mlbar) == sizeof(uint32_t), "Invalid size");

struct nvme_pcie_bar2 {
	uint32_t rte :	1;
	uint32_t res1 :	2;
	uint32_t ba :	29;
};
SPDK_STATIC_ASSERT(sizeof(struct nvme_pcie_bar2) == sizeof(uint32_t), "Bad NVMe BAR2 size");

struct spdk_log_flag SPDK_LOG_MUSER = {.enabled = true};

#define MUSER_DEFAULT_MAX_QUEUE_DEPTH 256
#define MUSER_DEFAULT_AQ_DEPTH 32
#define MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR 64
#define MUSER_DEFAULT_IN_CAPSULE_DATA_SIZE 0
#define MUSER_DEFAULT_MAX_IO_SIZE 131072
#define MUSER_DEFAULT_IO_UNIT_SIZE 131072
#define MUSER_DEFAULT_NUM_SHARED_BUFFERS 512 /* internal buf size */
#define MUSER_DEFAULT_BUFFER_CACHE_SIZE 0

#define NVME_REG_CFG_SIZE       0x1000
#define NVME_REG_BAR0_SIZE      0x4000

#define NVME_IRQ_INTX_NUM       1
#define NVME_IRQ_MSI_NUM       	2
#define NVME_IRQ_MSIX_NUM       32

enum muser_nvmf_dir {
	MUSER_NVMF_INVALID,
	MUSER_NVMF_READ,
	MUSER_NVMF_WRITE
};

struct muser_req  {
	struct spdk_nvmf_request		req;
	struct spdk_nvme_cpl			*rsp;
	struct spdk_nvme_cmd			*cmd;

	TAILQ_ENTRY(muser_req)			link;
};

struct muser_nvmf_prop_req {
	enum muser_nvmf_dir			dir;
	sem_t					wait;
	char					*buf;
	size_t					count;
	loff_t					pos;
	ssize_t					ret;
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

	/*
	 * FIXME move to parent struct muser_qpair? There's already qsize therenvme_config_space,
	 * duplicate?
	 */
	uint32_t size;

	union {
		struct {
			uint32_t tdbl;
			uint16_t head;
			uint32_t old_tail;
			/* multiple SQs can be mapped to the same CQ */
			uint16_t cqid;
		} sq;
		struct {
			uint32_t hdbl;
			uint32_t tail;
			uint16_t iv;
			bool ien;
		} cq;
	};
};

struct muser_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_muser_poll_group	*group;
	struct muser_ctrlr			*ctrlr;
	struct spdk_nvme_cmd			*cmd;
	struct muser_req			*reqs_internal;
	union nvmf_h2c_msg			*cmds_internal;
	union nvmf_c2h_msg			*rsps_internal;
	uint16_t				qsize;
	struct io_q				cq;
	struct io_q				sq;

	/* Internal command for spoofing register reads/writes. */
	struct muser_nvmf_prop_req		prop_req;

	TAILQ_HEAD(, muser_req)			reqs;
	TAILQ_ENTRY(muser_qpair)		link;
};

/*
 * XXX We need a way to extract the queue ID from an io_q, which is already
 * available in muser_qpair->qpair.qid. Currently we stored the type of the
 * queue within the queue, so retrieving the QID requires a comparison. Rather
 * than duplicating this information in struct io_q, we could store a pointer
 * to parent struct muser_qpair, however we would be using 8 bytes instead of
 * just 2 (uint16_t vs. pointer). This is only per-queue so it's not that bad.
 * Another approach is to define two types: struct io_cq { struct io_q q }; and
 * struct io_sq { struct io_q q; };. The downside would be that we would need
 * two almost identical functions to extract the QID.
 */
static uint16_t
io_q_id(struct io_q *q) {

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

struct muser_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	TAILQ_HEAD(, muser_qpair)		qps;
};

struct muser_ctrlr {
	struct spdk_nvme_transport_id		trid;
	char					uuid[37]; /* TODO 37 is already defined somewhere */
	pthread_t				lm_thr;
	lm_ctx_t				*lm_ctx;
	lm_pci_config_space_t			*pci_config_space;

	/* NB the doorbell member is not used for the admin SQ/CQ */
	struct spdk_nvme_registers		regs;

	/* PCI capabilities */
	struct pmcap				pmcap;
	struct msicap				msicap;
	struct msixcap				msixcap;
	struct pxcap				pxcap;

	uint16_t				cntlid;

	struct muser_qpair			qp[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR];

	TAILQ_ENTRY(muser_ctrlr)		link;
};

struct muser_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	struct muser_poll_group			*group;
	TAILQ_HEAD(, muser_ctrlr)		ctrlrs;

	TAILQ_HEAD(, muser_qpair)		new_qps;
};

static int
muser_destroy(struct spdk_nvmf_transport *transport)
{
	struct muser_transport *muser_transport;

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	(void)pthread_mutex_destroy(&muser_transport->lock);

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

	TAILQ_INIT(&muser_transport->ctrlrs);
	TAILQ_INIT(&muser_transport->new_qps);

	return &muser_transport->transport;

err:
	free(muser_transport);

	return NULL;
}

#define MDEV_CREATE_PATH "/sys/class/muser/muser/mdev_supported_types/muser-1/create"

static void
mdev_remove(const char *uuid)
{ /* TODO: Implement me */ }

static int
mdev_create(const char *uuid)
{
	int fd;
	int err;

	fd = open(MDEV_CREATE_PATH, O_WRONLY);
	if (fd == -1) {
		SPDK_ERRLOG("Error opening '%s': %m\n", MDEV_CREATE_PATH);
		return -1;
	}

	err = write(fd, uuid, strlen(uuid));
	if (err != (int)strlen(uuid)) {
		SPDK_ERRLOG("Error creating device '%s': %m\n", uuid);
		err = -1;
	} else {
		err = 0;
	}

	(void)close(fd);

	sleep(1);

	/* TODO: Wait until ctrlr appears on /ctrlr/muser/<uuid> */

	return err;
}

static ssize_t
read_nvme_cap(struct muser_ctrlr const *ctrlr, char *buf,
	 const size_t count, loff_t pos)
{
	/*
	 * FIXME need to validate count and pos
	 * FIXME is it OK to read it like that? Do we need to submit a request
	 * to the NVMf layer?
	 * TODO this line is far too long
	 */
	assert(ctrlr);
	memcpy(buf, ((uint8_t *)&ctrlr->qp[0].qpair.ctrlr->vcprop.cap.raw) + pos - offsetof(
		       struct spdk_nvme_registers, cap), count);
	return 0;
}

static bool
is_nvme_cap(const loff_t pos)
{
	const size_t off = offsetof(struct spdk_nvme_registers, cap);
	return (size_t)pos >= off && (size_t)pos < off + sizeof(uint64_t);
}

static int
handle_dbl_access(struct muser_ctrlr *ctrlr, uint8_t const *buf,
		  const size_t count, const loff_t pos, const bool is_write);

/*
 * FIXME read_bar0 and write_bar0 are very similar, merge
 */
static ssize_t
read_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_ctrlr *muser_ctrlr = pvt;
	int err;

	SPDK_NOTICELOG("ctrlr: %p, count=%zu, pos=%"PRIX64"\n",
		       muser_ctrlr, count, pos);

	/*
	 * NVMe CAP is 8 bytes long however the driver reads it 4 bytes at a
	 * time. NVMf doesn't like this.
	 */
	if (is_nvme_cap(pos)) {
		return read_nvme_cap(muser_ctrlr, buf, count, pos);
	}

	/* FIXME */
	if (pos >= DOORBELLS) {
		return handle_dbl_access(muser_ctrlr, buf, count,  pos, false);
	}

	muser_ctrlr->qp[0].prop_req.buf = buf;
	/* TODO: count must never be more than 8, otherwise we need to split it */
	muser_ctrlr->qp[0].prop_req.count = count;
	muser_ctrlr->qp[0].prop_req.pos = pos;
	spdk_wmb();
	muser_ctrlr->qp[0].prop_req.dir = MUSER_NVMF_READ;

	do {
		err = sem_wait(&muser_ctrlr->qp[0].prop_req.wait);
	} while (err != 0 && errno != EINTR);

	return muser_ctrlr->qp[0].prop_req.ret;
}

static uint16_t
max_queue_size(struct muser_ctrlr const *ctrlr)
{
	return ctrlr->qp[0].qpair.ctrlr->vcprop.cap.bits.mqes + 1;
}

static ssize_t
aqa_write(struct muser_ctrlr *ctrlr,
	  union spdk_nvme_aqa_register const *from)
{
	assert(ctrlr);
	assert(from);

	if (from->bits.asqs + 1 > max_queue_size(ctrlr) ||
	    from->bits.acqs + 1 > max_queue_size(ctrlr)) {
		SPDK_ERRLOG("admin queue(s) too big, ASQS=%d, ACQS=%d, max=%d\n",
			    from->bits.asqs + 1, from->bits.acqs + 1,
			    max_queue_size(ctrlr));
		return -EINVAL;
	}
	ctrlr->regs.aqa.raw = from->raw;
	SPDK_NOTICELOG("write to AQA %x\n", ctrlr->regs.aqa.raw);
	return 0;
}

static void
write_partial(uint8_t const *buf, const loff_t pos, const size_t count,
	      const size_t reg_off, uint64_t *reg)
{
	memcpy(reg + pos - reg_off, buf, count);
}

/*
 * Tells whether either the lower 4 bytes are written at the beginning of the
 * 8-byte register, or the higher 4 starting at the middle.
 */
static inline bool
_is_half(const size_t p, const size_t c, const size_t o)
{
	return c == sizeof(uint32_t) && (p == o || (p == o + sizeof(uint32_t)));
}

/*
 * Tells whether the full 8 bytes are written at the correct offset.
 */
static inline bool
_is_full(const size_t p, const size_t c, const size_t o)
{
	return c == sizeof(uint64_t) && p == o;
}

/*
 * Either write or lower/upper 4 bytes, or the full 8 bytes.
 *
 * p: position
 * c: count
 * o: register offset
 */
static inline bool
is_valid_asq_or_acq_write(const size_t p, const size_t c, const size_t o)
{
	return _is_half(p, c, o) || _is_full(p, c, o);
}

static ssize_t
asq_or_acq_write(uint8_t const *buf, const loff_t pos,
		 const size_t count, uint64_t *reg, const size_t reg_off)
{
	/*
	 * The NVMe driver seems to write those only in 4 upper/lower bytes, but
	 * we still have to support writing the whole register in one go.
	 */
	if (!is_valid_asq_or_acq_write((size_t)pos, count, reg_off)) {
		SPDK_ERRLOG("bad write count %zu and/or offset 0x%lx\n",
			    count, reg_off);
		return -EINVAL;
	}

	write_partial(buf, pos, count, reg_off, reg);

	return 0;
}

static ssize_t
asq_write(uint64_t *asq, uint8_t const *buf,
	  const loff_t pos, const size_t count)
{
	int ret = asq_or_acq_write(buf, pos, count, asq,
				   offsetof(struct spdk_nvme_registers, asq));
	SPDK_NOTICELOG("ASQ=0x%lx\n", *asq);
	return ret;
}

static ssize_t
acq_write(uint64_t *acq, uint8_t const *buf,
	  const loff_t pos, const size_t count)
{
	int ret = asq_or_acq_write(buf, pos, count, acq,
				   offsetof(struct spdk_nvme_registers, acq));
	SPDK_NOTICELOG("ACQ=0x%lx\n", *acq);
	return ret;
}

#define REGISTER_RANGE(name, size) \
	offsetof(struct spdk_nvme_registers, name) ... \
		offsetof(struct spdk_nvme_registers, name) + size - 1

#define ASQ \
	REGISTER_RANGE(asq, sizeof(uint64_t))

#define ACQ \
	REGISTER_RANGE(acq, sizeof(uint64_t))

#define ADMIN_QUEUES \
	offsetof(struct spdk_nvme_registers, aqa) ... \
		offsetof(struct spdk_nvme_registers, acq) + sizeof(uint64_t) - 1

static ssize_t
admin_queue_write(struct muser_ctrlr *ctrlr, uint8_t const *buf,
		  const size_t count, const loff_t pos)
{
	switch (pos) {
	case offsetof(struct spdk_nvme_registers, aqa):
		return aqa_write(ctrlr,
				 (union spdk_nvme_aqa_register *)buf);
	case ASQ:
		return asq_write(&ctrlr->regs.asq, buf, pos, count);
	case ACQ:
		return acq_write(&ctrlr->regs.acq, buf, pos, count);
	default:
		break;
	}
	SPDK_ERRLOG("bad admin queue write offset 0x%lx\n", pos);
	return -EINVAL;
}

/* TODO this should be a libmuser public function */
static void *
map_one(void *prv, uint64_t addr, uint64_t len)
{
	dma_sg_t sg[1];
	struct iovec iov;
	int ret;
	lm_ctx_t *ctx = (lm_ctx_t*)prv;

	ret = lm_addr_to_sg(ctx, addr, len, sg, 1);
	if (ret != 1) {
		SPDK_ERRLOG("failed to map 0x%lx-0x%lx\n", addr, addr + len);
		return NULL;
	}

	ret = lm_map_sg(ctx, PROT_READ | PROT_WRITE, sg, &iov, 1);
	if (ret != 0) {
		SPDK_ERRLOG("failed to map segment: %d\n", ret);
		return NULL;
	}

	return iov.iov_base;
}

static uint32_t
sq_tail(struct muser_ctrlr const *d, struct io_q const *q)
{
	assert(q);
	return q->sq.old_tail % q->size;
}

static void
sq_tail_advance(struct muser_ctrlr const *d, struct io_q *q)
{
	assert(q);
	assert(d);
	q->sq.old_tail = (sq_tail(d, q) + 1) % q->size;
}

static void
insert_queue(struct muser_ctrlr *ctrlr, struct io_q *q,
	     const bool is_cq, const uint16_t id)
{

	assert(ctrlr != NULL);
	assert(q != NULL);

	q->is_cq = is_cq;
	if (is_cq) {
		ctrlr->qp[id].cq = *q;
	} else {
		ctrlr->qp[id].sq = *q;
	}
}

static int
asq_map(struct muser_ctrlr *d)
{
	struct io_q q;

	assert(d);
	assert(!d->qp[0].sq.addr);
	/* XXX ctrlr->regs.asq == 0 is a valid memory address */

	q.size = d->regs.aqa.bits.asqs + 1;
	q.sq.old_tail = 0;
	q.sq.head = q.sq.tdbl = 0;
	q.sq.cqid = 0;
	q.addr = map_one(d->lm_ctx, d->regs.asq,
			 q.size * sizeof(struct spdk_nvme_cmd));
	if (!q.addr) {
		return -1;
	}
	insert_queue(d, &q, false, 0);
	return 0;
}

static uint16_t
cq_next(struct muser_ctrlr *d, struct io_q *q)
{
	assert(d);
	assert(q);
	return (q->cq.tail + 1) % q->size;
}

static bool
cq_is_full(struct muser_ctrlr *d, struct io_q *q)
{
	assert(d);
	assert(q);
	return cq_next(d, q) == q->cq.hdbl;
}

static void
cq_tail_advance(struct muser_ctrlr *d, struct io_q *q)
{
	assert(d);
	assert(q);
	q->cq.tail = cq_next(d, q);
}

static int
acq_map(struct muser_ctrlr *d)
{
	struct io_q *q;

	assert(d != NULL);
	assert(d->qp[0].cq.addr == NULL);
	assert(d->regs.acq != 0);

	q = &d->qp[0].cq;

	q->size = d->regs.aqa.bits.acqs + 1;
	q->cq.tail = 0;
	q->addr = map_one(d->lm_ctx, d->regs.acq,
			  q->size * sizeof(struct spdk_nvme_cpl));
	if (q->addr == NULL) {
		return -1;
	}
	q->is_cq = true;
	return 0;
}

static ssize_t
host_mem_page_size(uint8_t mps)
{
	/*
	 * only 4 lower bits can be set
	 * TODO this function could go into core SPDK
	 */
	if (0xf0 & mps) {
		return -EINVAL;
	}
	return 1 << (12 + mps);
}

static int
muser_map_prps(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
               struct iovec *iov, uint32_t length)
{
	return spdk_nvme_map_prps(ctrlr->lm_ctx, cmd, iov, length,
	                          host_mem_page_size(ctrlr->regs.cc.bits.mps), /* TODO don't compute this every time, store it in ctrlr */
	                          map_one);
}

/*
 * Maps a DPTR (currently a single page PRP) to our virtual memory.
 */
static int
dptr_remap(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd, size_t size)
{
	struct iovec iov;

	assert(ctrlr);
	assert(cmd);

	/* FIXME implement */
	assert(!cmd->dptr.prp.prp2);

	if (muser_map_prps(ctrlr, cmd, &iov, size) != 1) {
		return -1;
	}
	cmd->dptr.prp.prp1 = (uint64_t)iov.iov_base >> ctrlr->regs.cc.bits.mps;
	return 0;
}

#ifdef DEBUG
/* TODO does such a function already exist in SPDK? */
static bool
is_prp(struct spdk_nvme_cmd *cmd)
{
	return cmd->psdt == 0;
}
#endif

/* FIXME rename function, it handles more opcodes other than identify */
static int
handle_identify_req(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	int err;

	assert(ctrlr);
	assert(cmd);

	/* FIXME ensure it's PRP, implement for SGL */
	assert(is_prp(cmd));

	/*
	 * FIXME why do we specify size sizeof(struct spdk_nvme_cmd)? Check the
	 * spec.
	 */
	err = dptr_remap(ctrlr, cmd, sizeof(struct spdk_nvme_cmd));
	if (err) {
		SPDK_ERRLOG("failed to remap DPTR: %d\n", err);
		return -1;
	}

	ctrlr->qp[0].cmd = cmd;
	spdk_wmb();
	ctrlr->qp[0].prop_req.dir = MUSER_NVMF_READ; /* FIXME shouldn't this be MUSER_NVMF_READ? */

	return 0;
}

/*
 * TODO move into nvme_spec.h and change nvme_pcie_ctrlr_cmd_create_io_cq to
 * use it, also check for other functions
 */
union __attribute__((packed)) spdk_nvme_create_io_q_cdw10 {
	uint32_t raw;
	struct __attribute__((packed)) {
		uint32_t qid	: 16;
		uint32_t qsize	: 16;
	} bits;
};
SPDK_STATIC_ASSERT(sizeof(union spdk_nvme_create_io_q_cdw10) == 4, "Incorrect size");

union __attribute__((packed)) spdk_nvme_create_io_cq_cdw11 {
	uint32_t raw;
	struct __attribute__((packed)) {
		uint32_t pc		: 1;
		uint32_t ien		: 1;
		uint32_t reserved	: 14;
		uint32_t iv		: 16;

	} bits;
};
SPDK_STATIC_ASSERT(sizeof(union spdk_nvme_create_io_cq_cdw11) == 4, "Incorrect size");

union __attribute__((packed)) spdk_nvme_create_io_sq_cdw11 {
	uint32_t raw;
	struct __attribute__((packed)) {
		uint32_t pc		: 1;
		uint32_t qprio		: 2;
		uint32_t reserved	: 13;
		uint32_t cqid		: 16;
	} bits;
};
SPDK_STATIC_ASSERT(sizeof(union spdk_nvme_create_io_sq_cdw11) == 4, "Incorrect size");

/*
 * Completes a admin request.
 */
static int
do_admin_queue_complete(struct muser_ctrlr *d, struct spdk_nvme_cmd *cmd,
                        struct io_q *cq, struct spdk_nvmf_request *req)
{
	struct spdk_nvme_cpl *cpl;
	uint16_t qid;

	assert(d);
	assert(cmd);

	qid = io_q_id(cq);

	if (cq_is_full(d, cq)) {
		SPDK_ERRLOG("CQ%d full (tail=%d, head=%d)\n",
			    qid, cq->cq.tail, cq->cq.hdbl);
		return -1;
	}

	cpl = ((struct spdk_nvme_cpl *)cq->addr) + cq->cq.tail;

	/*
	 * FIXME intercept controller ID, we'll need it for converting a create
	 * I/O queue command to a fabric connect command. We assume that the
	 * will have issued the identify command first before attempting to
	 * create the I/O queues, so we'll have a chance to intercept it. This
	 * is a hack, and racy. Fix.
	 */
	if (qid == 0) {
		switch (cmd->opc) {
		case SPDK_NVME_OPC_IDENTIFY:
			if ((cmd->cdw10 & 0xFF) == SPDK_NVME_IDENTIFY_CTRLR && !d->cntlid) {
				struct spdk_nvme_ctrlr_data *p =
					(struct spdk_nvme_ctrlr_data *)cmd->dptr.prp.prp1;
				d->cntlid = p->cntlid;
				SPDK_DEBUGLOG(SPDK_LOG_MUSER,
			        	      "FIXME intercepted controlled ID %d\n",
				              d->cntlid);
			}
			break;
		case SPDK_NVME_OPC_SET_FEATURES:
			assert(req != NULL);
			SPDK_DEBUGLOG(SPDK_LOG_MUSER, "XXX number of queues=%#x\n",
			              req->rsp->nvme_cpl.cdw0);
			cpl->cdw0 = req->rsp->nvme_cpl.cdw0;
			break;
		}
	}

	cpl->sqhd = d->qp[qid].sq.sq.head;
	cpl->cid = cmd->cid;
	cpl->status.dnr = 0x0;
	cpl->status.m = 0x0;
	cpl->status.sct = 0x0;
	cpl->status.p = ~cpl->status.p; /* FIXME */
	cpl->status.sc = 0x0;

	cq_tail_advance(d, cq);

	if (qid != 0) {
		/*
		 * FIXME check STS.IS "Indicates the interrupt status of the device (‘1’ = asserted)."
		 */
		int err = lm_irq_trigger(d->lm_ctx, cq->cq.iv);
		if (err != 0) {
			SPDK_ERRLOG("failed to trigger interrupt: %m\n");
			return err;
		}
	}

	return 0;
}

/*
 * Completes a request by placing a completion response in the completion queue.
 * FIXME rename function this now handles completions for I/O queues as well.
 */
static int
admin_queue_complete(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd,
                     struct io_q *cq, struct spdk_nvmf_request *req)
{
	uint16_t qid;

	assert(ctrlr);
	assert(cmd);

	qid = io_q_id(cq);

	if (qid == 0 && ctrlr->qp[0].cq.addr == NULL) {
		int ret = acq_map(ctrlr);
		if (ret) {
			SPDK_ERRLOG("failed to map CQ0: %d\n", ret);
			return -1;
		}
	}
	do_admin_queue_complete(ctrlr, cmd, cq, req); /* FIXME check return value */
	return 0;
}

static struct io_q *
lookup_io_q(struct muser_ctrlr *ctrlr, const uint16_t qid, const bool is_cq)
{
	struct io_q *q;

	assert(ctrlr);

	if (qid > MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		return NULL;
	}

	if (is_cq) {
		q = &ctrlr->qp[qid].cq;
	} else {
		q = &ctrlr->qp[qid].sq;
	}

	/*
	 * XXX ASQ and ACQ are lazily mapped, see relevant comment in
	 * handle_sq0tdbl_write
	 */
	if (!q->addr && qid) {
		return NULL;
	}

	return q;
}

static void
destroy_qp(struct muser_qpair *qp)
{
	if (!qp) {
		return;
	}
	free(qp->reqs_internal);
	qp->reqs_internal = NULL;
	free(qp->cmds_internal);
	qp->cmds_internal = NULL;
	free(qp->rsps_internal);
	qp->rsps_internal = NULL;
}

static int
init_qp(struct muser_ctrlr *ctrlr, struct muser_qpair *qp,
	struct spdk_nvmf_transport *transport, const uint16_t qsize,
	const uint16_t id)
{
	int err = 0, i;

	assert(ctrlr);
	assert(qp);
	assert(transport);

	qp->qpair.qid = id;
	qp->qpair.transport = transport;
	qp->ctrlr = ctrlr;
	qp->qsize = qsize;

	TAILQ_INIT(&qp->reqs);

	qp->rsps_internal = calloc(qsize, sizeof(union nvmf_c2h_msg));
	if (qp->rsps_internal == NULL) {
		SPDK_ERRLOG("Error allocating rsps: %m\n");
		err = -ENOMEM;
		goto out;
	}

	qp->cmds_internal = calloc(qsize, sizeof(union nvmf_h2c_msg));
	if (qp->cmds_internal == NULL) {
		SPDK_ERRLOG("Error allocating cmds: %m\n");
		err = -ENOMEM;
		goto out;
	}

	qp->reqs_internal = calloc(qsize, sizeof(struct muser_req));
	if (qp->reqs_internal == NULL) {
		SPDK_ERRLOG("Error allocating reqs: %m\n");
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < qsize; i++) {
		qp->reqs_internal[i].req.qpair = &qp->qpair;
		qp->reqs_internal[i].req.rsp = &qp->rsps_internal[i];
		qp->reqs_internal[i].req.cmd = &qp->cmds_internal[i];
		TAILQ_INSERT_TAIL(&qp->reqs, &qp->reqs_internal[i], link);
	}
out:
	if (err) {
		destroy_qp(qp);
	}
	return err;
}

static int
add_qp(struct muser_ctrlr *ctrlr, struct muser_qpair *qp,
       struct spdk_nvmf_transport *transport, const uint16_t qsize,
       const uint16_t id)
{
	int err;
	struct muser_transport *muser_transport;

	err = init_qp(ctrlr, qp, transport, qsize, id);
	if (err) {
		return err;
	}

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	/* TODO: Instead of a lock, send a message */
	err = pthread_mutex_lock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to lock poll group lock: %m\n");
		return err;
	}

	TAILQ_INSERT_TAIL(&muser_transport->new_qps, qp, link);

	err = pthread_mutex_unlock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to unlock poll group lock: %m\n");
		return err;
	}

	return 0;
}

static int
prep_io_qp(struct muser_ctrlr *d, struct muser_qpair *qp,
	   const uint16_t id, const uint16_t qsize)
{
	int err;

	assert(d);
	assert(qp);

	/* FIXME need to specify qid */
	/* qp->qid = id; */

	/*
	 * FIXME don't use d->qp[0].qpair.transport, pass transport as a
	 * parameter instead
	 */
	err = add_qp(d, qp, d->qp[0].qpair.transport, qsize, id);
	if (err) {
		return err;
	}

	SPDK_NOTICELOG("waiting for NVMf to connect\n");
	do {
		err = sem_wait(&d->qp[id].prop_req.wait);
	} while (err != 0 && errno != EINTR);
	SPDK_NOTICELOG("NVMf connected\n");

	/* FIXME now we need to get the response from NVMf and pass it back */

	return 0;
}

/*
 * Creates a completion or sumbission I/O queue.
 */
static int
handle_create_io_q(struct muser_ctrlr *ctrlr,
		   struct spdk_nvme_cmd *cmd, const bool is_cq)
{
	union spdk_nvme_create_io_q_cdw10 *cdw10;
	union spdk_nvme_create_io_cq_cdw11 *cdw11_cq = NULL;
	union spdk_nvme_create_io_sq_cdw11 *cdw11_sq = NULL;
	size_t entry_size;

	/*
	 * XXX don't call io_q_id on this. Maybe operate directly on the
	 * ctrlr->qp[id].cq/sq?
	 */
	struct io_q io_q = { 0 };

	assert(ctrlr);
	assert(cmd);

	cdw10 = (union spdk_nvme_create_io_q_cdw10 *)&cmd->cdw10;

	SPDK_NOTICELOG("create I/O %cQ: QID=0x%x, QSIZE=0x%x\n",
		       is_cq ? 'C' : 'S', cdw10->bits.qid, cdw10->bits.qsize);

	if (cdw10->bits.qid >= MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		SPDK_ERRLOG("invalid QID=%d, max=%d\n", cdw10->bits.qid,
			    MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR);
		return -EINVAL;
	}

	if (lookup_io_q(ctrlr, cdw10->bits.qid, is_cq)) {
		SPDK_ERRLOG("%cQ%d already exists\n", is_cq ? 'C' : 'S',
			    cdw10->bits.qid);
		return -EEXIST;
	}

	/* TODO break rest of this function into smaller functions */
	if (is_cq) {
		cdw11_cq = (union spdk_nvme_create_io_cq_cdw11 *)&cmd->cdw11;
		entry_size = sizeof(struct spdk_nvme_cpl);
		/* FIXME implement */
		assert(cdw11_cq->bits.pc == 0x1);
		io_q.cq.ien = cdw11_cq->bits.ien;
		io_q.cq.iv = cdw11_cq->bits.iv;
	} else {
		cdw11_sq = (union spdk_nvme_create_io_sq_cdw11 *)&cmd->cdw11;
		if (!lookup_io_q(ctrlr, cdw11_sq->bits.cqid, true)) {
			SPDK_ERRLOG("CQ%d does not exist\n", cdw11_sq->bits.cqid);
			return -ENOENT;
		}
		entry_size = sizeof(struct spdk_nvme_cmd);
		/* FIXME implement */
		assert(cdw11_sq->bits.pc == 0x1);

		io_q.sq.cqid = cdw11_sq->bits.cqid;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "CQID=%d\n", io_q.sq.cqid);
	}

	io_q.size = cdw10->bits.qsize + 1;
	if (io_q.size > max_queue_size(ctrlr)) {
		SPDK_ERRLOG("queue too big, want=%d, max=%d\n", io_q.size,
			    max_queue_size(ctrlr));
		return -E2BIG;
	}
	io_q.addr = map_one(ctrlr->lm_ctx, cmd->dptr.prp.prp1,
			    io_q.size * entry_size);
	if (!io_q.addr) {
		SPDK_ERRLOG("failed to map I/O queue\n");
		return -1;
	}

	if (is_cq) {
		prep_io_qp(ctrlr, &ctrlr->qp[cdw10->bits.qid], cdw10->bits.qid,
			   MUSER_DEFAULT_MAX_QUEUE_DEPTH);
	}

	insert_queue(ctrlr, &io_q, is_cq, cdw10->bits.qid);

	/*
	 * FIXME we need to complete the admin request when we hear back from
	 * NVMf (muser_req_complete), not here.
	 */

	return admin_queue_complete(ctrlr, cmd, &ctrlr->qp[0].cq, NULL);
}

/*
 * Returns 1 if a request has been forwarded to NVMf and need to wait for
 * the response, 0 if no need for a response, and -1 on error.
 */
static int
consume_admin_req(struct muser_ctrlr *ctrlr, struct spdk_nvme_cmd *cmd)
{
	int err;

	assert(ctrlr);
	assert(cmd);

	SPDK_NOTICELOG("handle admin req opc=0x%x\n", cmd->opc);

	switch (cmd->opc) {
	case SPDK_NVME_OPC_ASYNC_EVENT_REQUEST: /* FIXME implement */
		return 0;
	/* TODO put all cases in order */
	case SPDK_NVME_OPC_IDENTIFY:
	case SPDK_NVME_OPC_SET_FEATURES:
	case SPDK_NVME_OPC_GET_LOG_PAGE:
	case SPDK_NVME_OPC_NS_MANAGEMENT:
		err = handle_identify_req(ctrlr, cmd);
		if (!err) {
			return 1;
		}
		return err;
	case SPDK_NVME_OPC_CREATE_IO_CQ:
		return handle_create_io_q(ctrlr, cmd, true);
	case SPDK_NVME_OPC_CREATE_IO_SQ:
		return handle_create_io_q(ctrlr, cmd, false);
	/* FIXME need to queue completion response */
	case SPDK_NVME_OPC_ABORT:
	case SPDK_NVME_OPC_DELETE_IO_SQ:
	case SPDK_NVME_OPC_DELETE_IO_CQ:
		return 0;
	default:
		SPDK_ERRLOG("unsupported command 0x%x\n", cmd->opc);
		return -1;
	}
	return -1;
}

static int
consume_io_req(struct muser_ctrlr *ctrlr, struct io_q *q,
               struct spdk_nvme_cmd *cmd)
{
	struct muser_qpair *qp;

	assert(cmd != NULL);
	assert(q != NULL);

	qp = &ctrlr->qp[io_q_id(q)];
	while (qp->cmd != NULL) { /* FIXME wait for previous request to finish */
		spdk_rmb();
	}
	qp->cmd = cmd;
	spdk_wmb();
	/* handle_req will pick up this request now */
	qp->prop_req.dir = MUSER_NVMF_READ;

	return 0;
}

static int
consume_req(struct muser_ctrlr *d, struct io_q *q,
	    struct spdk_nvme_cmd *cmd)
{
	if (io_q_id(q) == 0) {
		return consume_admin_req(d, cmd);
	}
	return consume_io_req(d, q, cmd);
}

/*
 * Returns how many requests have been forwarded to NVMf and need to wait for
 * the response.
 */
static int
consume_reqs(struct muser_ctrlr *d, const uint32_t new_tail,
	     struct io_q *q)
{
	int count = 0;
	struct spdk_nvme_cmd *queue;

	assert(d);
	assert(q);

	/* FIXME need to validate new_sq_tail */
	/*
	 * FIXME can queue size change arbitrarily? Shall we operate on a copy ?
	 *
	 * FIXME operating on an SQ is pretty much the same for admin and I/O
	 * queues. All we need is a callback to replace consume_req,
	 * depending on the type of the queue.
	 *
	 * FIXME no need to track old_tail, simply consume anything from head to
	 * tail.
	 */
	queue = q->addr;
	while (sq_tail(d, q) != new_tail) {
		struct spdk_nvme_cmd *cmd = &queue[sq_tail(d, q)];
		int ret = consume_req(d, q, cmd);
		if (ret < 0) {
			/* FIXME how should we proceed now? */
			SPDK_ERRLOG("failed to process request\n");
			assert(0);
		}
		count += ret;
		sq_tail_advance(d, q);
	}
	return count;
}

/*
 * Callback that gets triggered when the driver writes to a submission
 * queue doorbell.
 *
 * Returns how many requests have been forwarded to NVMf and need to wait for
 * the response.
 */
static ssize_t
handle_sq_tdbl_write(struct muser_ctrlr *d, const uint32_t new_tail,
		     struct io_q *q)
{
	assert(d);
	assert(q);

	SPDK_NOTICELOG("write to SQ%d tail=0x%x\n", io_q_id(q), new_tail);

	/*
	 * TODO we should be mapping the queue when ASQ gets written, however
	 * the NVMe driver writes it in two steps and this complicates things,
	 * e.g. is it guaranteed to write both upper and lower portions?
	 */
	if (io_q_id(q) == 0 && !d->qp[0].sq.addr) {
		/* FIXME do this when EN is set to one */
		int ret = asq_map(d);
		if (ret) {
			SPDK_ERRLOG("failed to map SQ0: %d\n", ret);
			return -1;
		}
	}

	return consume_reqs(d, new_tail, q);
}

static ssize_t
handle_cq_hdbl_write(struct muser_ctrlr *d, const uint32_t new_head,
		     struct io_q *q)
{
	assert(d);
	assert(q);

	/*
	 * FIXME is there anything we need to do with the new CQ0 head?
	 * Incrementing the head means the host consumed completions, right?
	 */
	SPDK_NOTICELOG("write to CQ%d head=0x%x\n", io_q_id(q), new_head);
	/* FIXME */
	q->cq.hdbl = new_head;
	return 0;
}

/*
 * SQ equation:
 *	2*y   = (ADDR - 0x1000) / (4 << CAP.DSTRD)
 * CQ equation:
 *	2*y+1 = (ADDR - 0x1000) / (4 << CAP.DSTRD)
 *
 * So if the result of the right hand side expression is an even number then
 * it's a submission queue, otherwise it's a completion queue.
 */
static inline int
get_qid_and_kind(struct muser_ctrlr const *ctrlr, const loff_t pos,
		 bool *is_cq)
{
	int i, n;

	assert(ctrlr);
	assert(is_cq);

	n = 4 << ctrlr->qp[0].qpair.ctrlr->vcprop.cap.bits.dstrd;
	i = pos - DOORBELLS;

	if (i % n) {
		SPDK_ERRLOG("invalid doorbell offset 0x%lx\n", pos);
		return -EINVAL;
	}

	i /= n;

	/*
	 * Adjusting 'i' is intentionally done in a verbose way for improved
	 * readability.
	 */
	if (i % 2) { /* CQ */
		*is_cq =  true;
		i = (i - 1) / 2;
	} else { /* SQ */
		*is_cq = false;
		i = i / 2;
	}
	return i;
}

#if 0
static int
handle_io_sq_tdbl_write(struct muser_ctrlr *ctrlr)
{
	assert(0);
}

static int
handle_io_cq_hbdl_write(struct muser_ctrlr *ctrlr)
{
	assert(0);
}
#endif

#if 0
static bool
is_admin_q(struct io_q const *queues, struct io_q const *q)
{
	return q == &queues[0];
}
#endif

static int
handle_dbl_write(struct muser_ctrlr *ctrlr, const uint32_t v, struct io_q *q)
{
	if (q->is_cq) {
		return handle_cq_hdbl_write(ctrlr, v, q);
	}
	return handle_sq_tdbl_write(ctrlr, v, q);
}

static uint32_t
handle_dbl_read(struct io_q *q)
{
	if (q->is_cq) {
		return q->cq.hdbl;
	}
	return q->sq.tdbl;
}

/*
 * Handles a write at offset 0x1000 or more.
 */
static int
handle_dbl_access(struct muser_ctrlr *ctrlr, uint8_t const *buf,
		  const size_t count, const loff_t pos, const bool is_write)
{
	int err;
	uint16_t qid;
	bool is_cq;
	struct io_q *q;

	assert(ctrlr);
	assert(buf);

	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("bad doorbell buffer size %ld\n", count);
		return -EINVAL;
	}

	err = get_qid_and_kind(ctrlr, pos, &is_cq);
	if (err < 0) {
		SPDK_ERRLOG("bad doorbell 0x%lx\n", pos);
		return err;
	}
	qid = err;

	q = lookup_io_q(ctrlr, qid, is_cq);
	if (!q) {
		SPDK_ERRLOG("%cQ%d doesn't exist\n", is_cq ? 'C' : 'S', qid);
		return -ENOENT;
	}

	if (is_write) {
		return handle_dbl_write(ctrlr, *(int *)buf, q);
	}
	*(uint32_t*)buf = handle_dbl_read(q);
	return 0;
}

static ssize_t
write_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_ctrlr *ctrlr = pvt;
	int err;

	SPDK_NOTICELOG("ctrlr: %p, count=%zu, pos=%"PRIX64"\n",
		       ctrlr, count, pos);
	spdk_log_dump(stdout, "muser_write", buf, count);

	switch (pos) {
	/* TODO sort cases */
	case ADMIN_QUEUES:
		return admin_queue_write(ctrlr, buf, count, pos);
	case CC:
		ctrlr->qp[0].prop_req.buf = buf;
		ctrlr->qp[0].prop_req.count = count;
		ctrlr->qp[0].prop_req.pos = pos;
		spdk_wmb();
		ctrlr->qp[0].prop_req.dir = MUSER_NVMF_WRITE;
		break;
	default:
		if (pos >= DOORBELLS) {
			err = handle_dbl_access(ctrlr, buf, count,
					       pos, true);
			if (err <= 0) {
				return err;
			}
		} else {
			SPDK_ERRLOG("write to 0x%lx not implemented\n",
				    pos);
			return -ENOTSUP;
		}
		break;
	}

	do {
		err = sem_wait(&ctrlr->qp[0].prop_req.wait);
	} while (err != 0 && errno != EINTR);

	/*
	 * FIXME we also call admin_queue_complete at end of handle_req for
	 * I/O reads, this started getting a bit messy.
	 */
	if (pos == SQ0TBDL && ctrlr->qp[0].cmd != NULL) { /* FIXME is this only for CC? */
		admin_queue_complete(ctrlr, ctrlr->qp[0].cmd, &ctrlr->qp[0].cq, NULL);
	}

	return ctrlr->qp[0].prop_req.ret;
}

static ssize_t
access_bar_fn(void *pvt, char *buf, size_t count, loff_t offset,
              const bool is_write)
{
	ssize_t ret;

	/*
	 * FIXME it doesn't make sense to have separate functions for the BAR0,
	 * since a lot of the code is common, e.g. figuring out which doorbell
	 * is accessed. Merge.
	 */
	if (is_write) {
		ret = write_bar0(pvt, buf, count, offset);
	} else {
		ret = read_bar0(pvt, buf, count, offset);
	}

	if (ret != 0) {
		SPDK_WARNLOG("failed to %s %lx@%lx BAR0: %zu\n",
			     is_write ? "write" : "read", offset, count, ret);
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
	struct muser_ctrlr *ctrlr = (struct muser_ctrlr *)pvt;

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
pmcap_access(void *pvt, const uint8_t id, char * const buf, const size_t count,
             const loff_t offset, const bool is_write)
{
	struct muser_ctrlr *ctrlr = (struct muser_ctrlr *)pvt;

	if (is_write)
		assert(false); /* TODO */

	memcpy(buf, ((char*)&ctrlr->pmcap) + offset, count);

	return count;
}

static ssize_t
handle_mxc_write(struct muser_ctrlr *ctrlr, const struct mxc * const mxc)
{
	uint16_t n;

	assert(ctrlr != NULL);
	assert(mxc != NULL);

	/* host driver writes RO field, don't know why */
	if (ctrlr->msixcap.mxc.ts == *(uint16_t*)mxc) {
		goto out;
	}

	n = ~(PCI_MSIX_FLAGS_MASKALL | PCI_MSIX_FLAGS_ENABLE) & *((uint16_t*)mxc);
	if (n != 0) {
		SPDK_ERRLOG("bad write 0x%x to MXC\n", n);
		return -EINVAL;
	}

	if (mxc->mxe != ctrlr->msixcap.mxc.mxe) {
		/*
		 * FIXME need to check that MSI enable bit is set to 0 before
		 * enabling MSI-X.
		 */
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "%s MSI-X\n",
		              mxc->mxe ? "enable" : "disable");
		ctrlr->msixcap.mxc.mxe = mxc->mxe;
	}

	if (mxc->fm != ctrlr->msixcap.mxc.fm) {
		if (mxc->fm) {
			SPDK_DEBUGLOG(SPDK_LOG_MUSER, "all MSI-X vectors masked\n");
		} else {
			SPDK_DEBUGLOG(SPDK_LOG_MUSER, "vector's mask bit determines whether whether vector is masked");
		}
		ctrlr->msixcap.mxc.fm = mxc->fm;
	}
out:
	return sizeof (struct mxc);
}

static ssize_t
handle_msix_write(struct muser_ctrlr *ctrlr, char * const buf, const size_t count,
                  const loff_t offset)
{
	if (count == sizeof (struct mxc)) {
		switch (offset) {
			case offsetof(struct msixcap, mxc):
				return handle_mxc_write(ctrlr, (struct mxc*)buf);
			default:
				SPDK_ERRLOG("invalid MSI-X write offset %ld\n",
				            offset);
				return -EINVAL;
		}
	}
	SPDK_ERRLOG("invalid MSI-X write size %lu\n", count);
	return -EINVAL;
}

static ssize_t
msixcap_access(void *pvt, const uint8_t id, char * const buf, size_t count,
               loff_t offset, const bool is_write)
{
	struct muser_ctrlr *ctrlr = (struct muser_ctrlr *)pvt;

	if (is_write) {
		return handle_msix_write(ctrlr, buf, count, offset);
	}

	memcpy(buf, ((char*)&ctrlr->msixcap) + offset, count);

	return count;
}

static int
handle_msicap_mc_write(struct muser_ctrlr * const ctrlr, const struct mc * const mc)
{
	assert(ctrlr != NULL);
	assert(mc != NULL);

	if (mc->msie != ctrlr->msicap.mc.msie) {
		ctrlr->msicap.mc.msie = mc->msie;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MSI %s\n",
		              mc->msie ? "enable" : "disable");
	}

	if (mc->mmc != ctrlr->msicap.mc.mmc) {
		SPDK_ERRLOG("invalid write %#x to RO register MMC (%#x)\n",
		            mc->mmc, ctrlr->msicap.mc.mmc);
	}

	if (mc->mme != ctrlr->msicap.mc.mme) {
		ctrlr->msicap.mc.mme = mc->mme;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MME set to %#x\n",
		              ctrlr->msicap.mc.mme);
	}

	if (mc->c64 != ctrlr->msicap.mc.c64) {
		SPDK_ERRLOG("invalid write %#x to RO register C64 (%#x)\n",
		            mc->c64, ctrlr->msicap.mc.c64);
	}

	if (mc->pvm != ctrlr->msicap.mc.pvm) {
		SPDK_ERRLOG("invalid write %#x to RO register PVM (%#x)\n",
		            mc->pvm, ctrlr->msicap.mc.pvm);
	}

	if (mc->res1) {
		SPDK_ERRLOG("invalid write %#x to RO reserved\n", mc->res1);
	}

	return 0;
}

static int
handle_msicap_md_write(struct muser_ctrlr *ctrlr, const uint16_t data)
{
	assert(ctrlr != NULL);

	ctrlr->msicap.md = data;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MD.DATA=%#x\n", ctrlr->msicap.md);
	return 0;
}

static int
handle_msicap_ma_write(struct muser_ctrlr *ctrlr, const struct ma * const ma)
{
	assert(ctrlr != NULL);
	assert(ma != NULL);

	if (ma->res1) {
		SPDK_ERRLOG("bad write to ma\n");
		return -EINVAL;
	}
	ctrlr->msicap.ma.addr = ma->addr;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MA.ADDR=%#x\n", ctrlr->msicap.ma.addr);
	return 0;
}

static int
handle_msicap_mua_write(struct muser_ctrlr *ctrlr, const uint32_t uaddr)
{
	assert(ctrlr != NULL);

	ctrlr->msicap.mua = uaddr;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MUA.UADDR=%#x\n", ctrlr->msicap.mua);
	return 0;
}

static int
handle_msicap_mmask_write(struct muser_ctrlr *ctrlr, const uint32_t mask)
{
	assert(ctrlr != NULL);

	ctrlr->msicap.mmask = mask;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MMASK.MASK=%#x\n", ctrlr->msicap.mmask);
	return 0;
}

static int
handle_msicap_mpend_write(struct muser_ctrlr *ctrlr, const uint32_t pend)
{
	assert(ctrlr != NULL);

	ctrlr->msicap.mpend = pend;
	SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MPEND.PEND=%#x\n", ctrlr->msicap.mpend);
	return 0;
}

static int
handle_msicap_write_2_bytes(struct muser_ctrlr *c, char * const b, loff_t o)
{
	switch (o) {
		case offsetof(struct msicap, mc):
			return handle_msicap_mc_write(c, (struct mc*)b);
		case offsetof(struct msicap, md):
			return handle_msicap_md_write(c, *(uint16_t*)b);

	}
	return -EINVAL;
}

static int
handle_msicap_write_4_bytes(struct muser_ctrlr *c, char * const b, loff_t o)
{
	switch (o) {
		case offsetof(struct msicap, ma):
			return handle_msicap_ma_write(c, (struct ma*)b);
		case offsetof(struct msicap, mua):
			return handle_msicap_mua_write(c, *(uint32_t*)b);
		case offsetof(struct msicap, mmask):
			return handle_msicap_mmask_write(c, *(uint32_t*)b);
		case offsetof(struct msicap, mpend):
			return handle_msicap_mpend_write(c, *(uint32_t*)b);
	}
	return -EINVAL;
}

static int
handle_msicap_write(struct muser_ctrlr *ctrlr, char * const buf, size_t count,
                    loff_t offset)
{
	assert(ctrlr != NULL);

	switch (count) {
		case 2:
			return handle_msicap_write_2_bytes(ctrlr, buf, offset);
		case 4:
			return handle_msicap_write_4_bytes(ctrlr, buf, offset);
	}
	return -EINVAL;
}

static ssize_t
msicap_access(void *pvt, const uint8_t id, char * const buf, size_t count,
              loff_t offset, const bool is_write)
{
	struct muser_ctrlr *ctrlr = (struct muser_ctrlr *)pvt;

	if (is_write) {
		int err = handle_msicap_write(ctrlr, buf, count, offset);
		if (err != 0) {
			return err;
		}
	} else {
		memcpy(buf, ((char*)&ctrlr->msicap) + offset, count);
	}

	return count;
}

static int
handle_pxcap_pxdc_write(struct muser_ctrlr * const c, const union pxdc * const p)
{
	assert(c != NULL);
	assert(p != NULL);

	if (p->cere != c->pxcap.pxdc.cere) {
		c->pxcap.pxdc.cere = p->cere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "CERE %s\n",
		              p->cere ? "enable" : "disable");
	}

	if (p->nfere != c->pxcap.pxdc.nfere) {
		c->pxcap.pxdc.nfere = p->nfere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "NFERE %s\n",
		              p->nfere ? "enable" : "disable");
	}

	if (p->fere != c->pxcap.pxdc.fere) {
		c->pxcap.pxdc.fere = p->fere;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "FERE %s\n",
		              p->fere ? "enable" : "disable");
	}

	if (p->urre != c->pxcap.pxdc.urre) {
		c->pxcap.pxdc.urre = p->urre;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "URRE %s\n",
		              p->urre ? "enable" : "disable");
	}

	if (p->ero != c->pxcap.pxdc.ero) {
		c->pxcap.pxdc.ero = p->ero;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "ERO %s\n",
		              p->ero ? "enable" : "disable");
	}

	if (p->mps != c->pxcap.pxdc.mps) {
		c->pxcap.pxdc.mps = p->mps;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MPS set to %d\n", p->mps);
	}

	if (p->ete != c->pxcap.pxdc.ete) {
		c->pxcap.pxdc.ete = p->ete;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "ETE %s\n",
		              p->ete ? "enable" : "disable");
	}

	if (p->pfe != c->pxcap.pxdc.pfe) {
		c->pxcap.pxdc.pfe = p->pfe;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "PFE %s\n",
		              p->pfe ? "enable" : "disable");
	}

	if (p->appme != c->pxcap.pxdc.appme) {
		c->pxcap.pxdc.appme = p->appme;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "APPME %s\n",
		              p->appme ? "enable" : "disable");
	}

	if (p->ens != c->pxcap.pxdc.ens) {
		c->pxcap.pxdc.ens = p->ens;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "ENS %s\n",
		              p->ens ? "enable" : "disable");
	}

	if (p->mrrs != c->pxcap.pxdc.mrrs) {
		c->pxcap.pxdc.mrrs = p->mrrs;
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "MRRS set to %d\n", p->mrrs);
	}

	if (p->iflr) {
		SPDK_DEBUGLOG(SPDK_LOG_MUSER, "initiate function level reset\n");
	}

	return 0;
}

static int
handle_pxcap_write_2_bytes(struct muser_ctrlr *c, char * const b, loff_t o)
{
	switch (o) {
		case offsetof(struct pxcap, pxdc):
			return handle_pxcap_pxdc_write(c, (union pxdc*)b);
	}
	return -EINVAL;
}

static ssize_t
handle_pxcap_write(struct muser_ctrlr *ctrlr, char * const buf, size_t count,
                   loff_t offset)
{
	int err = -EINVAL;
	switch (count) {
		case 2:
			err = handle_pxcap_write_2_bytes(ctrlr, buf, offset);
			break;
	}
	if (err != 0) {
		assert(false); /* FIXME */
		return err;
	}
	return count;
}

static ssize_t
pxcap_access(void *pvt, const uint8_t id, char * const buf, size_t count,
                    loff_t offset, const bool is_write)
{
	struct muser_ctrlr *ctrlr = (struct muser_ctrlr *)pvt;

	if (is_write) {
		return handle_pxcap_write(ctrlr, buf, count, offset);
	}

	memcpy(buf, ((char*)&ctrlr->pxcap) + offset, count);

	return count;
}



static void
nvme_reg_info_fill(lm_reg_info_t *reg_info)
{
	assert(reg_info != NULL);

	memset(reg_info, 0, sizeof(*reg_info) * LM_DEV_NUM_REGS);

	reg_info[LM_DEV_BAR0_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_BAR0_REG_IDX].size  = NVME_REG_BAR0_SIZE;
	reg_info[LM_DEV_BAR0_REG_IDX].fn  = access_bar_fn;

	reg_info[LM_DEV_BAR4_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_BAR4_REG_IDX].size  = PAGE_SIZE;

	reg_info[LM_DEV_BAR5_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_BAR5_REG_IDX].size  = PAGE_SIZE;

	reg_info[LM_DEV_CFG_REG_IDX].flags = LM_REG_FLAG_RW;
	reg_info[LM_DEV_CFG_REG_IDX].size  = NVME_REG_CFG_SIZE;
	reg_info[LM_DEV_CFG_REG_IDX].fn  = access_pci_config;
}

static void
nvme_log(void *pvt, char const *msg)
{
	fprintf(stderr, "%s", msg);
}

static void
nvme_dev_info_fill(lm_dev_info_t *dev_info, struct muser_ctrlr *muser_ctrlr,
                   bool en_msi, bool en_msix)
{
	static const lm_cap_t pm = {.id = PCI_CAP_ID_PM,
                                    .size = sizeof(struct pmcap),
	                            .fn = pmcap_access};
	static const lm_cap_t px = {.id = PCI_CAP_ID_EXP,
	                            .size = sizeof(struct pxcap),
	                            .fn = pxcap_access};

	assert(dev_info != NULL);
	assert(muser_ctrlr != NULL);

	dev_info->pvt = muser_ctrlr;

	dev_info->uuid = muser_ctrlr->uuid;

	dev_info->pci_info.id.vid = 0x4e58;     /* TODO: LE ? */
	dev_info->pci_info.id.did = 0x0001;

	/* controller uses the NVM Express programming interface */
	dev_info->pci_info.cc.pi = 0x02;

	/* non-volatile memory controller */
	dev_info->pci_info.cc.scc = 0x08;

	/* mass storage controller */
	dev_info->pci_info.cc.bcc = 0x01;

	dev_info->pci_info.irq_count[LM_DEV_INTX_IRQ_IDX] = NVME_IRQ_INTX_NUM;

	dev_info->pci_info.caps[dev_info->pci_info.nr_caps++] = pm;

	if (en_msi) {
		static const lm_cap_t msi = {.id = PCI_CAP_ID_MSI,
		                             .size = sizeof(struct msicap),
		                             .fn = msicap_access};
		dev_info->pci_info.irq_count[LM_DEV_MSI_IRQ_IDX] = 1 << NVME_IRQ_MSI_NUM;
		dev_info->pci_info.caps[dev_info->pci_info.nr_caps++] = msi;
	}

	if (en_msix) {
		static const lm_cap_t msix = {.id = PCI_CAP_ID_MSIX,
		                              .size = sizeof(struct msixcap),
		                              .fn = msixcap_access};
		dev_info->pci_info.irq_count[LM_DEV_MSIX_IRQ_IDX] = NVME_IRQ_MSIX_NUM;
		dev_info->pci_info.caps[dev_info->pci_info.nr_caps++] = msix;
	}

	dev_info->pci_info.caps[dev_info->pci_info.nr_caps++] = px;

	nvme_reg_info_fill(dev_info->pci_info.reg_info);

	dev_info->log = nvme_log;
	dev_info->log_lvl = LM_DBG;
}

static void *
drive(void *arg)
{
	lm_ctx_t *lm_ctx = arg;

	lm_ctx_drive(lm_ctx);

	return NULL;
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
muser_listen(struct spdk_nvmf_transport *transport,
	     const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_ctrlr *muser_ctrlr;
	lm_dev_info_t dev_info = { 0 };
	int err;
	const bool en_msi = false, en_msix = true;

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	err = mdev_create(trid->traddr);
	if (err == -1) {
		return -1;
	}

	muser_ctrlr = calloc(1, sizeof(*muser_ctrlr));
	if (muser_ctrlr == NULL) {
		SPDK_ERRLOG("Error allocating ctrlr: %m\n");
		goto err;
	}
	memcpy(muser_ctrlr->uuid, trid->traddr, sizeof(muser_ctrlr->uuid));
	memcpy(&muser_ctrlr->trid, trid, sizeof(muser_ctrlr->trid));

	err = sem_init(&muser_ctrlr->qp[0].prop_req.wait, 0, 0);
	if (err) {
		goto err_free_dev;
	}

	/* Admin QP setup */
	err = add_qp(muser_ctrlr, &muser_ctrlr->qp[0], transport,
		     MUSER_DEFAULT_AQ_DEPTH, 0);
	if (err) {
		goto err_free_dev;
	}

	/* LM setup */
	nvme_dev_info_fill(&dev_info, muser_ctrlr, en_msi, en_msix);

	/* PM */
	muser_ctrlr->pmcap.pmcs.nsfrst = 0x1;

	/* MSI */
	if (en_msi) {	
		muser_ctrlr->msicap.mc.mmc = 0x1;
		muser_ctrlr->msicap.mc.c64 = 0x1;
	}

	/* MSI-X */
	if (en_msix) {
		/*
		 * TODO for now we put table BIR and PBA BIR in BAR4 because
		 * it's just easier, otherwise in order to put it in BAR0 we'd
		 * have to figure out where exactly doorbells end.
		 */
		muser_ctrlr->msixcap.mxc.ts = 0x3;
		muser_ctrlr->msixcap.mtab.tbir = 0x4;
		muser_ctrlr->msixcap.mtab.to = 0x0;
		muser_ctrlr->msixcap.mpba.pbir = 0x5;
		muser_ctrlr->msixcap.mpba.pbao = 0x0;
	}

	/* EXP */
	muser_ctrlr->pxcap.pxcaps.ver = 0x2;
	muser_ctrlr->pxcap.pxdcap.per = 0x1;
	muser_ctrlr->pxcap.pxdcap.flrc = 0x1;
	muser_ctrlr->pxcap.pxdcap2.ctds = 0x1;
	/* FIXME check PXCAPS.DPT */

	muser_ctrlr->lm_ctx = lm_ctx_create(&dev_info);
	if (muser_ctrlr->lm_ctx == NULL) {
		/* TODO: lm_create doesn't set errno */
		SPDK_ERRLOG("Error creating libmuser ctx: %m\n");
		goto err_destroy_qp;
	}


	muser_ctrlr->pci_config_space = lm_get_pci_config_space(muser_ctrlr->lm_ctx);
	init_pci_config_space(muser_ctrlr->pci_config_space);

	err = pthread_create(&muser_ctrlr->lm_thr, NULL,
			     drive, muser_ctrlr->lm_ctx);
	if (err != 0) {
		/* TODO: pthread_create doesn't set errno */
		SPDK_ERRLOG("Error creating lm_drive thread: %m\n");
		goto err_destroy;
	}

	TAILQ_INSERT_TAIL(&muser_transport->ctrlrs, muser_ctrlr, link);

	return 0;

err_destroy:
	lm_ctx_destroy(muser_ctrlr->lm_ctx);
err_destroy_qp:
	destroy_qp(&muser_ctrlr->qp[0]);
err_free_dev:
	free(muser_ctrlr);
err:
	mdev_remove(trid->traddr);

	return -1;
}

static int
muser_stop_listen(struct spdk_nvmf_transport *transport,
		  const struct spdk_nvme_transport_id *trid)
{
	return -1;
}

static void
muser_accept(struct spdk_nvmf_transport *transport, new_qpair_fn cb_fn,
             void *cb_arg)
{
	int err;
	struct muser_transport *muser_transport;
	struct muser_qpair *qp, *tmp;

	muser_transport = SPDK_CONTAINEROF(transport, struct muser_transport,
					   transport);

	err = pthread_mutex_lock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to lock poll group lock: %m\n");
		return;
	}

	TAILQ_FOREACH_SAFE(qp, &muser_transport->new_qps, link, tmp) {
		TAILQ_REMOVE(&muser_transport->new_qps, qp, link);
		cb_fn(&qp->qpair, NULL);
	}

	err = pthread_mutex_unlock(&muser_transport->lock);
	if (err) {
		SPDK_ERRLOG("failed to lock poll group lock: %m\n");
		return;
	}
}

static void
muser_discover(struct spdk_nvmf_transport *transport,
	       struct spdk_nvme_transport_id *trid,
	       struct spdk_nvmf_discovery_log_page_entry *entry)
{ }

static struct spdk_nvmf_transport_poll_group *
muser_poll_group_create(struct spdk_nvmf_transport *transport)
{
	struct muser_poll_group *muser_group;

	muser_group = calloc(1, sizeof(*muser_group));
	if (muser_group == NULL) {
		SPDK_ERRLOG("Error allocating poll group: %m");
		return NULL;
	}

	TAILQ_INIT(&muser_group->qps);

	return &muser_group->group;
}

static void
muser_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;

	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);

	free(muser_group);
}

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


	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);
	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	muser_ctrlr = muser_qpair->ctrlr;

	muser_req = TAILQ_FIRST(&muser_qpair->reqs);
	TAILQ_REMOVE(&muser_qpair->reqs, muser_req, link);

	req = &muser_req->req;
	req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
	req->cmd->connect_cmd.cid = 0; /* FIXME */
	req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
	req->cmd->connect_cmd.recfmt = 0;
	req->cmd->connect_cmd.sqsize = muser_qpair->qsize - 1;
	req->cmd->connect_cmd.qid = qpair->qid;

	req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
	req->data = calloc(1, req->length);
	assert(req->data != NULL);
	/* TODO: Pre-allocate memory */

	data = (struct spdk_nvmf_fabric_connect_data *)req->data;
	/* data->hostid = { 0 } */

	data->cntlid = qpair->qid ? muser_ctrlr->cntlid : 0xffff;
	assert(data->cntlid);
	snprintf(data->subnqn, sizeof(data->subnqn),
		 "nqn.2019-07.io.spdk.muser:%s", muser_ctrlr->uuid);
	/* data->hostnqn = { 0 } */

	SPDK_NOTICELOG("sending connect fabrics command for QID=0x%x\n",
		       qpair->qid);

	spdk_nvmf_request_exec(req);

	TAILQ_INSERT_TAIL(&muser_group->qps, muser_qpair, link);

	return 0;
}

static int
muser_poll_group_remove(struct spdk_nvmf_transport_poll_group *group,
			struct spdk_nvmf_qpair *qpair)
{
	return -1;
}

static void
muser_req_done(struct spdk_nvmf_request *req)
{
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;

	muser_qpair = (struct muser_qpair *)req->qpair;
	muser_req = (struct muser_req *)req;

	if (req->cmd->connect_cmd.opcode == SPDK_NVME_OPC_FABRIC &&
	    req->cmd->connect_cmd.fctype == SPDK_NVMF_FABRIC_COMMAND_CONNECT) {

		if (req->cmd->connect_cmd.qid) {
			int err;
			SPDK_DEBUGLOG(SPDK_LOG_MUSER,
				      "fabric connect command completed\n");
			SPDK_DEBUGLOG(SPDK_LOG_MUSER, "sem_post %p\n", &muser_qpair->prop_req.wait);
			err = sem_post(&muser_qpair->prop_req.wait);
			if (err) {
				SPDK_ERRLOG("failed to sem_post: %m\n");
			}
		}
		free(req->data);
		req->data = NULL;
	}

	TAILQ_INSERT_TAIL(&muser_qpair->reqs, muser_req, link);
}

static int
muser_req_free(struct spdk_nvmf_request *req)
{
	muser_req_done(req);
	return 0;
}

static int
muser_req_complete(struct spdk_nvmf_request *req)
{
	if (req->cmd->connect_cmd.opcode != SPDK_NVME_OPC_FABRIC &&
	    req->cmd->connect_cmd.fctype != SPDK_NVMF_FABRIC_COMMAND_CONNECT) {
		/* TODO: do cqe business */
	}

	muser_req_done(req);

	return 0;
}

static void
muser_close_qpair(struct spdk_nvmf_qpair *qpair)
{ }

static struct spdk_nvmf_request*
get_nvmf_req(struct muser_qpair *qp)
{
	struct muser_req *muser_req;

	assert(qp);

	muser_req = TAILQ_FIRST(&qp->reqs);
	TAILQ_REMOVE(&qp->reqs, muser_req, link);
	return &muser_req->req;
}

static uint16_t
nlb(struct spdk_nvme_cmd *cmd)
{
	return 0x0000ffff & cmd->cdw12;
}

static int
handle_cmd_io_req(struct muser_ctrlr * ctrlr, struct spdk_nvmf_request *req)
{
	int err;
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
		case SPDK_NVME_OPC_DATASET_MANAGEMENT:
			req->xfer = SPDK_NVME_DATA_HOST_TO_CONTROLLER;
			break;
		default:
			SPDK_ERRLOG("invalid I/O request type 0x%x\n",
			            req->cmd->nvme_cmd.opc);
			return -EINVAL;
	}

	req->data = NULL;
	if (remap) {
		assert(is_prp(&req->cmd->nvme_cmd));
		req->length = (nlb(&req->cmd->nvme_cmd) + 1) << 9;
		/* FIXME prp address is still GPA, do we need to fix it? */
		err = muser_map_prps(ctrlr, &req->cmd->nvme_cmd, req->iov,
		                     req->length);
		if (err < 0) {
			SPDK_ERRLOG("failed to map PRP: %d\n", err);
			/* FIXME need to explicitly fail request */
			return err;
		}
		req->iovcnt = err;
		if (req->cmd->nvme_cmd.opc == SPDK_NVME_OPC_DATASET_MANAGEMENT) {
			assert(req->iovcnt == 1);
			req->data = req->iov->iov_base;
			req->length = req->iov->iov_len;
		} 
	}
	return 0;
}

/* TODO find better name */
static int
handle_cmd_req(struct muser_ctrlr * ctrlr, struct spdk_nvme_cmd * cmd,
               struct spdk_nvmf_request * req)
{
	assert(ctrlr != NULL);
	assert(cmd != NULL);
	assert(req != NULL);

	req->cmd->nvme_cmd = *cmd;
	/* FIXME figure out how to initialize this field. */
	if (!spdk_nvmf_qpair_is_admin_queue(req->qpair)) {
		return handle_cmd_io_req(ctrlr, req);
	}
	/* FIXME in which case is muser_qpair->cmd == NULL? */
	req->xfer = SPDK_NVME_DATA_CONTROLLER_TO_HOST;
	req->length = 1 << 12;
	req->data = (void *)(req->cmd->nvme_cmd.dptr.prp.prp1 << ctrlr->regs.cc.bits.mps);
	return 0;
}

static int
handle_req(struct muser_qpair *muser_qpair)
{
	struct spdk_nvmf_request *req;
	int err;

	assert(muser_qpair);

	req = get_nvmf_req(muser_qpair);

	if (muser_qpair->cmd != NULL) {
		err = handle_cmd_req(muser_qpair->ctrlr, muser_qpair->cmd, req);
		if (err != 0) {
			return err;
		}		
	} else {
		req->cmd->prop_set_cmd.opcode = SPDK_NVME_OPC_FABRIC;
		req->cmd->prop_set_cmd.cid = 0;
		if (muser_qpair->prop_req.dir == MUSER_NVMF_WRITE) {
			req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_SET;
			req->cmd->prop_set_cmd.value.u32.high = 0;
			req->cmd->prop_set_cmd.value.u32.low = *(uint32_t *)muser_qpair->prop_req.buf;
		} else {
			req->cmd->prop_set_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_PROPERTY_GET;
		}
		req->cmd->prop_set_cmd.attrib.size = (muser_qpair->prop_req.count / 4) - 1;
		req->cmd->prop_set_cmd.ofst = muser_qpair->prop_req.pos;
		req->length = 0;
		req->data = NULL;
	}

	spdk_nvmf_request_exec(req);

	/*
	 * The below should prob. be in complete or something
	 * This only works because the above will be sync
	 */

	if (muser_qpair->cmd) {
		/* FIXME we must now queue the response, either here or in write_bar0 */
		/* FIXME must use cq specified in cqid */
		err = admin_queue_complete(muser_qpair->ctrlr, muser_qpair->cmd,
		                           &muser_qpair->cq, req);
		assert(!err);
		muser_qpair->cmd = NULL; /* FIXME where do we free the request? */
	} else if (muser_qpair->prop_req.dir == MUSER_NVMF_READ) {
		memcpy(muser_qpair->prop_req.buf,
		       &req->rsp->prop_get_rsp.value.u64,
		       muser_qpair->prop_req.count);
	}

	muser_qpair->prop_req.dir = MUSER_NVMF_INVALID;
	return sem_post(&muser_qpair->prop_req.wait);
}

/*
 * Called unconditionally, periodically, very frequently from SPDK to ask
 * whether there's work to be done.  This functions consumes requests generated
 * from read/write_bar0 by setting muser_qpair->ctrlr->prop_req.dir. The
 * read/write_bar0 functions synchronously wait. This function will also
 * consume requests by looking at the queue pair which will be have an
 * associated guest SQ/CQ.
 */
static int
muser_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	int err;

	muser_group = SPDK_CONTAINEROF(group, struct muser_poll_group, group);

	TAILQ_FOREACH(muser_qpair, &muser_group->qps, link) {
		spdk_rmb();
		/* FIXME this is a queue of size 1, needs to change */
		if (muser_qpair->prop_req.dir != MUSER_NVMF_INVALID) {
			err = handle_req(muser_qpair);
			assert(err == 0);
			(void)err;
		}
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

	memcpy(trid, &muser_ctrlr->trid, sizeof(*trid));
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

	memcpy(trid, &muser_ctrlr->trid, sizeof(*trid));
	return 0;
}

static int
muser_qpair_set_sq_size(struct spdk_nvmf_qpair *qpair)
{
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
	.type = SPDK_NVME_TRANSPORT_MUSER,
	.opts_init = muser_opts_init,
	.create = muser_create,
	.destroy = muser_destroy,

	.listen = muser_listen,
	.stop_listen = muser_stop_listen,
	.accept = muser_accept,

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
	.qpair_set_sqsize = muser_qpair_set_sq_size,
};

SPDK_LOG_REGISTER_COMPONENT("nvmf_muser", SPDK_LOG_NVMF_MUSER)
