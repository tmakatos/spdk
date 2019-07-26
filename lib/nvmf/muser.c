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

#include "muser-nvme_pci.h"

#define MUSER_DEFAULT_MAX_QUEUE_DEPTH 128
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
#define NVME_IRQ_MSIX_NUM       32

/* TODO 36 comes from a real NVMe device, does it have to be 36? */
#define NVME_REG_OFFSET         (1UL << 36)

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

struct muser_qpair {
	struct spdk_nvmf_qpair			qpair;
	struct spdk_nvmf_muser_poll_group	*group;
	struct muser_dev			*dev;
	struct muser_nvmf_prop_req		prop_req;
	struct spdk_nvme_cmd			*cmd;
	struct muser_req			*reqs_internal;
	union nvmf_h2c_msg			*cmds_internal;
	union nvmf_c2h_msg			*rsps_internal;
	TAILQ_HEAD(, muser_req)			reqs;
	TAILQ_ENTRY(muser_qpair)		link;
};

struct muser_poll_group {
	struct spdk_nvmf_transport_poll_group	group;
	TAILQ_HEAD(, muser_qpair)		qps;
};

/*
 * An I/O queue.
 *
 * TODO we use the same struct both for submission and for completion I/O
 * queues because that simplifies queue creation. However we're wasting memory
 * for submission queues, maybe rethink this approach.
 */
struct io_q {
	/*
	 * XXX we can trivially figure out the QID based on the offset of a
	 * queue within the sq/cq array, however it's just faster to store it.
	 */
	uint16_t id;

	void *addr;
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
		} cq;
	};
};

struct muser_dev {
	struct spdk_nvme_transport_id		trid;
	struct muser_qpair			admin_qp;
	char					uuid[37];
	pthread_t				lm_thr;
	lm_ctx_t				*lm_ctx;
	bool					setup;
	lm_pci_config_space_t			*pci_config_space;

	/* NB the doorbell member is not used for the admin SQ/CQ */
	struct spdk_nvme_registers		regs;

	uint16_t				cntlid;

	/* I/O queues */
	struct io_q				cq[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR];
	struct io_q				sq[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR];

	TAILQ_ENTRY(muser_dev)			link;
};

struct muser_transport {
	struct spdk_nvmf_transport		transport;
	pthread_mutex_t				lock;
	TAILQ_HEAD(, muser_dev)			devs;
};

static int
muser_destroy(struct spdk_nvmf_transport *transport)
{
	struct muser_transport *muser_transport;

	muser_transport = (struct muser_transport *)transport;

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

	TAILQ_INIT(&muser_transport->devs);

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

	/* TODO: Wait until dev appears on /dev/muser/<uuid> */

	return err;
}

static ssize_t
read_cap(struct muser_dev const * const dev, char * const buf,
         const size_t count, loff_t pos)
{
	/*
	 * FIXME need to validate count and pos
	 * FIXME is it OK to read it like that? Do we need to submit a request
	 * to the NVMf layer?
	 * TODO this line is far too long
	 */
	assert(dev);
	memcpy(buf, ((uint8_t*)&dev->admin_qp.qpair.ctrlr->vcprop.cap.raw) + pos - offsetof(struct spdk_nvme_registers, cap), count);
	return 0;
}

static bool
is_cap(const loff_t pos)
{
	const size_t off = offsetof(struct spdk_nvme_registers, cap);
	return (size_t)pos >= off && (size_t)pos < off + sizeof(uint64_t);
}

/*
 * FIXME read_bar0 and write_bar0 are very similar, merge
 */
static ssize_t
read_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_dev *muser_dev = pvt;
	int err;

	SPDK_NOTICELOG("dev: %p, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, count, pos);

	/*
	 * CAP is 8 bytes long however the driver reads it 4 bytes at a time.
	 * NVMf doesn't like this.
	 */
	if (is_cap(pos))
		return read_cap(muser_dev, buf, count, pos);

	muser_dev->admin_qp.prop_req.buf = buf;
	/* TODO: count must never be more than 8, otherwise we need to split it */
	muser_dev->admin_qp.prop_req.count = count;
	muser_dev->admin_qp.prop_req.pos = pos;
	spdk_wmb();
	muser_dev->admin_qp.prop_req.dir = MUSER_NVMF_READ;

	do {
		err = sem_wait(&muser_dev->admin_qp.prop_req.wait);
	} while (err != 0 && errno != EINTR);

	return muser_dev->admin_qp.prop_req.ret;
}

static uint16_t
max_queue_size(struct muser_dev const * const dev)
{
	return dev->admin_qp.qpair.ctrlr->vcprop.cap.bits.mqes + 1;
}

static ssize_t
aqa_write(struct muser_dev * const dev,
          union spdk_nvme_aqa_register const * const from)
{
	assert(dev);
	assert(from);

	if (from->bits.asqs + 1 > max_queue_size(dev) ||
	    from->bits.acqs + 1 > max_queue_size(dev)) {
		SPDK_ERRLOG("admin queue(s) too big, ASQS=%d, ACQS=%d, max=%d\n",
		            from->bits.asqs + 1, from->bits.acqs + 1,
		            max_queue_size(dev));
		return -EINVAL;
	}
	dev->regs.aqa.raw = from->raw;
	SPDK_NOTICELOG("write to AQA %x\n", dev->regs.aqa.raw);
	return 0;
}

static void
write_partial(uint8_t const * const buf, const loff_t pos, const size_t count,
              const size_t reg_off, uint64_t * const reg)
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
asq_or_acq_write(uint8_t const * const buf, const loff_t pos,
                 const size_t count, uint64_t * const reg, const size_t reg_off)
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
asq_write(uint64_t * const asq, uint8_t const * const buf,
          const loff_t pos, const size_t count)
{
	int ret = asq_or_acq_write(buf, pos, count, asq,
	                           offsetof(struct spdk_nvme_registers, asq));
	SPDK_NOTICELOG("ASQ=0x%lx\n", *asq);
	return ret;
}

static ssize_t
acq_write(uint64_t * const acq, uint8_t const * const buf,
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
admin_queue_write(struct muser_dev * const dev, uint8_t const * const buf,
                  const size_t count, const loff_t pos)
{
	switch (pos) {
		case offsetof(struct spdk_nvme_registers, aqa):
			return aqa_write(dev,
			                 (union spdk_nvme_aqa_register*)buf);
		case ASQ:
			return asq_write(&dev->regs.asq, buf, pos, count);
		case ACQ:
			return acq_write(&dev->regs.acq, buf, pos, count);
		default:
			break;
	}
	SPDK_ERRLOG("bad admin queue write offset 0x%lx\n", pos);
	return -EINVAL;
}

/* TODO this should be a libmuser public function */
static void*
map_one(lm_ctx_t * const ctx, const uint64_t addr, const size_t len)
{
	dma_scattergather_t sg[1];
	struct iovec iov;
	int ret;

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

static bool
is_sq(struct muser_dev const * const dev, struct io_q const * const q)
{
	return q >= &dev->sq[0] && q <= &dev->sq[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR-1];
}

static bool
is_cq(struct muser_dev const * const dev, struct io_q const * const q)
{
	return q >= &dev->cq[0] && q <= &dev->cq[MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR-1];
}


static uint32_t
sq_tail(struct muser_dev const * const d, struct io_q const * const q)
{
	assert(q);
	assert(is_sq(d, q));
	return q->sq.old_tail % q->size;
}

static void
sq_tail_advance(struct muser_dev const * const d, struct io_q * const q)
{
	assert(q);
	assert(d);
	assert(is_sq(d, q));
	q->sq.old_tail = (sq_tail(d, q) + 1) % q->size;
}

static void
insert_queue(struct muser_dev * const dev, struct io_q const * const q,
             const bool is_cq)
{
	struct io_q *queue;

	assert(dev);
	assert(q);

	if (is_cq)
		queue = dev->cq;
	else
		queue = dev->sq;
	queue[q->id] = *q;
}

static int
asq_map(struct muser_dev * const d)
{
	struct io_q q;

	assert(d);
	assert(!d->sq[0].addr);
	/* XXX dev->regs.asq == 0 is a valid memory address */

	q.size = d->regs.aqa.bits.asqs + 1;
	q.id = 0;
	q.sq.old_tail = 0;
	q.sq.head = q.sq.tdbl = 0;
	q.sq.cqid = 0;
	q.addr = map_one(d->lm_ctx, d->regs.asq,
	                 q.size * sizeof(struct spdk_nvme_cmd));
	if (!q.addr)
		return -1;
	insert_queue(d, &q, false);
	return 0;
}

static uint16_t
cq_next(struct muser_dev * const d, struct io_q * const q)
{
	assert(d);
	assert(q);
	assert(is_cq(d, q));
	return (q->cq.tail + 1) % q->size;
}

static bool
cq_is_full(struct muser_dev * const d, struct io_q * const q)
{
	assert(d);
	assert(q);
	assert(is_cq(d, q));
	return cq_next(d, q) == q->cq.hdbl;
}

static void
cq_tail_advance(struct muser_dev * const d, struct io_q * const q)
{
	assert(d);
	assert(q);
	assert(is_cq(d, q));
	q->cq.tail = cq_next(d, q);
}

static int
acq_map(struct muser_dev * const d)
{
	struct io_q q;

	assert(d);
	assert(!d->cq[0].addr);
	assert(d->regs.acq);

	q.size = d->regs.aqa.bits.acqs + 1;
	q.id = 0;
	q.cq.tail = 0;
	q.addr = map_one(d->lm_ctx, d->regs.acq,
	                 q.size * sizeof(struct spdk_nvme_cpl));
	if (!q.addr)
		return -1;
	insert_queue(d, &q, true);
	return 0;
}

static int
dptr_remap(struct muser_dev const * const dev, union spdk_nvme_dptr * const dptr)
{
	void *p;

	assert(dev);
	assert(dptr);

	/* FIXME implement */
	assert(!dptr->prp.prp2);

	p = map_one(dev->lm_ctx, dptr->prp.prp1 << dev->regs.cc.bits.mps,
		sizeof(struct spdk_nvme_cmd));
	if (!p)
		return -1;
	dptr->prp.prp1 = (uint64_t)p >> dev->regs.cc.bits.mps;
	return 0;
}

static int
handle_identify_req(struct muser_dev * const dev, struct spdk_nvme_cmd * const cmd)
{
	int err;

	assert(dev);
	assert(cmd);

	/* FIXME implement */
	assert(!cmd->psdt);

	err = dptr_remap(dev, &cmd->dptr);
	if (err) {
		SPDK_ERRLOG("failed to remap DPTR: %d\n", err);
		return -1;
	}

	dev->admin_qp.cmd = cmd;
	spdk_wmb();
	dev->admin_qp.prop_req.dir = MUSER_NVMF_WRITE;

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
do_admin_queue_complete(struct muser_dev * const d,
                        struct spdk_nvme_cmd * const cmd)
{
	struct spdk_nvme_cpl *cpl;
	struct io_q *cq0;

	assert(d);
	assert(cmd);

	cq0 = &d->cq[0];

	if (cq_is_full(d, cq0)) {
		SPDK_ERRLOG("CQ0 full (tail=%d, head=%d)\n",
		            cq0->cq.tail, cq0->cq.hdbl);
		return -1;
	}

	cpl = ((struct spdk_nvme_cpl*)cq0->addr) + cq0->cq.tail;

	/*
	 * FIXME intercept controller ID, we'll need it for converting a create
	 * I/O queue command to a fabric connect command. We assume that the
	 * will have issued the identify command first before attempting to
	 * create the I/O queues, so we'll have a chance to intercept it. This
	 * is a hack, and racy. Fix.
	 */
	if (cmd->opc == SPDK_NVME_OPC_IDENTIFY) {
		struct spdk_nvme_ctrlr_data *p = (struct spdk_nvme_ctrlr_data*)cmd->dptr.prp.prp1;
		if ((cmd->cdw10 & 0xFF) == SPDK_NVME_IDENTIFY_CTRLR && !d->cntlid)
			d->cntlid = p->cntlid;
	}

	cpl->sqhd = d->sq[0].sq.head;
	cpl->cid = cmd->cid;
	cpl->status.dnr = 0x0;
	cpl->status.m = 0x0;
	cpl->status.sct = 0x0;
	cpl->status.p = ~cpl->status.p; /* FIXME */
	cpl->status.sc = 0x0;

	cq_tail_advance(d, cq0);

	return 0;
}

/*
 * Completes a admin request, mapping the completion queue if not already done
 * so.
 */
static int
admin_queue_complete(struct muser_dev * const dev,
                     struct spdk_nvme_cmd * const cmd)
{
	assert(dev);
	assert(cmd);

	if (!dev->cq[0].addr) {
		int ret = acq_map(dev);
		if (ret) {
			SPDK_ERRLOG("failed to map CQ0: %d\n", ret);
			return -1;
		}
	}
	do_admin_queue_complete(dev, cmd);
	return 0;
}

static struct io_q*
lookup_io_q(const uint16_t qid, struct io_q * const q)
{
	assert(q);

	if (qid > MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR)
		return NULL;

	/*
	 * XXX ASQ and ACQ are lazily mapped, see relevant comment in
	 * handle_sq0tdbl_write
	 */
	if (!q[qid].addr && qid)
		return NULL;

	return &q[qid];
}

static struct io_q*
lookup_io_cq(struct muser_dev * const dev, const uint16_t qid)
{
	return lookup_io_q(qid, dev->cq);
}

static struct io_q*
lookup_io_sq(struct muser_dev * const dev, const uint16_t qid)
{
	return lookup_io_q(qid, dev->sq);
}

/*
 * Creates a completion or sumbission I/O queue.
 */
static int
handle_create_io_q(struct muser_dev * const dev,
                   struct spdk_nvme_cmd * const cmd, const bool is_cq)
{
	union spdk_nvme_create_io_q_cdw10 * cdw10;
	union spdk_nvme_create_io_cq_cdw11 * cdw11_cq = NULL;
	union spdk_nvme_create_io_sq_cdw11 * cdw11_sq = NULL;
	size_t entry_size;
	struct io_q io_q = { 0 };

	assert(dev);
	assert(cmd);

	cdw10 = (union spdk_nvme_create_io_q_cdw10*)&cmd->cdw10;

	SPDK_NOTICELOG("create I/O %cQ: QID=0x%x, QSIZE=0x%x\n",
	               is_cq ? 'C' : 'S', cdw10->bits.qid, cdw10->bits.qsize);

	if (cdw10->bits.qid >= MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR) {
		SPDK_ERRLOG("invalid QID=%d, max=%d\n", cdw10->bits.qid,
		            MUSER_DEFAULT_MAX_QPAIRS_PER_CTRLR);
		return -EINVAL;
	}

	/* TODO break rest of this function into smaller functions */
	if (is_cq) {
		if (lookup_io_cq(dev, cdw10->bits.qid)) {
			SPDK_ERRLOG("CQ%d already exists\n", cdw10->bits.qid);
			return -EEXIST;
		}
		cdw11_cq = (union spdk_nvme_create_io_cq_cdw11*)&cmd->cdw11;
		entry_size = sizeof(struct spdk_nvme_cpl);
		/* FIXME implement */
		assert(cdw11_cq->bits.pc == 0x1);
		assert(cdw11_cq->bits.ien == 0x1);
		assert(cdw11_cq->bits.iv == 0x0);
	} else {
		if (lookup_io_sq(dev, cdw10->bits.qid)) {
			SPDK_ERRLOG("SQ%d already exists\n", cdw10->bits.qid);
			return -EEXIST;
		}
		cdw11_sq = (union spdk_nvme_create_io_sq_cdw11*)&cmd->cdw11;
		if (!lookup_io_cq(dev, cdw11_sq->bits.cqid)) {
			SPDK_ERRLOG("CQ%d does not exist\n", cdw11_sq->bits.cqid);
			return -ENOENT;
		}
		entry_size = sizeof(struct spdk_nvme_cmd);
		/* FIXME implement */
		assert(cdw11_sq->bits.pc == 0x1);

		io_q.sq.cqid = cdw11_sq->bits.cqid;
	}

	io_q.id = cdw10->bits.qid;
	io_q.size = cdw10->bits.qsize + 1;
	if (io_q.size > max_queue_size(dev)) {
		SPDK_ERRLOG("queue too big, want=%d, max=%d\n", io_q.size,
		            max_queue_size(dev));
		return -E2BIG;
	}
	io_q.addr = map_one(dev->lm_ctx, cmd->dptr.prp.prp1,
	                    io_q.size * entry_size);
	if (!io_q.addr) {
		SPDK_ERRLOG("failed to map I/O queue\n");
		return -1;
	}

	SPDK_NOTICELOG("create I/O queue at 0x%p\n", io_q.addr);

	insert_queue(dev, &io_q, is_cq);

	return admin_queue_complete(dev, cmd);
}

/*
 * Returns 1 if a request has been forwarded to NVMf and need to wait for
 * the response, 0 if no need for a response, and -1 on error.
 */
static int
consume_admin_req(struct muser_dev * const dev, struct spdk_nvme_cmd * const cmd)
{
	int err;

	assert(dev);
	assert(cmd);

	SPDK_NOTICELOG("handle admin req opc=0x%x\n", cmd->opc);

	switch(cmd->opc) {
		/* TODO put all cases in order */
		case SPDK_NVME_OPC_IDENTIFY:
		case SPDK_NVME_OPC_SET_FEATURES:
		case SPDK_NVME_OPC_GET_LOG_PAGE:
		case SPDK_NVME_OPC_ASYNC_EVENT_REQUEST:
		case SPDK_NVME_OPC_NS_MANAGEMENT:
			err = handle_identify_req(dev, cmd);
			if (!err) {

				/*
				 * FIXME This request is now probably lost.
				 */
				if (cmd->opc == SPDK_NVME_OPC_ASYNC_EVENT_REQUEST)
					return 0;

				return 1;
			}
			return err;
		case SPDK_NVME_OPC_CREATE_IO_CQ:
			return handle_create_io_q(dev, cmd, true);
		case SPDK_NVME_OPC_CREATE_IO_SQ:
			return handle_create_io_q(dev, cmd, false);
		default:
			SPDK_ERRLOG("unsupported command 0x%x\n", cmd->opc);
			return -1;
	}
	return -1;
}

static int
handle_io_read(struct spdk_nvme_cmd * const cmd)
{
	uint64_t slba;
	uint16_t nlb;

	assert(cmd);

	slba = (((uint64_t)cmd->cdw11) << 32) + (uint64_t)cmd->cdw10;

	nlb = 0x0000ffff & cmd->cdw12;

	SPDK_NOTICELOG("read MPTR=0x%lx, PRP1=0x%lx, PRP2=0x%lx, SLBA=0x%lx, NLB=0x%x\n",
	               cmd->mptr, cmd->dptr.prp.prp1, cmd->dptr.prp.prp2, slba, nlb);

	assert(0);

	return 0;
}

static int
consume_io_req(struct muser_dev * const d, struct io_q * const q,
               struct spdk_nvme_cmd * const cmd)
{
	SPDK_NOTICELOG("XXX opc=0x%x\n", cmd->opc);
	switch (cmd->opc) {
		case SPDK_NVME_OPC_READ:
			return handle_io_read(cmd);
		default:
			SPDK_ERRLOG("bad I/O command 0x%x\n", cmd->opc);
			return -1;
	}
	return 0;
}

static int
consume_req(struct muser_dev * const d, struct io_q * const q,
            struct spdk_nvme_cmd * const cmd)
{
	if (q->id == 0)
		return consume_admin_req(d, cmd);
	return consume_io_req(d, q, cmd);
}

/*
 * Returns how many requests have been forwarded to NVMf and need to wait for
 * the response.
 */
static int
consume_reqs(struct muser_dev * const d, const uint32_t new_tail,
             struct io_q * const q)
{
	int count = 0;
	struct spdk_nvme_cmd * queue;

	assert(d);
	assert(q);

	/* FIXME need to validate new_sq_tail */
	/*
	 * FIXME can queue size change arbitrarily? Shall we operate on a copy ?
	 *
	 * FIXME operating on an SQ is pretty much the same for admin and I/O
	 * queues. All we need is a callback to replace consume_req,
	 * depending on the type of the queue.
	 */
	queue = q->addr;
	while (sq_tail(d, q) != new_tail) {
		struct spdk_nvme_cmd * const cmd = &queue[sq_tail(d, q)];	
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
handle_sq_tdbl_write(struct muser_dev * const d, const uint32_t new_tail,
                     struct io_q * const q)
{
	assert(d);
	assert(q);

	SPDK_NOTICELOG("write to SQ%d tail=0x%x\n", q->id, new_tail);

	/*
	 * TODO we should be mapping the queue when ASQ gets written, however
	 * the NVMe driver writes it in two steps and this complicates things,
	 * e.g. is it guaranteed to write both upper and lower portions?
	 */
	if (q->id == 0 && !d->sq[0].addr) {
		int ret = asq_map(d);
		if (ret) {
			SPDK_ERRLOG("failed to map SQ0: %d\n", ret);
			return -1;
		}
	}

	return consume_reqs(d, new_tail, q);
}

static ssize_t
handle_cq_hdbl_write(struct muser_dev * const d, const uint32_t new_head,
                     struct io_q * const q)
{
	assert(d);
	assert(q);

	/*
	 * FIXME is there anything we need to do with the new CQ0 head?
	 * Incrementing the head means the host consumed completions, right?
	 */
	SPDK_NOTICELOG("write to CQ%d head=0x%x\n", q->id, new_head);
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
get_qid_and_kind(struct muser_dev const * const dev, const loff_t pos,
                 bool * const is_sq)
{
	int i, n;

	assert(dev);
	assert(is_sq);

	n = 4 << dev->admin_qp.qpair.ctrlr->vcprop.cap.bits.dstrd;
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
		*is_sq =  false;
		i = (i - 1) / 2;
	} else { /* SQ */
		*is_sq = true;
		i = i / 2;
	}
	return i;
}

static int
handle_io_sq_tdbl_write(struct muser_dev * const dev)
{
	assert(0);
}

static int
handle_io_cq_hbdl_write(struct muser_dev * const dev)
{
	assert(0);
}

static bool
is_admin_q(struct io_q const * const queues, struct io_q const * const q)
{
	return q == &queues[0];
}

/*
 * Handles a write at offset 0x1000 or more.
 */
static int
handle_dbl_write(struct muser_dev * const dev, uint8_t const * const buf,
                 const size_t count, const loff_t pos)
{
	int err;
	uint16_t qid;
	bool is_sq;
	uint32_t v;
	struct io_q * queues;
	struct io_q * q;

	assert(dev);
	assert(buf);

	if (count != sizeof(uint32_t)) {
		SPDK_ERRLOG("bad doorbell buffer size %ld\n", count);
		return -EINVAL;
	}

	err = get_qid_and_kind(dev, pos, &is_sq);
	if (err < 0) {
		SPDK_ERRLOG("bad doorbell 0x%lx\n", pos);
		return err;
	}
	qid = err;
	v = *(int*)buf;

	if (is_sq)
		queues = dev->sq;
	else
		queues = dev->cq;

	q = lookup_io_q(qid, queues);
	if (!q) {
		SPDK_ERRLOG("%cQ%d doesn't exist\n", 'S' ? is_sq : 'C', qid);
		return -ENOENT;
	}

	if (is_sq)
		return handle_sq_tdbl_write(dev, v, q);
	return handle_cq_hdbl_write(dev, v, q);
}

static ssize_t
write_bar0(void *pvt, char *buf, size_t count, loff_t pos)
{
	struct muser_dev * const muser_dev = pvt;
	int err;

	SPDK_NOTICELOG("dev: %p, count=%zu, pos=%"PRIX64"\n",
		       muser_dev, count, pos);
	spdk_log_dump(stdout, "muser_write", buf, count);

	switch (pos) {
		/* TODO sort cases */
		case ADMIN_QUEUES:
			return admin_queue_write(muser_dev, buf, count, pos);
		case CC:
			muser_dev->admin_qp.prop_req.buf = buf;
			muser_dev->admin_qp.prop_req.count = count;
			muser_dev->admin_qp.prop_req.pos = pos;
			spdk_wmb();
			muser_dev->admin_qp.prop_req.dir = MUSER_NVMF_WRITE;
			break;		
		default:
			if (pos >= DOORBELLS) {
				err = handle_dbl_write(muser_dev, buf, count,
				                       pos);
				if (err <= 0)
					return err;
			} else {
				SPDK_ERRLOG("write to 0x%lx not implemented\n",
				            pos);
				return -ENOTSUP;	
			}
			break;
	}

	do {
		err = sem_wait(&muser_dev->admin_qp.prop_req.wait);
	} while (err != 0 && errno != EINTR);

	if (pos == SQ0TBDL) {
		admin_queue_complete(muser_dev, muser_dev->admin_qp.cmd);
	}

	return muser_dev->admin_qp.prop_req.ret;
}

static ssize_t
access_bar_fn(void *pvt, const int region_index, char * const buf, size_t count,
              loff_t offset, const bool is_write)
{
	ssize_t ret;

	if (region_index != LM_DEV_BAR0_REG_IDX) {
		SPDK_WARNLOG("unsupported access to BAR%d, dev: %p, count=%zu, pos=%"PRIX64"\n",
		       region_index, pvt, count, offset);
		return -1;
	}	

	if (is_write)
		ret = write_bar0(pvt, buf, count, offset);
	else
		ret = read_bar0(pvt, buf, count, offset);

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
    struct muser_dev * const muser_dev = (struct muser_dev*)pvt;

    if (is_write) {
        switch (offset) {
            case offsetof(struct nvme_config_space, pci_expr_cap.pxdc):
		if (count != sizeof (union pxdc)) {
			SPDK_WARNLOG("bad write size to PXDC %zu\n", count);
			return -EINVAL;
		} 
                SPDK_NOTICELOG("writing to PXDC 0x%hx\n",
		               ((union pxdc*)buf)->raw);
                return count;
        }

        fprintf(stderr, "writes non supported\n");
        return -EINVAL;
    }

    if (offset + count > PCI_EXTENDED_CONFIG_SPACE_SIZEOF) {
        fprintf(stderr, "access past end of extended PCI configuration space, want=%ld+%ld, max=%d\n",
                offset, count, PCI_EXTENDED_CONFIG_SPACE_SIZEOF);
        return -ERANGE;
    }

    memcpy(buf, ((unsigned char*)muser_dev->pci_config_space) + offset, count);

    return count;
}

static void
nvme_reg_info_fill(lm_reg_info_t *reg_info)
{
    int i;

    assert(reg_info != NULL);

    memset(reg_info, 0, sizeof(*reg_info) * LM_DEV_NUM_REGS);

    for (i = 0; i < LM_DEV_NUM_REGS; i++) {
        reg_info[i].offset = i * NVME_REG_OFFSET;
    }

    reg_info[LM_DEV_BAR0_REG_IDX].flags = LM_REG_FLAG_RW;
    reg_info[LM_DEV_BAR0_REG_IDX].size  = NVME_REG_BAR0_SIZE;

    reg_info[LM_DEV_CFG_REG_IDX].flags = LM_REG_FLAG_RW;
    reg_info[LM_DEV_CFG_REG_IDX].size  = NVME_REG_CFG_SIZE;
}

static void
nvme_log(void *pvt, char const * const msg) {
    fprintf(stderr, "%s", msg);
}

static void
nvme_dev_info_fill(lm_dev_info_t *dev_info, lm_fops_t *fops,
                   struct muser_dev *muser_dev)
{
	assert(dev_info != NULL);
	assert(muser_dev != NULL);

	dev_info->pvt = muser_dev;

	dev_info->uuid = muser_dev->uuid;

	dev_info->id.vid = 0x4e58;     // TODO: LE ?
	dev_info->id.did = 0x0001;

	/* controller uses the NVM Express programming interface */
	dev_info->cc.pi = 0x02;

	/* non-volatile memory controller */
	dev_info->cc.scc = 0x08;

	/* mass storage controller */
	dev_info->cc.bcc = 0x01;

	if (fops)
		dev_info->fops = *fops;

	dev_info->irq_count[LM_DEV_INTX_IRQ_IDX] = NVME_IRQ_INTX_NUM;
	dev_info->irq_count[LM_DEV_MSIX_IRQ_IDX] = NVME_IRQ_MSIX_NUM;

	dev_info->nr_dma_regions = 0x10;

	dev_info->bar_fn = &access_bar_fn;
	dev_info->pci_config_fn = &access_pci_config;

	dev_info->extended = true;

	nvme_reg_info_fill(dev_info->reg_info);

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
init_pci_config_space(struct nvme_config_space * const p)
{
    mlbar_t *mlbar;
    nvme_bar2_t *nvme_bar2;

    /* MLBAR */
    mlbar = (mlbar_t*)&p->hdr.bars[0].raw;
    mlbar->raw = 0x0; /* initialize register to 0 */

    /* MUBAR */
    p->hdr.bars[1].raw = 0x0;

    /*
     * BAR2, index/data pair register base address or vendor specific (optional)
     */
    nvme_bar2 = (nvme_bar2_t*)&p->hdr.bars[2].raw;
    nvme_bar2->raw = 0x0;
    nvme_bar2->rte = 0x1;

    /* vendor specific, let's set them to zero for now */
    p->hdr.bars[3].raw = 0x0;
    p->hdr.bars[4].raw = 0x0;
    p->hdr.bars[5].raw = 0x0;

    p->hdr.intr.ipin = 0x1;

    /* enables capabilities */
    p->hdr.sts.cl = 0x1;

    /*
     * TODO add function that adds a capability (takes care of updating the
     * next pointers etc.)
     */
   
    p->hdr.cap = offsetof(struct nvme_config_space, pmcap); 
    assert(p->hdr.cap = 0x40);
    /* initialize PMCAP */
    p->pmcap.pid.cid = 0x1; /* PCI power management capability */
    p->pmcap.pmcs.nsfrst = 0x1;

    p->pmcap.pid.next = offsetof(struct nvme_config_space, pci_expr_cap);
    /* initialize PXCAP */
    p->pci_expr_cap.pxid.cid = 0x10; /* PCI Express capability */
    p->pci_expr_cap.pxcap.ver = 0x2;
    p->pci_expr_cap.pxdcap.per = 0x1;
    p->pci_expr_cap.pxdcap.flrc = 0x1;
    p->pci_expr_cap.pxdcap2.ctds = 0x1;
}

static int
muser_listen(struct spdk_nvmf_transport *transport,
	     const struct spdk_nvme_transport_id *trid)
{
	struct muser_transport *muser_transport;
	struct muser_dev *muser_dev;
	lm_dev_info_t dev_info = { 0 };
	int i;
	int err;

	muser_transport = (struct muser_transport *)transport;

	err = mdev_create(trid->traddr);
	if (err == -1) {
		return -1;
	}

	muser_dev = calloc(1, sizeof(*muser_dev));
	if (muser_dev == NULL) {
		SPDK_ERRLOG("Error allocating dev: %m\n");
		goto err;
	}
	memcpy(muser_dev->uuid, trid->traddr, sizeof(muser_dev->uuid));
	memcpy(&muser_dev->trid, trid, sizeof(muser_dev->trid));

	/* Admin QP setup */
	muser_dev->admin_qp.qpair.transport = transport;
	muser_dev->admin_qp.dev = muser_dev;

	TAILQ_INIT(&muser_dev->admin_qp.reqs);

	err = sem_init(&muser_dev->admin_qp.prop_req.wait, 0, 0);
	assert(err == 0);

	muser_dev->admin_qp.rsps_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(union nvmf_c2h_msg));
	if (muser_dev->admin_qp.rsps_internal == NULL) {
		SPDK_ERRLOG("Error allocating rsps: %m\n");
		goto err_free_dev;
	}

	muser_dev->admin_qp.cmds_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(union nvmf_h2c_msg));
	if (muser_dev->admin_qp.cmds_internal == NULL) {
		SPDK_ERRLOG("Error allocating cmds: %m\n");
		goto err_free_rsps;
	}

	muser_dev->admin_qp.reqs_internal = calloc(MUSER_DEFAULT_AQ_DEPTH,
						   sizeof(struct muser_req));
	if (muser_dev->admin_qp.reqs_internal == NULL) {
		SPDK_ERRLOG("Error allocating reqs: %m\n");
		goto err_free_cmds;
	}

	for (i = 0; i < MUSER_DEFAULT_AQ_DEPTH; i++) {
		muser_dev->admin_qp.reqs_internal[i].req.qpair =
				&muser_dev->admin_qp.qpair;
		muser_dev->admin_qp.reqs_internal[i].req.rsp =
				&muser_dev->admin_qp.rsps_internal[i];
		muser_dev->admin_qp.reqs_internal[i].req.cmd =
				&muser_dev->admin_qp.cmds_internal[i];
		TAILQ_INSERT_TAIL(&muser_dev->admin_qp.reqs,
				  &muser_dev->admin_qp.reqs_internal[i],
				  link);
	}

	/* LM setup */
	nvme_dev_info_fill(&dev_info, NULL, muser_dev);
	muser_dev->lm_ctx = lm_ctx_create(&dev_info);
	if (muser_dev->lm_ctx == NULL) {
		/* TODO: lm_create doesn't set errno */
		SPDK_ERRLOG("Error creating libmuser ctx: %m\n");
		goto err_free_reqs;
	}


	muser_dev->pci_config_space = lm_get_pci_config_space(muser_dev->lm_ctx);
	init_pci_config_space((struct nvme_config_space*)muser_dev->pci_config_space);

	err = pthread_create(&muser_dev->lm_thr, NULL,
			     drive, muser_dev->lm_ctx);
	if (err != 0) {
		/* TODO: pthread_create doesn't set errno */
		SPDK_ERRLOG("Error creating lm_drive thread: %m\n");
		goto err_destroy;
	}

	TAILQ_INSERT_TAIL(&muser_transport->devs, muser_dev, link);

	return 0;

err_destroy:
	lm_ctx_destroy(muser_dev->lm_ctx);
err_free_reqs:
	free(muser_dev->admin_qp.reqs_internal);
err_free_cmds:
	free(muser_dev->admin_qp.cmds_internal);
err_free_rsps:
	free(muser_dev->admin_qp.rsps_internal);
err_free_dev:
	free(muser_dev);
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
muser_accept(struct spdk_nvmf_transport *transport, new_qpair_fn cb_fn)
{
	struct muser_transport *muser_transport;
	struct muser_dev *muser_dev;

	muser_transport = (struct muser_transport *)transport;

	TAILQ_FOREACH(muser_dev, &muser_transport->devs, link) {
		if (muser_dev->setup == false) {
			cb_fn(&muser_dev->admin_qp.qpair);
			muser_dev->setup = true;
		}
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

	return (struct spdk_nvmf_transport_poll_group *)muser_group;
}

static void
muser_poll_group_destroy(struct spdk_nvmf_transport_poll_group *group)
{
    struct muser_poll_group *poll_group;

    poll_group = (struct muser_poll_group *)group;

    free(poll_group);
}

static int
muser_poll_group_add(struct spdk_nvmf_transport_poll_group *group,
		     struct spdk_nvmf_qpair *qpair)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	struct muser_req *muser_req;
	struct muser_dev *muser_dev;

	muser_group = (struct muser_poll_group *)group;
	muser_qpair = SPDK_CONTAINEROF(qpair, struct muser_qpair, qpair);
	muser_dev = muser_qpair->dev;

	/* Admin QP */
	if (qpair->qid == 0) {
		struct spdk_nvmf_request *req;
		struct spdk_nvmf_fabric_connect_data *data;

		muser_req = TAILQ_FIRST(&muser_qpair->reqs);
		TAILQ_REMOVE(&muser_qpair->reqs, muser_req, link);

		req = &muser_req->req;
		req->cmd->connect_cmd.opcode = SPDK_NVME_OPC_FABRIC;
		req->cmd->connect_cmd.cid = 0;
		req->cmd->connect_cmd.fctype = SPDK_NVMF_FABRIC_COMMAND_CONNECT;
		req->cmd->connect_cmd.recfmt = 0;
		req->cmd->connect_cmd.sqsize = MUSER_DEFAULT_AQ_DEPTH - 1;
		req->cmd->connect_cmd.qid = 0;

		req->length = sizeof(struct spdk_nvmf_fabric_connect_data);
		req->data = calloc(1, req->length);
		assert(req->data != NULL);
		/* TODO: Pre-allocate memory */

		data = (struct spdk_nvmf_fabric_connect_data *)req->data;
		/* data->hostid = { 0 } */
		data->cntlid = 0xffff;
		snprintf(data->subnqn, sizeof(data->subnqn),
			 "nqn.2019-07.io.spdk.muser:%s", muser_dev->uuid);
		/* data->hostnqn = { 0 } */

		spdk_nvmf_request_exec(req);
	}

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

static int
handle_req(struct muser_qpair * const muser_qpair)
{
	struct spdk_nvmf_request *req;
	struct muser_req *muser_req;

	assert(muser_qpair);

	muser_req = TAILQ_FIRST(&muser_qpair->reqs);
	TAILQ_REMOVE(&muser_qpair->reqs, muser_req, link);

	req = &muser_req->req;

	if (muser_qpair->cmd) {
		/* FIXME figure out how to initialize this field. */
		req->xfer = SPDK_NVME_DATA_CONTROLLER_TO_HOST;
		req->cmd->nvme_cmd = *muser_qpair->cmd;
		req->length = 1 << 12;
		req->data = (void*)(req->cmd->nvme_cmd.dptr.prp.prp1 << muser_qpair->dev->regs.cc.bits.mps);
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
		req->cmd->prop_set_cmd.attrib.size = (muser_qpair->prop_req.count/4)-1;
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
		;
	} else if (muser_qpair->prop_req.dir == MUSER_NVMF_READ) {
		memcpy(muser_qpair->prop_req.buf,
		       &req->rsp->prop_get_rsp.value.u64,
		       muser_qpair->prop_req.count);
	}

	muser_qpair->prop_req.dir = MUSER_NVMF_INVALID;
	return sem_post(&muser_qpair->prop_req.wait);
}

static int
muser_poll_group_poll(struct spdk_nvmf_transport_poll_group *group)
{
	struct muser_poll_group *muser_group;
	struct muser_qpair *muser_qpair;
	int err;

	muser_group = (struct muser_poll_group *)group;

	TAILQ_FOREACH(muser_qpair, &muser_group->qps, link) {
		spdk_rmb();
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
	struct muser_dev *muser_dev;

	muser_qpair = (struct muser_qpair *)qpair;
	muser_dev = muser_qpair->dev;

	memcpy(trid, &muser_dev->trid, sizeof(*trid));
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
	struct muser_dev *muser_dev;

	muser_qpair = (struct muser_qpair *)qpair;
	muser_dev = muser_qpair->dev;

	memcpy(trid, &muser_dev->trid, sizeof(*trid));
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
