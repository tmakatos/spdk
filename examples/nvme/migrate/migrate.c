/*-
 *   BSD LICENSE
 *
 * Copyright (c) 2021 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
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

#include "spdk/stdinc.h"

#include "spdk/nvme.h"
#include "spdk/vmd.h"
#include "spdk/nvme_zns.h"
#include "spdk/env.h"

#include "lib/nvme/nvme_internal.h"

#include <vfio-user/libvfio-user.h>

struct ctrlr_entry {
	struct spdk_nvme_ctrlr		*ctrlr;
	TAILQ_ENTRY(ctrlr_entry)	link;
	char				name[1024];
};

struct ns_entry {
	struct spdk_nvme_ctrlr	*ctrlr;
	struct spdk_nvme_ns	*ns;
	TAILQ_ENTRY(ns_entry)	link;
	struct spdk_nvme_qpair	*qpair;
};

static bool g_vmd = false;
static struct spdk_nvme_transport_id g_trid;
static char g_hostnqn[SPDK_NVMF_NQN_MAX_LEN + 1];
static int g_controllers_found = 0;
static int g_main_core = 0;
static char g_core_mask[16] = "0x1";

static void
usage(const char *program_name)
{
	printf("%s [options]", program_name);
	printf("\n");
	printf("options:\n");
	printf(" -V         enumerate VMD\n");
}

static int
parse_args(int argc, char **argv)
{
	int op;
	char *hostnqn;

	while ((op = getopt(argc, argv, "r:V")) != -1) {
		switch (op) {
		case 'r':
			if (spdk_nvme_transport_id_parse(&g_trid, optarg) != 0) {
				fprintf(stderr, "Error parsing transport address\n");
				return 1;
			}

			hostnqn = strcasestr(optarg, "hostnqn:");
			if (hostnqn) {
				size_t len;

				hostnqn += strlen("hostnqn:");

				len = strcspn(hostnqn, " \t\n");
				if (len > (sizeof(g_hostnqn) - 1)) {
					fprintf(stderr, "Host NQN is too long\n");
					return 1;
				}

				memcpy(g_hostnqn, hostnqn, len);
				g_hostnqn[len] = '\0';
			}
			break;
		case 'V':
			g_vmd = true;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc;
	struct spdk_env_opts opts;
	struct spdk_nvme_ctrlr *ctrlr;
	int migration_region;
	uint32_t device_state;

	rc = parse_args(argc, argv);
	if (rc != 0) {
		return rc;
	}

	/*
	 * SPDK relies on an abstraction around the local environment
	 * named env that handles memory allocation and PCI device operations.
	 * This library must be initialized first.
	 *
	 */
	spdk_env_opts_init(&opts);
	opts.name = "migrate";
	opts.shm_id = -1;
	opts.no_pci = true;

	/* FIXME necessary? */
#if 1
	opts.main_core = g_main_core;
	opts.core_mask = g_core_mask;
	opts.mem_channel = 1;
	opts.hugepage_single_segments = true;
#endif

	if (spdk_env_init(&opts) < 0) {
		fprintf(stderr, "Unable to initialize SPDK env\n");
		return 1;
	}

	printf("Initializing NVMe Controllers\n");

	if (g_vmd && spdk_vmd_init()) {
		fprintf(stderr, "Failed to initialize VMD."
			" Some NVMe devices can be unavailable.\n");
	}

	/* A specific trid is required. */
	if (strlen(g_trid.traddr) != 0) {
		struct spdk_nvme_ctrlr_opts opts;

		spdk_nvme_ctrlr_get_default_ctrlr_opts(&opts, sizeof(opts));
		memcpy(opts.hostnqn, g_hostnqn, sizeof(opts.hostnqn));
		ctrlr = spdk_nvme_connect(&g_trid, &opts, sizeof(opts));
		if (!ctrlr) {
			fprintf(stderr, "spdk_nvme_connect to %s failed\n",
				opts.hostnqn);
			return 1;
		}

		g_controllers_found++;
	} else {
		assert(false);
	}

	if (g_controllers_found == 0) {
		fprintf(stderr, "No NVMe controllers found.\n");
	}

	printf("Initialization complete.\n");

	/* read migration device state */
	migration_region = nvme_vfio_ctrlr_get_migration_region(ctrlr);
	printf("migration region = %d\n", migration_region);

	rc = nvme_transport_ctrlr_get_reg_4(ctrlr,
	                                    vfu_region_to_offset(migration_region) + offsetof(struct vfio_device_migration_info, device_state),
	                                    &device_state);
	assert(rc == 0);
	printf("device state = %d\n", device_state);
	rc = nvme_transport_ctrlr_set_reg_4(ctrlr,
	                                    vfu_region_to_offset(migration_region) + offsetof(struct vfio_device_migration_info, device_state),
	                                    VFIO_DEVICE_STATE_SAVING);
	assert(rc == 0);

	if (g_vmd) {
		spdk_vmd_fini();
	}

	return 0;
}
