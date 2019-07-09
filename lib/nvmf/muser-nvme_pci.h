#include <muser/pmcap.h>
#include <muser/pxcap.h>

typedef union {
    uint32_t raw;
    struct {
        unsigned int rte:1;
        unsigned int tp:2;
        unsigned int pf:1;
        unsigned int res1:10;
        unsigned int ba:16;
    } __attribute__ ((packed));
} __attribute__((packed)) mlbar_t;
_Static_assert(sizeof(mlbar_t) == 0x4, "bad MLBAR size");

typedef union {
    uint32_t raw;
    struct {
        unsigned int rte:1;
        unsigned int res1:2;
        unsigned int ba:29;
    } __attribute__ ((packed));
} __attribute__ ((packed)) nvme_bar2_t;
_Static_assert(sizeof(nvme_bar2_t) == 0x4, "bad NVMe BAR2 size");

struct nvme_config_space {
    lm_pci_hdr_t hdr;
    struct pmcap pmcap;
    struct PCI_Express_Capability pci_expr_cap;
} __attribute__((packed));

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
