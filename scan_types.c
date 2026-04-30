#include "ft_nmap.h"

const t_scan_type g_scan_types[SCAN_COUNT] = {
    { SCAN_SYN,  TH_SYN,                     "SYN"  },
    { SCAN_NULL, 0,                            "NULL" },
    { SCAN_ACK,  TH_ACK,                     "ACK"  },
    { SCAN_FIN,  TH_FIN,                     "FIN"  },
    { SCAN_XMAS, TH_FIN | TH_PUSH | TH_URG, "XMAS" },
    { SCAN_UDP,  0,                            "UDP"  },
};
