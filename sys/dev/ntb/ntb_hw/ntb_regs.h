/*-
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: release/10.1.0/sys/dev/ntb/ntb_hw/ntb_regs.h 255279 2013-09-05 23:11:11Z carl $
 */

#ifndef _NTB_REGS_H_
#define _NTB_REGS_H_

#define NTB_LINK_ENABLE		0x0000
#define NTB_LINK_DISABLE	0x0002
#define NTB_LINK_STATUS_ACTIVE	0x2000
#define NTB_LINK_SPEED_MASK	0x000f
#define NTB_LINK_WIDTH_MASK	0x03f0

#define XEON_MSIX_CNT		4
#define XEON_MAX_SPADS		16
#define XEON_MAX_COMPAT_SPADS	8
/* Reserve the uppermost bit for link interrupt */
#define XEON_MAX_DB_BITS	15
#define XEON_DB_BITS_PER_VEC	5

#define XEON_DB_HW_LINK		0x8000

#define XEON_PCICMD_OFFSET	0x0504
#define XEON_DEVCTRL_OFFSET	0x0598
#define XEON_LINK_STATUS_OFFSET	0x01a2

#define XEON_PBAR2LMT_OFFSET	0x0000
#define XEON_PBAR4LMT_OFFSET	0x0008
#define XEON_PBAR2XLAT_OFFSET	0x0010
#define XEON_PBAR4XLAT_OFFSET	0x0018
#define XEON_SBAR2LMT_OFFSET	0x0020
#define XEON_SBAR4LMT_OFFSET	0x0028
#define XEON_SBAR2XLAT_OFFSET	0x0030
#define XEON_SBAR4XLAT_OFFSET	0x0038
#define XEON_SBAR0BASE_OFFSET	0x0040
#define XEON_SBAR2BASE_OFFSET	0x0048
#define XEON_SBAR4BASE_OFFSET	0x0050
#define XEON_NTBCNTL_OFFSET	0x0058
#define XEON_SBDF_OFFSET	0x005c
#define XEON_PDOORBELL_OFFSET	0x0060
#define XEON_PDBMSK_OFFSET	0x0062
#define XEON_SDOORBELL_OFFSET	0x0064
#define XEON_SDBMSK_OFFSET	0x0066
#define XEON_USMEMMISS		0x0070
#define XEON_SPAD_OFFSET	0x0080
#define XEON_SPADSEMA4_OFFSET	0x00c0
#define XEON_WCCNTRL_OFFSET	0x00e0
#define XEON_B2B_SPAD_OFFSET	0x0100
#define XEON_B2B_DOORBELL_OFFSET	0x0140
#define XEON_B2B_XLAT_OFFSET	0x0144

#define SOC_MSIX_CNT		34
#define SOC_MAX_SPADS		16
#define SOC_MAX_COMPAT_SPADS	16
#define SOC_MAX_DB_BITS		34
#define SOC_DB_BITS_PER_VEC	1

#define SOC_PCICMD_OFFSET	0xb004
#define SOC_MBAR23_OFFSET	0xb018
#define SOC_MBAR45_OFFSET	0xb020
#define SOC_DEVCTRL_OFFSET	0xb048
#define SOC_LINK_STATUS_OFFSET	0xb052
#define SOC_ERRCORSTS_OFFSET	0xb110

#define SOC_SBAR2XLAT_OFFSET	0x0008
#define SOC_SBAR4XLAT_OFFSET	0x0010
#define SOC_PDOORBELL_OFFSET	0x0020
#define SOC_PDBMSK_OFFSET	0x0028
#define SOC_NTBCNTL_OFFSET	0x0060
#define SOC_EBDF_OFFSET		0x0064
#define SOC_SPAD_OFFSET		0x0080
#define SOC_SPADSEMA_OFFSET	0x00c0
#define SOC_STKYSPAD_OFFSET	0x00c4
#define SOC_PBAR2XLAT_OFFSET	0x8008
#define SOC_PBAR4XLAT_OFFSET	0x8010
#define SOC_B2B_DOORBELL_OFFSET	0x8020
#define SOC_B2B_SPAD_OFFSET	0x8080
#define SOC_B2B_SPADSEMA_OFFSET	0x80c0
#define SOC_B2B_STKYSPAD_OFFSET	0x80c4

#define SOC_MODPHY_PCSREG4	0x1c004
#define SOC_MODPHY_PCSREG6	0x1c006

#define SOC_IP_BASE		0xc000
#define SOC_DESKEWSTS_OFFSET	(SOC_IP_BASE + 0x3024)
#define	SOC_LTSSMERRSTS0_OFFSET (SOC_IP_BASE + 0x3180)
#define SOC_LTSSMSTATEJMP_OFFSET	(SOC_IP_BASE + 0x3040)
#define SOC_IBSTERRRCRVSTS0_OFFSET	(SOC_IP_BASE + 0x3324)

#define SOC_DESKEWSTS_DBERR	(1 << 15)
#define SOC_LTSSMERRSTS0_UNEXPECTEDEI	(1 << 20)
#define SOC_LTSSMSTATEJMP_FORCEDETECT	(1 << 2)
#define SOC_IBIST_ERR_OFLOW	0x7fff7fff

#define NTB_CNTL_BAR23_SNOOP	(1 << 2)
#define NTB_CNTL_BAR45_SNOOP	(1 << 6)
#define SOC_CNTL_LINK_DOWN	(1 << 16)

#define XEON_PBAR23SZ_OFFSET	0x00d0
#define XEON_PBAR45SZ_OFFSET	0x00d1
#define NTB_PPD_OFFSET		0x00d4
#define XEON_PPD_CONN_TYPE	0x0003
#define XEON_PPD_DEV_TYPE	0x0010
#define SOC_PPD_INIT_LINK	0x0008
#define SOC_PPD_CONN_TYPE	0x0300
#define SOC_PPD_DEV_TYPE	0x1000

#define NTB_CONN_CLASSIC 	0
#define NTB_CONN_B2B 		1
#define NTB_CONN_RP 		2

#define NTB_DEV_DSD	1
#define NTB_DEV_USD	0

#define PBAR2XLAT_USD_ADDR	0x0000004000000000
#define PBAR4XLAT_USD_ADDR	0x0000008000000000
#define MBAR01_USD_ADDR		0x000000210000000c
#define MBAR23_USD_ADDR		0x000000410000000c
#define MBAR45_USD_ADDR		0x000000810000000c
#define PBAR2XLAT_DSD_ADDR	0x0000004100000000
#define PBAR4XLAT_DSD_ADDR	0x0000008100000000
#define MBAR01_DSD_ADDR		0x000000200000000c
#define MBAR23_DSD_ADDR		0x000000400000000c
#define MBAR45_DSD_ADDR		0x000000800000000c

/* XEON Shadowed MMIO Space */
#define XEON_SHADOW_PDOORBELL_OFFSET	0x60
#define XEON_SHADOW_SPAD_OFFSET		0x80

#endif /* _NTB_REGS_H_ */
