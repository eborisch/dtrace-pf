/*	$NetBSD: obiovar.h,v 1.4 2003/06/16 17:40:53 thorpej Exp $	*/

/*-
 * Copyright (c) 2002, 2003 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD: release/10.1.0/sys/mips/idt/obiovar.h 202175 2010-01-12 21:36:08Z imp $
 *
 */

#ifndef _ADM5120_OBIOVAR_H_
#define	_ADM5120_OBIOVAR_H_

#include <sys/rman.h>

/* Number of controller's IRQs */
#define	NIRQS	32*5

/* Number of CPU IRQ lines */
#define	MIPS_IRQS	5

#define	OBIO_MEM_START	0x18000000L
#define	OBIO_MEM_SIZE	0x200000

struct obio_softc {
	struct rman		oba_mem_rman;
	struct rman		oba_irq_rman;
	struct intr_event	*sc_eventstab[NIRQS];	/* IRQ events structs */
	struct resource		*sc_irq[MIPS_IRQS];	/* IRQ resource */
	void			*sc_ih[MIPS_IRQS];	/* interrupt cookie */
};

struct obio_ivar {
	struct resource_list	resources;
};

#endif /* _ADM5120_OBIOVAR_H_ */