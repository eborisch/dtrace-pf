# $FreeBSD: release/10.1.0/sys/modules/libmbpool/Makefile 117624 2003-07-15 08:59:38Z harti $

.PATH: ${.CURDIR}/../../kern

KMOD=	libmbpool
SRCS=	subr_mbpool.c

EXPORT_SYMS=	mbp_create	\
		mbp_destroy	\
		mbp_alloc	\
		mbp_free	\
		mbp_ext_free	\
		mbp_card_free	\
		mbp_count	\
		mbp_get		\
		mbp_get_keep	\
		mbp_sync

.include <bsd.kmod.mk>
