#
# $FreeBSD: release/10.1.0/sys/modules/cxgbe/Makefile 270297 2014-08-21 19:54:02Z np $
#

SUBDIR=	if_cxgbe
SUBDIR+=	t4_firmware
SUBDIR+=	t5_firmware
SUBDIR+=	${_tom}
SUBDIR+=	${_iw_cxgbe}

.if ${MACHINE_CPUARCH} == "amd64"
_tom=	tom
_iw_cxgbe=	iw_cxgbe
.endif

.if ${MACHINE_CPUARCH} == "i386"
_tom=	tom
.endif


.include <bsd.subdir.mk>
