# $FreeBSD: release/10.1.0/sbin/mount_fusefs/Makefile 241519 2012-10-13 23:54:26Z attilio $

.if defined(DEBUG)
DEBUG_FLAGS+= -D_DEBUG -g
.endif

.if defined(DEBUG2G)
DEBUG_FLAGS+= -D_DEBUG2G -g
.endif

.if defined(DEBUG3G)
DEBUG_FLAGS+= -D_DEBUG3G -g
.endif

.if defined(DEBUG_MSG)
DEBUG_FLAGS+= -D_DEBUG_MSG
.endif

.if defined(F4BVERS)
DEBUG_FLAGS+= -DFUSE4BSD_VERSION="\"${F4BVERS}\""
.endif

PROG=	mount_fusefs
SRCS=	mount_fusefs.c getmntopts.c
MAN8=	mount_fusefs.8
NO_MANCOMPRESS?=	yes

MOUNT=	${.CURDIR}/../mount
CFLAGS+=	-I${MOUNT}

.PATH: ${MOUNT}

.include <bsd.prog.mk>
