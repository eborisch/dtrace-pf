# $FreeBSD: release/10.1.0/sys/modules/mrsas/Makefile 265555 2014-05-07 16:16:49Z ambrisko $

.PATH:	${.CURDIR}/../../dev/mrsas

KMOD=	mrsas
SRCS=	mrsas.c mrsas_cam.c mrsas_ioctl.c mrsas_fp.c
SRCS+=	device_if.h bus_if.h pci_if.h opt_cam.h opt_scsi.h

#CFLAGS+= -MRSAS_DEBUG
.include <bsd.kmod.mk>
#CFLAGS+= -fgnu89-inline

clean_cscope:
	rm -f cscope*

cscope:	clean_cscope
	/usr/local/bin/cscope -b *.[ch]

cleanall:	clean clean_cscope
	rm -f '@' machine
