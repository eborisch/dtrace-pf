# $FreeBSD: release/10.1.0/usr.sbin/sa/Makefile 264996 2014-04-27 01:15:10Z jmmv $

.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../usr.bin/lastcomm

PROG=	sa
MAN=	sa.8
SRCS=	main.c db.c pdb.c usrdb.c readrec.c

.if ${MK_TESTS} != "no"
SUBDIR+= tests
.endif

.include <bsd.prog.mk>
