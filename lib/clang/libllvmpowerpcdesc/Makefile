# $FreeBSD: release/10.1.0/lib/clang/libllvmpowerpcdesc/Makefile 263508 2014-03-21 17:53:59Z dim $

.include <bsd.own.mk>

LIB=	llvmpowerpcdesc

SRCDIR=	lib/Target/PowerPC/MCTargetDesc
SRCS=	PPCAsmBackend.cpp \
	PPCELFObjectWriter.cpp \
	PPCMCAsmInfo.cpp \
	PPCMCCodeEmitter.cpp \
	PPCMCExpr.cpp \
	PPCMCTargetDesc.cpp \
	PPCMachObjectWriter.cpp \
	PPCPredicates.cpp
CFLAGS+= -I${LLVM_SRCS}/${SRCDIR}/..

TGHDRS=	PPCGenInstrInfo \
	PPCGenMCCodeEmitter \
	PPCGenRegisterInfo \
	PPCGenSubtargetInfo

.include "../clang.lib.mk"
