# $FreeBSD: release/10.1.0/lib/clang/libllvmanalysis/Makefile 263508 2014-03-21 17:53:59Z dim $

.include <bsd.own.mk>

LIB=	llvmanalysis

SRCDIR=	lib/Analysis
SRCS=	AliasAnalysis.cpp \
	AliasAnalysisCounter.cpp \
	AliasAnalysisEvaluator.cpp \
	AliasDebugger.cpp \
	AliasSetTracker.cpp \
	Analysis.cpp \
	BasicAliasAnalysis.cpp \
	BranchProbabilityInfo.cpp \
	CFG.cpp \
	CFGPrinter.cpp \
	CaptureTracking.cpp \
	CodeMetrics.cpp \
	ConstantFolding.cpp \
	CostModel.cpp \
	Delinearization.cpp \
	DependenceAnalysis.cpp \
	DomPrinter.cpp \
	DominanceFrontier.cpp \
	IVUsers.cpp \
	InstCount.cpp \
	InstructionSimplify.cpp \
	Interval.cpp \
	IntervalPartition.cpp \
	LazyValueInfo.cpp \
	LibCallAliasAnalysis.cpp \
	LibCallSemantics.cpp \
	Lint.cpp \
	Loads.cpp \
	LoopInfo.cpp \
	LoopPass.cpp \
	MemDepPrinter.cpp \
	MemoryBuiltins.cpp \
	MemoryDependenceAnalysis.cpp \
	ModuleDebugInfoPrinter.cpp \
	NoAliasAnalysis.cpp \
	PHITransAddr.cpp \
	PostDominators.cpp \
	PtrUseVisitor.cpp \
	RegionInfo.cpp \
	RegionPass.cpp \
	RegionPrinter.cpp \
	ScalarEvolution.cpp \
	ScalarEvolutionAliasAnalysis.cpp \
	ScalarEvolutionExpander.cpp \
	ScalarEvolutionNormalization.cpp \
	SparsePropagation.cpp \
	TargetTransformInfo.cpp \
	Trace.cpp \
	TypeBasedAliasAnalysis.cpp \
	ValueTracking.cpp

.if ${MK_CLANG_EXTRAS} != "no"
SRCS+=	BlockFrequencyInfo.cpp
.endif

TGHDRS=	Intrinsics

.include "../clang.lib.mk"
