#! /bin/sh
# $FreeBSD: release/10.1.0/usr.bin/make/tests/basic/t3/legacy_test.sh 263346 2014-03-19 12:29:20Z jmmv $

. $(dirname $0)/../../common.sh

# Description
DESC="No Makefile file, no command line target."

# Run
TEST_N=1
TEST_1=

eval_cmd $*
