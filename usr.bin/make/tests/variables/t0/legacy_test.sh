#! /bin/sh
# $FreeBSD: release/10.1.0/usr.bin/make/tests/variables/t0/legacy_test.sh 263346 2014-03-19 12:29:20Z jmmv $

. $(dirname $0)/../../common.sh

# Description
DESC="Variable expansion."

eval_cmd $*
