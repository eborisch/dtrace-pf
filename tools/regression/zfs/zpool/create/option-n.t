#!/bin/sh
# $FreeBSD: release/10.1.0/tools/regression/zfs/zpool/create/option-n.t 185029 2008-11-17 20:49:29Z pjd $

dir=`dirname $0`
. ${dir}/../../misc.sh

echo "1..5"

disks_create 1
names_create 1

expect_fl is_mountpoint /${name0}
exp=`(
  echo "would create '${name0}' with the following layout:"
  echo "	${name0}"
  echo "	  ${disk0}"
)`
expect "${exp}" ${ZPOOL} create -n ${name0} ${disk0}
expect_fl is_mountpoint /${name0}
expect_fl ${ZPOOL} status -x ${name0}
expect_fl ${ZPOOL} destroy ${name0}

disks_destroy
