#!/bin/sh

GITID=$1
TARBALL=$2
DIR=$3

XZ_THREADS=`rpm --eval %{_smp_mflags} | sed -e 's!^-j!--threads !'`

ARCH=`uname -m`
if [ "$ARCH" == "i686" -o "$ARCH" == "ppc" ]
then
	XZ_MEMLIMIT="-M 3G"
fi


if [ -f ${TARBALL} ]; then
	TARID=`( xzcat -qq ${TARBALL} | git get-tar-commit-id ) 2>/dev/null`
	if [ "${GITID}" = "${TARID}" ]; then
		echo "`basename ${TARBALL}` unchanged..."
		exit 0
	fi
	rm -f ${TARBALL}
fi

echo "Creating `basename ${TARBALL}`..."
trap 'rm -vf ${TARBALL}' INT
cd ../ &&
  git archive --prefix=${DIR}/ --format=tar ${GITID} | xz ${XZ_MEMLIMIT} ${XZ_THREADS} > ${TARBALL};
