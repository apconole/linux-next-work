#!/bin/sh

SOURCES=$1
SPECFILE=$2
PKGRELEASE=$3
RPMVERSION=$4
RELEASED_KERNEL=$5
SPECRELEASE=$6
DISTRO_BUILD=$7
ZSTREAM_FLAG=$8
BUILDOPTS=$9
clogf="$SOURCES/changelog"
# hide [redhat] entries from changelog
HIDE_REDHAT=1;
# hide entries for unsupported arches
HIDE_UNSUPPORTED_ARCH=1;
# override LC_TIME to avoid date conflicts when building the srpm
LC_TIME=
STAMP=$(echo $MARKER | cut -f 1 -d '-' | sed -e "s/v//");
RPM_VERSION="$RPMVERSION-$PKGRELEASE";

echo >$clogf

lasttag=$(git rev-list --first-parent --grep="^\[redhat\] kernel-${RPMVERSION}" --max-count=1 HEAD)
echo "Gathering new log entries since $lasttag"
git log --topo-order --reverse --no-merges -z --format="- %s (%an)%n%b" ${lasttag}.. |
	${0%/*}/genlog.py >> "$clogf"

cat $clogf | grep -v "tagging $RPM_VERSION" > $clogf.stripped
cp $clogf.stripped $clogf

if [ "x$HIDE_REDHAT" == "x1" ]; then
	cat $clogf | grep -v -e "^- \[redhat\]" |
		sed -e 's!\[Fedora\]!!g' > $clogf.stripped
	cp $clogf.stripped $clogf
fi

if [ "x$HIDE_UNSUPPORTED_ARCH" == "x1" ]; then
	cat $clogf | egrep -v "^- \[(alpha|arc|arm|arm64|avr32|blackfin|c6x|cris|frv|h8300|hexagon|ia64|m32r|m68k|metag|microblaze|mips|mn10300|openrisc|parisc|score|sh|sparc|tile|um|unicore32|xtensa)\]" > $clogf.stripped
	cp $clogf.stripped $clogf
fi

LENGTH=$(wc -l $clogf | awk '{print $1}')

#the changelog was created in reverse order
#also remove the blank on top, if it exists
#left by the 'print version\n' logic above
cname="$(git var GIT_COMMITTER_IDENT |sed 's/>.*/>/')"
cdate="$(LC_ALL=C date +"%a %b %d %Y")"
cversion="[$RPM_VERSION]";
tac $clogf | sed "1{/^$/d; /^- /i\
* $cdate $cname $cversion
	}" > $clogf.rev

if [ "$LENGTH" = 0 ]; then
	rm -f $clogf.rev; touch $clogf.rev
fi

# add extra description if localdesc file is found. useful for
# test builds that go to customer (added disclaimer)
EXTRA_DESC=../localdesc
if [ -f "$EXTRA_DESC" ]; then
       sed -i -e "/%%EXTRA_DESC/r $EXTRA_DESC" $SPECFILE
fi

test -n "$SPECFILE" &&
        sed -i -e "
	/%%CHANGELOG%%/r $clogf.rev
	/%%CHANGELOG%%/d
	/%%EXTRA_DESC%%/d
	s/%%RPMVERSION%%/$RPMVERSION/
	s/%%PKGRELEASE%%/$PKGRELEASE/
	s/%%SPECRELEASE%%/$SPECRELEASE/
	s/%%DISTRO_BUILD%%/$DISTRO_BUILD/
	s/%%RELEASED_KERNEL%%/$RELEASED_KERNEL/" $SPECFILE

for opt in $BUILDOPTS; do
	add_opt=
	[ -z "${opt##+*}" ] && add_opt="_with_${opt#?}"
	[ -z "${opt##-*}" ] && add_opt="_without_${opt#?}"
	[ -n "$add_opt" ] && sed -i "s/^\\(# The following build options\\)/%define $add_opt 1\\n\\1/" $SPECFILE
done

rm -f $clogf{,.rev,.stripped};

