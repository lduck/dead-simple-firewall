#! /bin/sh

IT=/sbin/iptables
MP=/sbin/modprobe
IP=/sbin/ip

cd /etc/firewall/_scripts

NOW=`date +%s`

echo "Generating fw-$NOW.txt"
./fw.php --dump > data/fw-$NOW.txt

echo "Generating routes-$NOW.sh"
./fw.php --dump-routes > data/routes-$NOW.sh

echo "Inserting conntrack modules"

find /lib/modules/`uname -r`/kernel/net -name nf_nat_\*.ko -o -name nf_conntrack_\*.ko | while read M; do
	TMP=${M##*/}
	MODULENAME=${TMP%.ko}
	$MP $MODULENAME > /dev/null 2>&1
done

# echo "Keeping memorable moments"
# svn commit ../

echo "Applying FW"
iptables-restore < data/fw-$NOW.txt

echo "Applying ROUTES"
. ./data/routes-$NOW.sh > /dev/null 2>&1
