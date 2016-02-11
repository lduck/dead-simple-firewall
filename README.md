Dead Simple Firewall (for complicated networks)

Everybody who configured firewall rules for a large network would agree
that as the number of interfaces and rules increases, keeping it readable
and effective requires almost superhuman capabilities. Changes are prone
to errors, debugging is almost impossible.

This project makes it possible (and even easy) to maintain firewall rules
for network of any size.

Let's say you have a linux firewall which routes packets between many
different interfaces (most usually these are various VLANs over several
bridge, bond, and physical interfaces). Instead of placing all of your
firewall rules in a single script, or hand-creating the many custom chains,
you would follow these simple steps:

1) create the main configuration file, fw.cfg. In this file,
you would define all 30 networks. In our sample configuration we only
have 7: admins, sales, printers, dmznet, phones, remote, world

2) create a directory for each SOURCE network.

3) create a file for each DESTINATION network.

4) put rules concerning these two networks into each file. That's the most
important part. For connection from network A to network B, you put rules
to networkA/networkB file.

5) when happy, just run fw.sh

It couldn't get easier than that!

The firewall script will create a separate chain for each pair of networks,
so you don't need to concern yourself with matching the source and destination
nets. For example, if you would like to allow SSH from the entire
administrator's network to sales network, you would add:
	-p tcp --dport ssh -j ACCEPT
into the file: admins/sales. Of course, we encourage you to be more specific
than that, for example:
	-s 10.7.0.1 -d 10.8.0.20 -p tcp --dport 3389 -j ACCEPT

You can use comments in your configuration files. The default actions is,
of course, to DROP the packet.

ADVANCED FEATURES

- firewall rules are in sourceNetwork/destinationNetwork (you already know that)

- SNAT rules are in sourceNetwork/destinationNetwork.dnat, for example:
$ cat lan/world.snat
-j MASQUERADE

- DNAT rules are in originalNetwork.dnat, for example
$ cat dmznet.dnat
-d 192.168.0.5 -j DNAT --to-destination 10.11.0.1

- custom chains could be created in _extras/

INSTALLATION:

put the files to /etc/firewall. Start the firewall from your startup scripts,
such as from /etc/rc.local or pre-up in /etc/network/interfaces, etc.

Only fw.cfg, _extras, and _scripts are required. All other directories
are an example and can be safely deleted:

rm -rf _extras/* admins dmznet phones printers remote sales world
