corsarotagger captures packets from a libtrace source and performs
some preliminary processing (e.g. geolocation). The results of this processing
are prepended to the captured packets as "tags" and the tagged packets are
published onto a multicast group that other corsaro tools (such as corsarotrace)
can use to perform further downstream analysis.

Running corsarotagger
=====================
To use corsarotagger, write a suitable config file (see below for more details)
and run the following command (assuming the corsarotagger binary is in your
PATH):

    corsarotagger -c <config filename> -l <logmode>

The full set of supported config options for corsarotagger is:

    logfilename           If the log mode is set to 'file', the log messages
                          will be written to the file name provided by this
                          option. This option must be set if the log mode
                          is set to 'file'.

    inputuri              A libtrace URI describing where corsarotagger should
                          read captured packets from. Ideally, this would be
                          a live capture interface of some sort (i.e. an
                          interface name, a DPDK PCI identifier or an
                          ndag multicast location).

    consterfframing       Tells corsarotagger that it can automatically assume
                          that the ERF framing for a captured packet has a
                          certain length, which improves performance slightly.
                          This option only applies to packet captures using an
                          Endace DAG card (i.e. dag: or ndag: URIs) and should
                          not be used if provenance meta-data is enabled on
                          the capture device.

    promisc               If set to 'yes', will enable promiscuous mode on the
                          capture interface. Defaults to 'no'.
    dohashing             If set to 'yes', will instruct the tagger to assign
                          packets to processing threads using a software
                          hasher that ensures all packets for the same
                          bidirectional flow end up on the same thread. If
                          using an ndag: input, set this to 'no'. Defaults to
                          'no'.

    basicfilter           A BPF filter to be applied to all captured packets.
                          Packets that do not match the filter will be
                          discarded.

    controlsocketname     The name of the zeroMQ queue which will be listening
                          for meta-data requests from clients. This must be a
                          valid zeroMQ socket URI, preferably using either the
                          ipc:// or tcp:// transports. The default is
                          'ipc:///tmp/corsarotagger-control'.

    pktthreads            The number of threads to devote to reading packets
                          from the input source. If using an ndag: input, this
                          should be equal to the number of ndag streams. The
                          default is 2.

    tagproviders          A sequence that specifies which additional tagging
                          providers should be used to tag captured packets.
                          More information about tag providers is given below.

    multicast             A map that contains configuration options that are
                          specific to the multicasting of tagged packets to
                          downstream clients (see below for more details).


corsarotagger Multicast
=======================
Configuration options for the multicast section of the corsarotagger config
file are described below.

    monitorid             A number that uniquely identifies this particular
                          tagger instance.

    beaconport            The port to use for multicasting nDAG beacon messages.
                          These messages are used to tell clients how many
                          streams of tagged packets there are and what ports
                          they are being multicast on. nDAG clients need to
                          know this port to join the tagged multicast groups.

    groupaddr             The multicast address that will be used for delivering
                          tagged packets and beacon messages. Must be a valid
                          IPv4 multicast address.

    sourceaddr            The IP address of the interface that the multicast
                          should be transmitted on.

    mtu                   The MTU that should be used when constructing nDAG
                          messages. Note that this should be slightly (e.g. 100
                          bytes) smaller than your expected MTU on the
                          path that you will be using to distribute the
                          multicast to clients, just to account for L2 + IP
                          encapsulation.

    ttl                   The TTL to set on the emitted multicast packets.
                          Defaults to 4, to allow multicast to be routed
                          into containers by receiving hosts.


corsarotagger Tag Providers
===========================
At present, corsarotagger supports four tagging providers.

**Standard:** the standard set of tags are applied to all captured packets
and therefore do not need to be explicitly included in the tagproviders:
config option. Standard tags include the following entries:
 * Transport protocol (e.g. TCP, UDP), given as the IP protocol number
 * Source port (or ICMP type for ICMP packets)
 * Destination port (or ICMP code for ICMP packets)
 * Flow hash value
 * A bitmask showing which built-in filters were matched by the packet

No configuration is required for the standard tagging, as this will happen
automatically.


**Prefix2ASN:** maps the source IP address to the ASN that owns it, as
determined from the prefix2asn data.

To enable Prefix2ASN tagging, add the following entry to your 'tagproviders:'
configuration sequence:

    - pfx2as:
        prefixfile: <location of the pfx2asn data file>


**Maxmind:** looks up the source IP address in the Maxmind geo-location dataset
and tags the packet with the country and continent that the address belongs
to.

To enable Maxmind geo-location tagging, add the following entry to your
'tagproviders:' configuration sequence:

    - maxmind:
       blocksfile: <location of the "GeoLiteCity-Blocks.csv" file>
       locationsfile: <location of the "GeoLiteCity-Location.csv" file>


**NetAcq-Edge:** looks up the source IP address in the NetAcuity Edge
geo-location dataset and tags the packet with the country, continent and
polygon for that IP address.

To enable NetAcuity geo-location tagging, add the following entry to your
'tagproviders:' configuration sequence:

    - netacq-edge:
       blocksfile: <location of the Blocks CSV file>
       locationsfile: <location of the Locations CSV file>
       countryfile: <location of the Country Codes CSV file>
       polygonmapfile: <location of the Polygons CSV file>
       polygontablefile: <location of a processed Polygons CSV file>
                         (may be specified multiple times)

