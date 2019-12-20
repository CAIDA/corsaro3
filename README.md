Corsaro 3: the Parallel Edition
-------------------------------

Introduction
============

Corsaro 3 is a re-implementation of a decent chunk of the original Corsaro
which aims to be better suited to processing parallel traffic sources, such
as nDAG streams or DPDK pipelines.

Requirements
============

 * libtrace >= 4.0.10 -- download from https://github.com/LibtraceTeam/libtrace
 * libwandio >= 4.2.0 -- download from https://github.com/wanduow/wandio
 * libyaml -- https://github.com/yaml/libyaml
 * libipmeta -- https://github.com/CAIDA/libipmeta
 * libzmq3
 * libavro
 * libtimeseries -- https://github.com/CAIDA/libtimeseries
 * libJudy
 * tcmalloc -- https://github.com/gperftools/gperftools

Debian / Ubuntu users can also find packages for libtrace and libwandio at
http://bintray.com/wand.

Libyaml, libzmq, libavro, libJudy and tcmalloc should be available through
your standard OS package repository -- make sure you install the development
versions of those libraries. On Debian / Ubuntu, tcmalloc is included in
the libgoogle-perftools-dev package.


Installing
==========

Standard installation instructions apply.

    ./bootstrap.sh        (if cloned from GitHub)
    ./configure
    make
    sudo make install


Included Tools
==============
There are four tools included with Corsaro 3:
 * corsarotagger -- captures packets from a libtrace source and performs
                    some preliminary processing (e.g. geolocation).
 * corsarofanner -- receives tagged packets from corsarotagger and
                    republishes them on a local socket for consumption
                    by multiple corsarotrace (or other analysis) processes.
 * corsarotrace -- receives tagged packets from either corsarofanner or
                   corsarotagger and runs one or more of the built-in analysis
                   plugins against that data stream.
 * corsarowdcap -- captures packets from a libtrace source and writes them
                   to disk as a set of trace files.
                
If you have installed Corsaro 3 from source via 'make install', these
tools will reside in /usr/local/bin/ by default.

Configuration
=============

Old Corsaro used a pile of CLI arguments for configuring each run. This has
now been replaced with YAML configuration files.

The YAML required to use the Corsaro 3 tools is pretty simple to write. There
are a number of top-level global config options which are simply set by
specifying a key value pair using the following format:

    key: value

In the case of corsarotrace, the plugins to apply are expressed as a YAML
sequence, with the plugin-specific options appearing as key value pairs
following the plugin name itself. For instance, the following config segment
will run a corsarotrace instance using the flowtuple and dos plugins. The
flowtuple plugin will be configured with the 'sorttuples' option set to 'yes'.
The dos plugin will be configured with the 'minattackduration' option set
to 60.

    plugins:
      - flowtuple:
          sorttuples: yes
      - dos:
          minattackduration: 60

Note that the indentation and colon placement is important.

An example configuration file for each corsaro tool is included with the
Corsaro 3 source code.

Logging modes
=============

Each corsaro 3 tools will accept a logmode option which is used to determine
where any log messages produced by the tool end up. There are four logging
modes available:

    terminal              write log messages to stderr
    syslog                write log messages to syslog (daemon.log)
    file                  write log messages to a file
    disabled              do not write log messages

Running corsarowdcap
====================

To use corsarowdcap, write a suitable config file (see below for more details)
and run the following command (assuming the corsarowdcap binary is in your
PATH):

    corsarowdcap -c <config filename> -l <logmode>

The full set of supported config options for corsarowdcap is:

    outtemplate           The template to use for output file names. The format
                          specification semantics are the same as they were in
                          old Corsaro (%N for monitor name, as well as all
                          strftime(3) modifiers). A %P modifier will be replaced
                          with 'wdcap'.

    logfilename           If the log mode is set to 'file', the log messages
                          will be written to the file name provided by this
                          option. This option must be set if the log mode
                          is set to 'file'.

    inputuri              A libtrace URI describing where corsarowdcap should
                          read captured packets from. Ideally, this would be
                          a live capture interface of some sort (i.e. an
                          interface name, a DPDK PCI identifier or an
                          ndag multicast location).

    consterfframing       Tells corsarowdcap that it can automatically assume
                          that the ERF framing for a captured packet has a
                          certain length, which improves performance slightly.
                          This option only applies to packet captures using an
                          Endace DAG card (i.e. dag: or ndag: URIs) and should
                          not be used if provenance meta-data is enabled on
                          the capture device.

    monitorid             Set the monitor name that will appear in output file
                          names if the %N modifier is present in the template.

    interval              Specifies the file rotation frequency in seconds.
                          Defaults to 300.

    threads               The number of processing threads to use to receive
                          and write packets. If using an ndag: input, this
                          should be equal to the number of ndag streams.

    fileformat            The trace format to use when writing packets into
                          trace files. Must be a libtrace format type (e.g.
                          pcapfile, erf)

    stripvlans            If set to 'yes', any VLAN tags within the captured
                          packets will be stripped before the packets are
                          written to disk. IMPORTANT: set this to 'no' if
                          you know that there will be no VLAN headers in any
                          captured packets -- this will improve performance.

    writestats            If set to 'yes', statistics relating to the number
                          of packets received and dropped by the corsarowdcap
                          process will be written to a separate statistics file.
                          The resulting files will have the same name as the
                          corresponding trace files, except they will have a
                          '.stats' extension.

    compresslevel         Compression level to use when writing compressed
                          trace files (defaults to 0, i.e. no compression).

    compressmethod        Compression method to use when writing compressed
                          trace files. Can be one of "gzip", "bzip2", "lzo",
                          or "lzma" ("zstd" and "lz4" will be added if
                          libtrace 4.0.8 is installed on your system). If
                          not present, no compression will be performed.

    mergethreads          Number of threads to dedicate to merging the
                          interim output files into a single coherent trace
                          file. Defaults to 1.

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

    pubqueuename          The name of the zeroMQ queue to publish the tagged
                          packets to. This must be a valid zeroMQ socket URI,
                          preferably using either the ipc:// or tcp://
                          transports. The default is 'ipc:///tmp/corsarotagger'.

    controlsocketname     The name of the zeroMQ queue which will be listening
                          for meta-data requests from clients. This must be a
                          valid zeroMQ socket URI, preferably using either the
                          ipc:// or tcp:// transports. The default is
                          'ipc:///tmp/corsarotagger-control'.

    outputhwm             The high-water mark for the zeroMQ queue that is
                          publishing tagged packets. If the backlog for this
                          queue reaches or exceeds this value, then packets
                          will be dropped rather than sent to clients. Larger
                          HWM values will consume more memory whenever the
                          tagger clients are failing to keep up, but will
                          allow more packets to be buffered before dropping
                          begins. Default is 125.

    pktthreads            The number of threads to devote to reading packets
                          from the input source. If using an ndag: input, this
                          should be equal to the number of ndag streams. The
                          default is 2.

    tagthreads            The number of threads to devote to performing the
                          tagging work on received packets. The default is 2.

    tagproviders          A sequence that specifies which additional tagging
                          providers should be used to tag captured packets.
                          More information about tag providers is given below.


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


Running corsarofanner
=====================

To use corsarofanner, write a suitable config file (see below for more
details) and run the following command:

    ./corsarofanner -c <config filename> -l <logmode>

Use corsarofanner to consume a feed of tagged packets that are being
published by corsarotagger over a TCP socket and re-publish those packets
on a local IPC socket on the host running the fanner. This allows you to
run multiple corsarotrace instances on the same host without each instance
consuming network bandwidth to receive a separate feed from a remote
corsarotagger.

The full set of supported global config options is:

    threads               The number of threads to use for consuming and
                          re-publishing tagged packets. Clients must make sure
                          that they are consuming from the queues created by
                          all of the threads (e.g. the number of processing
                          threads for corsarotrace instances MUST match this
                          number to avoid missing packets). Defaults to 4.

    logfilename           If the log mode is set to 'file', the log messages
                          will be written to the file name provided by this
                          option. This option must be set if the log mode
                          is set to 'file'.

    statfilename          If specified, each thread will write basic statistics
                          about received and missing packets to a file using
                          the given value as the base filename, followed by
                          "-t<thread id>".

    subqueuename          The name of the zeroMQ queue where the
                          corresponding corsarotagger is writing tagged packets
                          to. This MUST match the 'pubqueuename' option being
                          used by the corsarotagger instance.
                          If not specified, corsarofanner will immediately halt.

    pubqueuename          The base name of the zeroMQ queue to re-publish any
                          received packets to. This queue should be an "ipc://"
                          queue and each thread will extend the base name to
                          include its thread ID.
                          Defaults to "ipc://tmp/corsarofanner".

    inputhwm              The high-water mark for the subscription queue which
                          this corsarofanner instance is receiving tagged
                          packets from. This is approximately the number of
                          received packets that each processing thread can
                          buffer internally before having to stop reading from
                          the tagger socket. Larger HWM values will consume more
                          local memory whenever the corsarofanner instance is
                          unable to keep up with the incoming packet rate.
                          Default is 25.

    outputhwm             The high-water mark for the publishing queue which
                          this corsarofanner instance is emitting tagged packets
                          to. This is approximately the number of received
                          packets that each processing thread can buffer
                          internally before having to stop writing to the
                          publishing socket. Larger HWM values will consume more
                          local memory whenever the downstream clients are
                          unable to keep up with the incoming packet rate.
                          Default is 25.

Running corsarotrace
====================

To use corsarotrace, write a suitable config file (see below for more
details) and run the following command:

    ./corsarotrace -c <config filename> -l <logmode>

Unlike the other tools, corsarotrace does not read packets directly from the
capture source -- instead, it expects to received tagged packets either
directly from corsarotagger or from a corsarofanner local socket. Therefore,
corsarotrace will require a running instance of corsarotagger to be able to
function correctly.

The full set of supported global config options is:

    outtemplate           The template to use for output file names. The format
                          specification semantics are the same as they were in
                          old Corsaro (i.e. %P for plugin name, %N for monitor
                          name, as well as all strftime(3) modifiers).

    logfilename           If the log mode is set to 'file', the log messages
                          will be written to the file name provided by this
                          option. This option must be set if the log mode
                          is set to 'file'.

    subqueuename          The name of the zeroMQ queue where the corresponding
                          corsarotagger or corsarofanner instance is writing
                          tagged packets to.
                          This MUST match the 'pubqueuename' option being used
                          by the corsarotagger or corsarofanner instance.
                          Defaults to 'ipc:///tmp/corsarotagger'.

    controlsocketname     The name of the zeroMQ queue to connect to when
                          sending meta-data requests to the corsarotagger
                          instance. This MUST match the 'controlsocketname'
                          option being used by the corsarotagger instance.
                          A control socket MUST connect to a corsarotagger
                          instance -- corsarofanner does not have a control
                          socket to connect to.
                          Defaults to 'ipc:///tmp/corsarotagger-control'.

    monitorid             Set the monitor name that will appear in output file
                          names if the %N modifier is present in the template.

    threads               Set the number of threads to be created for packet
                          processing. Defaults to 4. If connecting to a
                          corsarofanner instance, ensure that this matches the
                          number of threads being used by the fanner, otherwise
                          you will miss packets.

    interval              Specifies the distribution interval length in seconds.
                          Defaults to 60.

    rotatefreq            Specifies the number of intervals that must complete
                          before an output file is rotated. Defaults to 4. If
                          set to 0, no file rotation is performed (all output
                          ends up in a single file).

    startboundaryts       Ignore all packets that have a timestamp earlier than
                          the Unix timestamp specified for this option.

    endboundaryts         Ignore all packets that have a timestamp after the
                          Unix timestamp specified for this option.

    removespoofed         If set to 'yes', ignore all packets that the
                          corsarotagger has marked as spoofed. Defaults to 'no'.

    removeerratic         If set to 'yes', ignore all packets that the
                          corsarotagger has marked as an erratic traffic type.
                          Defaults to 'no'.

    removerouted          If set to 'yes', ignore all packets that the
                          corsarotagger has marked as coming from a globally
                          routable address (i.e. not an RFC5735 address).
                          Defaults to 'no'.

    removenotscan         If set to 'yes', only include packets that the
                          corsarotagger has marked as likely to be from a
                          known large-scale scanning system. Defaults to 'no'.

    inputhwm              The high-water mark for the subscription queue which
                          this corsarotrace instance is receiving tagged packets
                          from. This is approximately the number of received
                          packets that each processing thread can buffer
                          internally before having to stop reading from the
                          tagger socket. Larger HWM values will consume more
                          local memory whenever the corsarotrace instance is
                          unable to keep up with the incoming packet rate.
                          Default is 25.

    libtimeseriesbackends If a plugin is going to use libtimeseries to stream
                          output into a data platform, this sequence will list
                          the backend(s) to use and their configuration options
                          (see below for more details).

    plugins               A sequence that specifies which plugins to use for
                          packet processing, as well as any plugin-specific
                          configuration options (see below for more details).



Libtimeseries Backends and their Configuration Options
======================================================
Backends must be specified as a YAML sequence within the 'libtimeseriesbackends'
configuration option. Multiple backends may be included in this sequence, but
they will only be used if corsarotrace is running at least one plugin that
is configured to write output using libtimeseries. Otherwise, any configuration
of libtimeseries backends will be ignored.

There are four backends currently supported by corsarotrace:

**ascii:** Write the output into a file on disk, mostly useful for debugging.

Supported options:

        file              The path to the output file to write into.
    compress              The gzip compression level for the output file.
                          0 = uncompressed, 1-9 = increasingly compressed.


**kafka:** Write the output into a Kafka broker.

Supported options:

    brokeruri             The host:port that the broker is running on.
    channelname           The name of the channel to write the output into.
    topicprefix           The name of the topic to write the output to.
    compresscodec         The compression method to apply to records -- one of
                          "snappy", "gzip", "lz4" and "uncompressed".

**dbats:** Write the output into a DBATS instance.

Supported options:

    compression           If set to 'no, the created database will _not_
                          use compression. (This is ignored if the database
                          already exists.)
    exclusive             If set to 'yes', get an exclusive lock on the
                          database. (Possibly improves performance slightly.)
    transactions          If set to 'no', disable transactions. Don't do this.
    updatable             If set to 'yes', allow updates to existing
                          values. Always set this.
    path                  The path to the DBATS instance.


Supported Plugins and their Configuration Options
=================================================

Remember that plugin-specific configuration must be appear as a map within
the appearance of the plugin name in the config file, not alongside the global
options.

Also note that many of these plugins only really make sense when used in
the network telescope context, i.e. when the observed traffic is unsolicited.

**Flowtuple:** This plugin simply reports statistics for all flows observed
on the monitored network within each interval. Flows are defined slightly
unconventionally; rather than the standard 5-tuple, this plugin defines a
flow using an 8-tuple of the following packet fields:

 * source IP address
 * destination IP address
 * source port number (or ICMP type)
 * destination port number (or ICMP code)
 * TTL
 * TCP flags (or 0 for non-TCP traffic)
 * IP protocol
 * IP length

The flowtuple plugin can be further configured using the following options:

    sorttuples            If 'yes', the flowtuples are output in sorted order.
                          The sorting is based on the same sorting method as in
                          previous Corsaro versions. Defaults to 'yes'.

    mergethreads          Specifies the number of threads to reserve for
                          merging flowtuple results into a single coherent
                          file. Defaults to 2.

  usesnappy             If 'yes', the avro files produced as output will be
                        compressed using the snappy compression method (if
                        available). Otherwise, deflate will be used.
                        snappy uses less CPU time but will produce larger
                        files, deflate is the opposite. Defaults to 'no'.

Flowtuple output is written to an avro file, which is named according to
the 'outtemplate' option specified at the global config level.

**DOS:** This plugin attempts to identify remote IP addresses that appear to
be targets of DOS attacks, based on backscatter observed in the packet
capture.

The dos plugin takes several options which are used to fine-tune the
sensitivity of the attack detection:

    min_attack_packets          The minimum number of packets that must be
                                seen from a source IP before it is considered
                                to be the target of an attack. Defaults to 25.

    min_attack_duration         The minimum duration in seconds for an attack
                                to be included in the plugin output. Defaults
                                to 60.

    min_attack_packet_rate      The minimum number of packets that must be
                                observed within a single window for an attack
                                to be included in the plugin output. Defaults
                                to 30.

    rate_window_size            The size of the window to use when determining
                                the packet rate for an attack (in seconds).
                                Defaults to 60.

    rate_window_slide           The frequency that the window should be moved
                                forward and the packet rate re-calculated
                                (in seconds). Defaults to 10.

DOS output is written to two separate avro files, which are named according to
the 'outtemplate' option specified at the global config level. The first
file replaces the plugin name modifier with 'dos' and contains a list of all
of the attacks observed in each interval, plus some high-level stats about each
attack. The second file replaces the plugin name modifier with 'dosflows' and
contains a list of all of the individual flows that were part of an observed
attack.

**Report:** The report plugin produces time series of the number of
packets, bytes, source IPs and destination IPs that matched each of the tags
assigned to observed traffic by the corsarotagger.

For instance, the report plugin will generate time series for each of the
TCP / UDP ports, IP protocols, source ASNs, geo-location continents / countries
and ICMP codes / types that appear in the packet tags.

The report plugin supports the following configuration options:

    output_row_label      A label to apply to each time series entry generated
                          by this instance of corsarotrace. Defaults to
                          'unlabeled'. For avro output, this will appear in
                          the 'source_label' field. For libtimeseries output,
                          this will be prepended to the 'key' string.

    output_format         The format to use when writing output, either 'avro'
                          or 'libtimeseries'. If set to 'avro', report output is
                          written to avro files, which are rotated and named
                          according to the 'rotatefreq' and 'outtemplate'
                          options specified at the global config level. If set
                          to 'libtimeseries', the output is written to all
                          backends specified using the 'libtimeseriesbackends'
                          sequence.

    iptracker_threads     The number of threads to dedicate to tracking the
                          number of unique source and destination IPs seen
                          sending or receiving a packet matching each metric.
                          Defaults to 4.

    internalhwm           The high-water mark applied to the internal queues
                          linking the processing threads to the IP tracking
                          threads. The same HWM is applied to both sending and
                          receiving sockets for those queues. Defaults to 30
                          messages.

    limitmetrics          Limit the time series generation by this plugin to
                          a specific set of metrics. If not specified, time
                          series will be generated for all metrics *except*
                          the filter criteria -- otherwise,
                          only time series for the listed metric types will be
                          generated. The value for this option is a YAML list
                          containing one or more of the following values:

                          - "basic" : include the 'combined' and IP protocol
                                      metrics
                          - "tcpports" : include the source and dest TCP port
                                         metrics
                          - "udpports" : include the source and dest UDP port
                                         metrics
                          - "icmp" : include the ICMP code and type metrics
                          - "netacq" : include the metrics for the Netacq-Edge
                                      geo-tagging
                          - "maxmind" : include the metrics for the Maxmind
                                      geo-tagging
                          - "pfx2asn" : include the prefix2asn metrics
                          - "filter": include the individual filter matching
                                      metrics

    querytaggerlabels     If set to 'no', the plugin will NOT attempt to ask
                          the tagger for FQ labels for each country, region,
                          etc. that appears in the geo-location tags. This is
                          useful if you are running an older corsarotagger that
                          does not support this feature, but will mean that your
                          metric labels may contain a lot of 'unknown's. Default
                          is 'yes'.
