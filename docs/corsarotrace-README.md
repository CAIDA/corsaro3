corsarotrace runs one or more analysis plugins against a stream of tagged
packets received via libtrace.

If the packets are not tagged (i.e. they are being sourced
directly from a pcap file, rather than streamed live via corsarotagger),
corsarotrace is capable of adding the tags itself (given the right
configuration arguments) but this is only recommended for offline analysis;
the performance impact of combining tagging and analysis into one process
is significant for real-time packet processing.

Running corsarotrace
====================

To use corsarotrace, write a suitable config file (see below for more
details) and run the following command:

    ./corsarotrace -c <config filename> -l <logmode>

Unlike the other tools, corsarotrace does not read packets directly from the
capture source -- instead, it expects to received tagged packets from
corsarotagger that are being distributed using the nDAG protocol. Therefore,
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

    packetsource          The nDAG protocol URI to use to join a multicast
                          group where a corsarotagger instance is emitting
                          tagged packets.
                          This should look something like:
                          ndag:<interface>,<groupaddr>,<beaconport>

			  corsarotrace can also be used to process pcap
                          trace files, in which case you would set your
                          URI to be:
                          pcapfile:<file location>

                          Other valid libtrace input URIs may also be used
                          here, if desired.

    controlsocketname     The name of the zeroMQ queue to connect to when
                          sending meta-data requests to the corsarotagger
                          instance. This MUST match the 'controlsocketname'
                          option being used by the corsarotagger instance.

                          If not specified, corsarotrace will create its own
                          internal control socket that will serve meta-data
                          requests using any tagging providers that have been
                          specified in this config file.

			  If specified but the configuration also specifies
                          at least one valid tag provider, then corsarotrace
                          will ignore this option and use an internal control
                          socket as though this option was not present.

    monitorid             Set the monitor name that will appear in output file
                          names if the %N modifier is present in the template.

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

    libtimeseriesbackends If a plugin is going to use libtimeseries to stream
                          output into a data platform, this sequence will list
                          the backend(s) to use and their configuration options
                          (see below for more details).

    plugins               A sequence that specifies which plugins to use for
                          packet processing, as well as any plugin-specific
                          configuration options (see below for more details).

    tagproviders	  A sequence that specifies which additional tagging
                          providers should be used to tag packets, if they
                          come from a source other than a corsarotagger
			  instance.
                          More information about tag providers is given below.


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

The flowtuples generated by this plugin may be either written to disk using
the Avro format or published directly into a kafka broker.

If using Avro output, flows are written to a series of interim files which
can then be merged into a single output file using `corsaroftmerge`. The
interim file method is used for performance reasons -- trying to merge
eight or more processing threads worth of flowtuples into a single output
stream is a massive bottleneck, otherwise.

There will be one interim file per processing thread and each is named
according to the 'outtemplate' option specified at the global level of the
config file, followed by "--" and an interim file number.

The flowtuple plugin can be further configured using the following options:

    sorttuples            If 'yes', the flowtuples are output in sorted order.
                          The sorting is based on the same sorting method as in
                          previous Corsaro versions. Defaults to 'yes'.

    mergethreads          Specifies the number of threads to reserve for
                          merging flowtuple results into a single coherent
                          file. Defaults to 2.

    avrooutput            If set to 'snappy', the avro files produced as
                          interim output will be compressed using the snappy
                          compression method (if available). If set to
                          'deflate', gzip compression will be used. If set to
                          'none', no avro files will be written (use this if
                          you want to use kafka output only).
                          snappy uses less CPU time than deflate but will
                          produce larger files. Defaults to 'deflate'.

    kafkabrokers          A comma-separated list of kafka brokers to publish
                          flowtuple records to. If this option is not present,
                          no kafka publishing will occur.

    kafkatopicprefix      A custom string to prepend to the topic that the
                          flowtuples are published to, i.e. the topic will be
                          "<prefix>.corsaroflowtuple". If not specified, the
                          topic will simply be "corsaroflowtuple".

    kafkabatchsize        The maximum number of messages that kafka is allowed
                          to batch before sending to the broker. Defaults to 50.

    kafkalingerms         The maximum number of milliseconds that can occur
                          between a kafka batch being created and it being sent,
                          even if the batch is not full. Defaults to 500ms.

    kafkasampling         For each 10,000 flows, randomly sample approximately
                          this number of flow records for publishing to kafka.
                          Defaults to 10,000 (i.e. no sampling). E.g. to sample
                          at 50%, set this value to 5,000.

If the `sorttuples` option was set to `no`, then the interim files can be
merged using the `concat` tool in the `avro-tools` JAR. Otherwise, you will
need to use `corsaroftmerge` to merge the interim files and maintain the
sorted order in the final merged result.

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


corsarotrace Tag Providers
==========================

For situations where you are running corsarotrace against a non-tagged
packet stream (e.g. reading directly from a pcap), corsarotrace can be
configured to tag packets just like corsarotagger would before passing them
on to the plugins.

To enable this feature, use the `tagproviders` configuration option to point
corsarotrace at the data files that contain the information libipmeta will
use to tag each processed packet. The configuration format is exactly the same
as described in corsarotagger-README.md, and the Prefix2ASN, Maxmind and
Netacq-Edge tagging methods are all supported. Standard tagging will also
be applied at the same time.

If you wish to use standard tagging only (i.e. without specifying a tag provider
for Prefix2ASN, Maxmind or Netacq-Edge), just make sure that you do *not*
include a `controlsocketname` option in your configuration file and
corsarotrace will create a local tagging thread that corsarotrace will fall
back to doing its own tagging of packets.





