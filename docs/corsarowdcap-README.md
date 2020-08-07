corsarowdcap captures packets from a libtrace source and writes them
to disk as a set of trace files.

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

    inputfilter           A BPF filter to be applied to all captured packets.
                          Packets that do not match the filter will be
                          discarded.

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



