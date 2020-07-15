Author: Shane Alcock <shane@alcock.co.nz>

## Purpose

This container can be used to post-process pcap trace files using the
corsaro3 report plugin. The resulting time series can be written to
Avro data files or directly into libtimeseries (i.e. published to Kafka).

## Build Instructions

To build the Docker image for this container, simply run:

    docker build -t offlinereport .

Alternatively, the Docker image should be available from
https://hub.docker.com/orgs/caida/repositories

## Usage

The container is designed to process a **single** pcap trace file. Run
multiple instances of the container to process multiple files (in parallel,
if you wish). A running container will require 5 + (the number of IP tracking
threads) CPU cores and at least 12GB of memory.

The basic syntax for running this container is:

    docker run -v <corsaro config file>:/report/baseconfig.yaml offlinereport
        <pcapuri>

This will process the pcap trace located at `<pcapuri>` using the corsaro
report plugin, as configured by the config file `<corsaro config file>`.

If you wish to write your time series to Avro files on disk, you will also
need to mount a volume into the container for these files to written into
(using the `-v` option again). Make sure you mount the volume as `rw`.
You would then need to set an `outtemplate` option in your configuration file
that points into the directory where your volume is mounted so that your Avro
files are accessible once the container has completed processing.

## Configuration
Report plugin configuration is slightly complicated, so you will need to
directly provide a valid corsarotrace configuration file with all of your
desired processing options set accordingly. The file must be mounted at
/report/baseconfig.yaml inside the container at runtime.

See https://github.com/CAIDA/corsaro3/blob/offline-ft-docker/docs/corsarotrace-README.md
for more details on the configuration file syntax and what options are required
to run the report plugin. A basic configuration file for this container which
writes the time series to a Kafka broker is provided in the git repository for
this container (https://github.com/CAIDA/corsaro3/tree/master/docker/offline-report).

Some other general notes about configuration:

 * Set your `packetsource` option to `PCAPURI` and the container will
   substitute that with the pcap URI you provide at run time via `docker run`.
   You can also hard-code the pcap URI in your config file if you prefer -- in
   that case, you may leave out the pcap URI when you run the container.
 * To generate time series that are sub-classified by geo-location and ASN,
   you will need to provide specify the `tagproviders` option and provide
   valid paths to the various files used by libipmeta to associate IP addresses
   with locations and ASNs.
 * Your Kafka broker will need to be reachable from within the container. If
   you are running a broker on the host, make sure that the Kafka server is
   configured to advertise a listener that is on your docker network (e.g.
   in addition to `localhost`). Otherwise your container will not be able to
   publish.
 * If you want to write the time series to Avro files instead, you must set
   the `outtemplate` config option and it must point to a path that is on
   a volume mounted from the host into the container. The container file
   system will be removed once the container finishes its processing, so any
   files you wish to keep must be written to a directory that was mounted from
   the host file system at runtime.
 * Choosing the right number of IP tracker threads: this is less important
   than when running the report plugin against live data but will still impact
   a) how long each container takes to process its pcap file and b) how many
   CPUs will be required by each container. In brief unscientific testing I've
   found 4 tracker threads tends to run slightly slower than "real time",
   whereas 8 tracker threads will process a pcap trace within 75% of the
   time range covered by the trace (i.e. a 1hr trace is processed within 45
   minutes).

### Mounting Pcaps
If you have a pcap trace on the container host that you want to process, you
will need to mount that file inside the container to be able to process it.

You can do this by adding an additional `-v` option to the `docker run`
command. For example, if my pcap is located in `/trace/example.pcap`, I would
issue the command:

    docker run -v <corsaro config file>:/report/baseconfig.yaml
        -v /trace/example.pcap:/report/example.pcap:ro offlinereport
        pcapfile:/flowtuple/example.pcap

This will mount the pcap file (read-only) inside the container at the location
`/report/example.pcap`, so I can now specify my pcap URI using that
location. The container will be able to read the file as though it were on
its native filesystem.

Exactly where you mount the trace file is up to you, but you can at least
be guaranteed that `/report/` exists inside the container so that is a
safe place to mount it.

### Providing Swift Credentials
In cases where your trace files are in a Swift object store, you can instead
have the container read from there directly if you provide your swift
credentials at runtime.

To do this, first create a file containing all of the environment variables
that you would normally set to read from your Swift store, e.g.

    export OS_PROJECT_NAME=myproject
    export OS_USERNAME=steve
    export OS_PASSWORD=mypassword
    export OS_AUTH_URL=https://swift-auth.example.org
    export OS_IDENTITY_API_VERSION=3

Mount that file into the container at runtime (using `-v`) at the location
`/report/swiftcreds`. Note that when mounting, you must specify the
absolute path to the file. For instance, if your swift credentials are in a
file called `swiftcreds` in the current working directory:

    docker run -v -v <corsaro config file>:/report/baseconfig.yaml
        -v $(pwd)/swiftcreds:/report/swiftcreds:ro offlinereport
        <swift URI for pcap file>

The pcap URI you specify at runtime now becomes a wandio swift URI, e.g.
`pcapfile:swift:///<container>/path/to/pcap/file.pcap.gz`.

