Author: Shane Alcock <shane@alcock.co.nz>

## Purpose

This container can be used to post-process pcap trace files using the
corsaro3 flowtuple plugin. The resulting flowtuples are written to an Avro
data file.

## Build Instructions

To build the Docker image for this container, simply run:

    docker build -t offlineft .

Alternatively, the Docker image should be available from
https://hub.docker.com/orgs/caida/repositories

## Usage

The container is designed to process a **single** pcap trace file. Run
multiple instances of the container to process multiple files (in parallel,
if you wish). A running container will require at least 2 CPU cores.

The basic syntax for running this container is:

    docker run -v <host output dir>:/flowtuple/output:rw offlineft
        <pcapuri> <output prefix> <monitor id>

This will process the pcap trace located at `<pcapuri>` and write a
flowtuple avro file into the directory located at `<host output dir>`. Note
that the processing may take a long time to complete.

The resulting avro file will be named according to the following format:

    <output prefix>-<timestamp>-<monitor id>.flowtuple.avro

where `<timestamp>` is the Unix timestamp of the first packet in the pcap trace.

### Mounting Pcaps
If you have a pcap trace on the container host that you want to process, you
will need to mount that file inside the container to be able to process it.

You can do this by adding an additional `-v` option to the `docker run`
command. For example, if my pcap is located in `/trace/example.pcap`, I would
issue the command:

    docker run -v <host output dir>:/flowtuple/output:rw
        -v /trace/example.pcap:/flowtuple/example.pcap:ro offlineft
        pcapfile:/flowtuple/example.pcap <output prefix> <monitor id>

This will mount the pcap file (read-only) inside the container at the location
`/flowtuple/example.pcap`, so I can now specify my pcap URI using that
location. The container will be able to read the file as though it were on
its native filesystem.

Exactly where you mount the trace file is up to you, but you can at least
be guaranteed that `/flowtuple/` exists inside the container so that is a
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
`/flowtuple/swiftcreds`. Note that when mounting, you must specify the
absolute path to the file. For instance, if your swift credentials are in a
file called `swiftcreds` in the current working directory:

    docker run -v <host output dir>:/flowtuple/output:rw
        -v $(pwd)/swiftcreds:/flowtuple/swiftcreds:ro
        <swift URI for pcap file> <output prefix> <monitor id>

The pcap URI you specify at runtime now becomes a wandio swift URI, e.g.
`pcapfile:swift:///<container>/path/to/pcap/file.pcap.gz`.
