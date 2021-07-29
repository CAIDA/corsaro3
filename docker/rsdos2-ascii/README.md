Author: Shane Alcock <shane@alcock.co.nz>

## Purpose

This container should be used to convert RSDoS v2 files from their native
corsaro format into a simple ASCII CSV format that does not require
the corsaro2 libraries to read and process.

NOTE: the `initial_packet` field from the corsaro format is NOT included
in the resulting ASCII CSV -- if required, users will need to look this up
either in the corsaro2 file or in the saved pcap from the same time period.

## Build Instructions

To build the Docker image for this container, simply run:

    docker build -t rsdos2ascii .

## Usage

This container is designed to process an entire month's worth of rsdosv2
data from a Swift object store. You can run multiple instances of the container
to process multiple months in parallel -- I would recommend that each
container be given at least 2 CPU cores.

The syntax for running this container is:

    docker run -v <host output dir>:/rsdosconv/output:rw
        -v <path to swift credentials>:/rsdosconv/swiftcreds:ro
        rsdos2ascii <year> <month number>

For example, you convert the rsdosv2 files for June 2021, you would set
`<year>` to `2021` and `<month>` to `6`.

This will process all of the UCSD-NT rsdosv2 files stored in Swift for
the given month and write compressed CSV files into the directory located
on the host at `<host output dir>`. Make sure `<host output dir>` exists on
your host machine before starting the container.

### Providing Swift Credentials

Create a file containing all of the environment variables that you would
normally have to set to read from the Swift object store, e.g.

    export OS_PROJECT_NAME=myproject
    export OS_USERNAME=steve
    export OS_PASSWORD=mypassword
    export OS_AUTH_URL=https://swift-auth.example.org
    export OS_IDENTITY_API_VERSION=3

When running the container, use the `-v` option to mount that file at the
location `/rsdosconv/swiftcreds` -- note that when mounting, you must
specify the absolute path to your file on the host.

## CSV Format
Each line represents a single observed attack. Each line contains the
following fields, in order:

 * Target IP
 * Total Attacker IPs
 * Attacker IPs seen in this interval
 * Attacker Ports
 * Target Ports
 * Total Packets
 * Packets seen in this interval
 * Total Bytes
 * Bytes seen in this interval
 * Maximum Packets per Minute rate
 * Attack Start Timestamp (Unix timestamp, floating point)
 * Attack Latest Timestamp (Unix timestamp, floating point)
 * Interval Number
 * Interval Timestamp

