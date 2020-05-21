Corsaro 3: the Parallel Edition
-------------------------------

Introduction
============

Corsaro 3 is a re-implementation of a decent chunk of the original Corsaro
which aims to be better suited to processing parallel traffic sources, such
as nDAG streams or DPDK pipelines.

Requirements
============

 * libtrace >= 4.0.12 -- download from https://github.com/LibtraceTeam/libtrace
 * libwandio >= 4.2.0 -- download from https://github.com/wanduow/wandio
 * libyaml -- https://github.com/yaml/libyaml
 * libipmeta -- https://github.com/CAIDA/libipmeta
 * libzmq3
 * libavro
 * libtimeseries -- https://github.com/CAIDA/libtimeseries
 * libJudy
 * tcmalloc -- https://github.com/gperftools/gperftools
 * librdkafka

Debian / Ubuntu users can also find packages for libtrace and libwandio at
http://bintray.com/wand.

Libyaml, libzmq, libavro, libJudy and tcmalloc should be available through
your standard OS package repository -- make sure you install the development
versions of those libraries. On Debian / Ubuntu, tcmalloc is included in
the libgoogle-perftools-dev package.

On macOS, using HomeBrew you'll want something like `brew install avro-c zeromq traildb/judy/judy nwoolls/homebrew-xgminer/uthash`.


Installing
==========

Ubuntu/Debian packages are available from CAIDA's package repository:
```
curl https://pkg.caida.org/os/ubuntu/bootstrap.sh | bash
# ^ of course, you should inspect this script first
sudo apt install corsaro
```

Otherwise, standard installation instructions apply:

    ./bootstrap.sh        (if cloned from GitHub)
    ./configure
    make
    sudo make install


Included Tools
==============
There are four tools included with Corsaro 3:
 * corsarotagger -- captures packets from a libtrace source and performs
                    some preliminary processing (e.g. geolocation). Emits
                    "tagged" packets onto a multicast group for further
                    downstream analysis.
 * corsarotrace -- receives tagged packets from corsarotagger and runs one or
                   more of the built-in analysis plugins against that data
                   stream.
 * corsarowdcap -- captures packets from a libtrace source and writes them
                   to disk as a set of trace files.
 * corsaroftmerge -- merges interim flowtuple avro files produced by
                     corsarotrace into a single file.

If you have installed Corsaro 3 from source via 'make install', these
tools will reside in /usr/local/bin/ by default.

Documentation for each individual tool is included in the docs/ directory
in the corsaro3 source tree, or will have been installed on your system
alongside this README (if you installed corsaro3 via a package).

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

Each corsaro 3 tool will accept a logmode option which is used to determine
where any log messages produced by the tool end up. There are four logging
modes available:

    terminal              write log messages to stderr
    syslog                write log messages to syslog (daemon.log)
    file                  write log messages to a file
    disabled              do not write log messages

