# session-stat

session-stat is a python script which generates either Excel or CSV files containing session information taken from pcap files.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

To run dkb-robo on your system you need

* [Python] - (https://www.python.org)
* [Wireshark] - (https://www.wireshark.org/ - network protocol analyzer
* [pyshark] - (https://pypi.python.org/pypi/pyshark) - Python wrapper for tshark, allowing python packet parsing using wireshark dissectors
* [xlsxwriter]  - (http://xlsxwriter.readthedocs.io/) - a Python library to create XLSX files.

Please make sure python and all the above modules had been installed successfully before you start any kind of testing.

### Installation

* download the archive and unpack it

### Usage

session-stat can be controlled by several command line options
```
>session_stat.py -h
usage: session_stat.py [-h] (-b DIRECTORY | -r FILE) -w OUTPUT_FILE [-a] [-c]
                       [-d] [-e] [-s SORT_BY]

session analyzer

optional arguments:
  -h, --help            show this help message and exit
  -b DIRECTORY          directory with pcap files to analyze
  -r FILE               pcap file to analyze
  -w OUTPUT_FILE        output file
  -a, --aggregate       aggregate sessions based on src,dst,proto and dst_port
  -c, --csv             export as csv
  -d, --debug           debug mode
  -e, --expert          add information from TCP sequence analysis
  -s SORT_BY, --sort-by SORT_BY
                        sort results by vlan, src, dst, dst_port, cnt or
                        bytes, (default: by time)
>
```
The directory examples contains several several examples based on a capture file taken from the [tcpreplay](https://s3.amazonaws.com/tcpreplay-pcap-files/smallFlows.pcap) webpage 

* smallFlows.txt - flow statistics in csv format
* smallFlows.xlsx - flow statistics in xlsx format
* smallFlows-aggregated.txt - aggregated flow statistics in csv format
* smallFlows-aggregated.xlsx - aggregated flow statistics in xlsx format

## Contributing

Please read [CONTRIBUTING.md](https://github.com/grindsa/session-stat/blob/master/CONTRIBUTING.md) for details on my code of conduct, and the process for submitting pull requests.
Please note that I have a life besides programming. Thus, expect a delay in answering.

## Versioning

I use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/grindsa/session-stat/tags). 

## License

This project is licensed under the GPLv3 - see the [LICENSE.md](https://github.com/grindsa/session-stat/blob/master/LICENSE) file for details


