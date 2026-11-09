import csv
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


pcap_path = "pcap"
csv_path = "temp"


def clean():
    p = Path(csv_path)
    [x.unlink() for x in p.iterdir()]


def run_application(infile, outfile):
    if os.name == "nt":
        exe = Path(
            "..",
            "out",
            "build",
            "x64-Debug",
            "src",
            "network-capture.exe",
        )
    ret = subprocess.Popen(
        f"../out/build/x64-Debug/src/network-capture.exe --input-file {pcap_path}/{infile} --output-file {csv_path}/{outfile}",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    ).wait()


def check_protocol(file, protocol):
    count = 0
    with open(f"{csv_path}/{file}") as f:
        reader = csv.reader(f, delimiter=";")
        next(reader)
        for row in reader:
            fields = row[1].split("/")
            protocols = fields[8].split(":")
            if protocol in protocols:
                count += 1
    return count


def test_protocol(infile, outfile, protocol_name, expected_occurence):
    run_application(infile, outfile)
    found_entries = check_protocol(outfile, protocol_name)
    if found_entries == expected_occurence:
        logging.info(f"{protocol_name} test passed")
    else:
        logging.error(
            f"{protocol_name} test failed, expected occurences: {expected_occurence}, found occurences: {found_entries}"
        )


def main():
    clean()

    test_protocol("lldp.pcapng", "lldp.csv", "LLDP", 33)
    test_protocol("opcua.pcapng", "opcua.csv", "OPC-UA", 63)
    test_protocol("pn_dcp.pcapng", "pn_dcp.csv", "PROFINET_RT_DCP", 2)
    test_protocol("pn_io.pcapng", "pn_io.csv", "PROFINET_RT_IO", 73)
    test_protocol("ssdp.pcapng", "ssdp.csv", "SSDP", 12)
    test_protocol("syslog.pcapng", "syslog.csv", "Syslog", 1)


if __name__ == "__main__":
    main()
