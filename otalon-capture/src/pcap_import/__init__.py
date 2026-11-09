"""PCAP import worker: a passive HTTP receiver for capture-file import jobs.

The worker accepts an import job pushed to it over HTTP, replays the referenced
capture file through the shared Netcap++ capture pipeline into InfluxDB, and
reports progress back to the job's owner. It holds no connection to the
operations job store — the job owner remains the single writer of job records.
"""
