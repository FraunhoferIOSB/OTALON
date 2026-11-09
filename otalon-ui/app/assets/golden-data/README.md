# UI Regression Fixture Provenance

These JSON files are offline regression fixtures, not live telemetry.
Network/device identifiers were pseudonymized consistently for publication:
private IPv4 addresses use `192.0.2.0/24`, unicast MAC addresses use locally
administered `02:00:00:00:xx:xx` values, and the application identity is an
example. Standard multicast/broadcast addresses retain protocol meaning.

Shapes, cross-file identifier relationships, timestamps and metric values were
retained. The transformation is pseudonymization, not a claim of anonymity,
synthetic original capture, current network state or production equivalence.
The private mapping is not included in the repository.
