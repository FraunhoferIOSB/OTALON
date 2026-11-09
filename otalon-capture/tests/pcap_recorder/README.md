# Testplan fuer `pcap_recorder`

Diese Datei beschreibt die Testabdeckung fuer die in [`pcap_recorder`](../../src/pcap_recorder) implementierten Komponenten und mappt die offenen Punkte aus Abschnitt 8 der TODO-Liste auf konkrete Testmodule.

## 1. Konfiguration & Settings

- **Ziel**: Absichern von [`PcapRecorderSettings.from_json()`](../../src/pcap_recorder/settings.py:102) inkl. ENV-Aufloesung sowie Validierung der einzelnen Pydantic-Modelle.
- **Testmodul**: `tests/pcap_recorder/test_settings.py`
- **Faelle**:
  - Erfolgreiche Aufloesung aller `$ENV` Platzhalter.
  - Fehlerfall bei fehlender ENV-Variable.
  - Pydantic-Validierungen (z. B. `PositiveInt` Felder) fuer `PcapConfig`, `ApiConfig`, `LogConfig`.

## 2. Index-Management

- **Ziel**: Sicherstellen, dass [`PcapIndex`](../../src/pcap_recorder/index.py:29) Dateien korrekt erfasst, Zeitbereiche filtert und Anomalien markiert.
- **Testmodul** (neu): `tests/pcap_recorder/test_index.py`
- **Faelle**:
  - `add_chunk()` erfasst Dateigroesse und Timestamps aus dem Dateinamen.
  - `find_by_timerange()` filtert ueberschneidende Chunks und respektiert `include_non_archive`.
  - `mark_anomaly()` aktualisiert Labels und Persistenz.

## 3. Ringbuffer-Logik

- **Ziel**: Verhalten des [`RingbufferManager`](../../src/pcap_recorder/ringbuffer.py:15) beim Einlesen neuer Chunks, Einhalten der Speicherlimits und Archivieren.
- **Testmodul** (neu): `tests/pcap_recorder/test_ringbuffer.py`
- **Faelle**:
  - `scan_for_new_chunks()` indiziert neue `.pcap` Dateien genau einmal.
  - `enforce_limits()` entfernt aelteste nicht markierte Chunks basierend auf Groesse/Anzahl.
  - `archive_chunks()` verschiebt Dateien ins Archiv und markiert sie als Anomalie.

## 4. Service- und REST-API

- **Ziel**: Validierung der internen [`PcapService`](../../src/pcap_recorder/api.py:33) sowie der FastAPI-Endpunkte aus [`create_app()`](../../src/pcap_recorder/api.py:55).
- **Testmodul** (neu): `tests/pcap_recorder/test_api.py`
- **Faelle**:
  - `flag_anomaly()` delegiert korrekt an Ringbuffer/Index und liefert Chunk-IDs.
  - `GET /chunks` liefert JSON-Metadaten und reagiert auf unguelitge Zeitraeume.
  - `GET /chunks/{id}` liefert einen FileResponse bzw. 404 wenn unbekannt.

## 5. Pytest-Ausfuehrung

- Alle Tests werden aus dem Ordner `otalon-capture` via `source ../.venv313/bin/activate && pytest tests/pcap_recorder` ausgefuehrt.
- Ziel: Sicherstellen, dass die neuen Module ohne echte Netzwerkintegration lauffaehig sind.
