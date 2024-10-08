# PCAPNG to HAR Converter

## Overview

This project is a Python-based tool for converting PCAPNG files to HAR files.
It supports both HTTP/1.1 and HTTP/2 protocols.

## Requirements

- Python 3.11+
- `tshark` (part of the Wireshark suite; tested on version >= 4.0)

## Installation

1. Install Python 3.11 or higher.
2. Install `tshark` from the Wireshark suite.
3. Clone this repository:
```sh
git clone <repository_url>
cd <repository_directory>
```
4. Install the required Python packages:
```sh
pip install -r requirements.txt
```

## Usage

Prior to using this converter, please have a look at [documentation on how to convert .pcap to .pcapng](./pcapng_utils/tshark/wrapper.py#L28)

### Shell

Run `./pcapng_to_har.py [-h]` in your shell (with your Python virtual environment activated)

### Python

```python
from pcapng_to_har import pcapng_to_har, Tshark
pcapng_to_har(
    input_file: Path | str,
    output_file: Path | str | None = None,
    *,
    tshark: Tshark | None = None,
    overwrite: bool = False,
    **json_dump_kws: Any  # e.g. indent=4
)
```
