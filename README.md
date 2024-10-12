<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>PCAPNG to HAR Converter</h1>
<p>
Python-based tool for converting PCAPNG files to HAR files.
</p>
<p>
License: GPLv3 and MIT
</p>
<p>
<img alt="PyPI - Version" src="https://img.shields.io/pypi/v/pcapng-utils" >
<img alt="GitHub Release" src="https://img.shields.io/github/v/release/PiRogueToolSuite/pcapng-utils" >
</p>
<p>
<a href="https://pts-project.org">Website</a> | 
<a href="https://discord.gg/qGX73GYNdp">Support</a>
</p>
</div>

## Overview
This project is a Python-based tool for converting PCAPNG files to HAR files. It supports both HTTP/1.1 and HTTP/2 protocols.

## Requirements
This converter requires a PCAPNG file as input. If you have a PCAP file, you can convert it to PCAPNG using `editcap`:

```shell
editcap <input_file.pcap> <output_file.pcapng>
```

Make sure the following tools are installed on your system:
- Python 3.11+
- `tshark` (part of the Wireshark suite; **requires version >= 4.0**)

## Installation
```shell
pip install pcapng-utils
```

## Usage
### Shell
Run `pcapng_to_har [-h]` in your shell (with your Python virtual environment activated)

### Python
```python
from pcapng_to_har import pcapng_to_har, Tshark
def pcapng_to_har(
    input_file: Path | str,
    output_file: Path | str | None = None,
    *,
    tshark: Tshark | None = None,
    socket_operations_file: Path | str | None = None,
    cryptography_operations_file: Path | str | None = None,
    overwrite: bool = False,
    **json_dump_kws: Any,
) -> None
```

## Features
### TLS Decryption
If the captured traffic contains TLS traffic and a [`SSLKEYLOGFILE`](https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html) has been generated during the capture, use the following command to inject the TLS client randoms read from the `<keylog_file>` into the PCAPNG file:

```shell
editcap --inject-secrets tls,<keylog_file> <file.pcap> <output.pcapng>
```

Once the secrets have been injected into the PCAPNG file, you can use `pcapng_to_har` to convert the PCAPNG file to a HAR file. The output HAR will contain the decrypted TLS traffic.

```shell
pcapng_to_har -i <input.pcapng> -o <input.har> 
```

### Stacktrace Identification (PiRogue only)
If the traffic has been captured on a PiRogue with the command `pirogue-intercept[single|gated]`, the stacktrace of all operations (read, write) on sockets have been logged in a file `socket_trace.json`. The converter will use this file to add the stacktrace information to each request and response. The attributes `request._stacktrace` and `response._stacktrace` will, respectively, contain the stacktrace of the socket operations that have been performed for the request and the response.

```shell
pcapng_to_har -i <input.pcapng> -o <input.har> -sf <socket_trace.json>
```

### Payload Decryption (PiRogue only)
If the traffic has been captured on a PiRogue with the command `pirogue-intercept[single|gated]`, the encryption and decryption operations have been logged in a file `aes_info.json`. The converter will use this file to identifies the payloads that have been encrypted before been transmitted. The encrypted payload will be replaced by its cleartext in `request.postData.text` and `response.content.text`.

Additional information about the encryption and decryption operations will be added to the HAR in the attributes `request._decryption` and `response._decryption`.

```shell 
pcapng_to_har -i <input.pcapng> -o <input.har> -cf <aes_info.json>
```

## Development
1. Install Python 3.11 or higher.
2. Install `tshark` from the Wireshark suite.
3. Clone this repository:
  ```shell
  git clone https://github.com/PiRogueToolSuite/pcapng-utils
  cd pcapng-utils
  ```
4. Install the required Python packages:
  ```shell
  pip install -r requirements.txt
  ```

## Licensing
This work is licensed under multiple licences:
* All the code in this repository is licensed under the GPLv3 license.
  * Copyright: 2024   U+039b <hello@pts-project.org>  
  * Copyright: 2024   Defensive Lab Agency <contact@defensive-lab.agency>
* The files containing a SPDX header are licensed under the MIT license.
  * Copyright: 2024   Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
