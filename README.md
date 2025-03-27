# Langdon

CLI for network application reconnaissance

## Requirements

- exploitdb ~= 20241126
- gau ~= 2.2.4
- host ~= 9.20.4-4-Debian
- httpx ~= v1.6.10
- Mozilla Firefox ~= 128.7.0esr
- Nmap ~= 7.95
- Python >= 3.12
- Tor ~= 0.4.8.14.
- webanalyze ~= v0.4.1

## Initial configuration

For the langdon to work, it needs to have the `tor` daemon running. If you have the `tor` already installed, just use the following command:
```bash
$ sudo systemctl start tor
```
