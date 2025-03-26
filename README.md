# Langdon

CLI for network application reconnaissance

## Requirements

- ffmpeg >= 7.1.1-1+b1
- Mozilla Firefox >= 128.7.0esr
- Python >= 3.12
- tor >= 0.4.8.14

## Initial configuration

For the langdon to work, it needs to have the `tor` daemon running. If you have the `tor` already installed, just use the following command:
```bash
$ sudo systemctl start tor
```

Create a new profile in Firefox with the Firefox Profile Manager and set the path to langdon using the following command:

```bash
$ langdon config set FIREFOX_PROFILE_PATH path
```
