<p align="center">
  <a href="https://github.com/lupaxa-workstation-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/workstation-toolbox/readme-logo.png" alt="Workstation Toolbox" />
  </a>
</p>

<h1 align="center">SSH Doctor</h1>

Read-only diagnostics for a local SSH client. SSH Doctor inspects OpenSSH,
configuration, keys, permissions, the agent, and known-host files, then
reports what it found and how to fix it.

It does not change keys, configuration, permissions, known hosts, or the
agent. It does not ask for passphrases.

## Requirements

- Python 3.11 or newer
- macOS or Linux
- OpenSSH client utilities (`ssh`, `ssh-keygen`, `ssh-add`, `ssh-agent`)

## Install

```bash
pip install lupaxa-ssh-doctor
ssh-doctor --help
```

## Commands

```bash
ssh-doctor check
ssh-doctor check --json
ssh-doctor system
ssh-doctor permissions
ssh-doctor keys
ssh-doctor config
ssh-doctor config --host github.com
ssh-doctor agent
ssh-doctor known-hosts
ssh-doctor known-hosts github.com
```

`check` runs the local diagnostics and does not open network connections.
`--verbose` prints extra detail. `--quiet` hides passes and skips.
`--timeout` sets the limit, in seconds, for each external command.

## Output

Each check is `PASS`, `WARN`, `FAIL`, or `SKIP`. A summary line gives the
counts. `--json` prints one document with the version, timestamp, operating
system, results, and summary. Colour is used on a terminal and turned off
when `NO_COLOR` is set.

## Exit Codes

| Code | Meaning                                              |
| :--- | :--------------------------------------------------- |
| 0    | No failures or warnings                              |
| 1    | One or more warnings                                 |
| 2    | One or more failures                                 |
| 3    | Invalid arguments or application configuration       |
| 4    | Diagnostic execution could not be completed          |

Skipped checks alone do not change a successful exit.

## Configuration

An optional TOML file can set the SSH directory, extra key directories,
extra known-host files, enabled or disabled categories, the timeout, the
default output format, and warning identifiers to hide. The file is
`~/.config/ssh-doctor/config.toml`, or the path in `--config` or
`SSH_DOCTOR_CONFIG`. The tool works with no configuration file.

```toml
ssh_directory = "~/.ssh"
timeout = 10
output_format = "text"
disabled_categories = ["agent"]
suppressed_warnings = ["keys.obsolete.id_dsa"]
```

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
