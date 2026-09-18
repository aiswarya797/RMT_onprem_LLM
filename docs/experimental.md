# Experimental workflows

The default preview is same-machine passive monitoring on Apple Silicon macOS.

These implementations remain in the repository but are disabled by default:

- Remote master/collector installation, enrollment UI/API, network listener and remote collector transport. Physical two-Mac activation is unresolved.
- Explicit inference probes and request-evidence import/comparisons. Successful local inference qualification and complete live comparison UX are pending.
- Notification destination setup and outbound delivery. Transport and persistence tests passed; complete live destination UX is pending.

Local monitoring, retained history, investigations, in-app alert rules, backup/recovery and removal remain available. Existing experimental data and credentials are preserved. A new default hub does not start a previously configured remote listener or send retained notifications.

## Developer opt-in

Set `LLM_MONITOR_EXPERIMENTAL=1` in the environment of the relevant process. For example:

```sh
LLM_MONITOR_EXPERIMENTAL=1 ./llm-monitor-install.sh master
```

Setup records that opt-in in the generated LLM Monitor LaunchAgent plist so launchd starts the same feature set. This is a developer testing switch, not a promise that remote collection works. No privacy permission, TLS validation or inference-admission check is bypassed.

To return a stopped installation to the local preview, run the local installer/setup without the variable. Retained remote hosts and their historical observations are not removed. Restart the hub with its regenerated default LaunchAgent for the gate to take effect. Do not use the opt-in as an end-user troubleshooting instruction.

The dashboard receives its feature state from the hub. Hidden experimental actions also return `preview_feature_disabled` at the HTTP/CLI boundary, so older clients cannot accidentally enable them. Starting an existing remote collector without the opt-in fails with an explanatory message rather than silently treating it as local.
