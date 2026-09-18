# Recover the installed foundation

> Same-machine developer preview: remote setup, probes, comparisons and external notifications are disabled by default. Historical advanced instructions require the explicit [experimental opt-in](experimental.md). See [current verification and limits](preview-verification.md).


All commands below are local and work offline. They inspect LLM Monitor only.

## A service is unavailable

Start with the product status and the user launchd domain:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" status
launchctl print "gui/$UID/com.llm-monitor.hub"
launchctl print "gui/$UID/com.llm-monitor.collector"
tail -n 100 "$HOME/Library/Logs/LLM Monitor/hub.error.log"
tail -n 100 "$HOME/Library/Logs/LLM Monitor/collector.error.log"
```

`launchctl print` may exit nonzero when a service is not loaded; that result is diagnostic. Rerun the idempotent setup after resolving the reported permission, port or path problem:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" install check --role local
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" setup local
```

Do not kill a process that owns a conflicting port. Choose a free configured port after identifying the owner.

## The first setup token expired

If no administrator exists:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" admin bootstrap-renew
```

Return to the local browser and choose **Check again**. The browser obtains the
new one-use setup handoff automatically; the command never prints the secret
or asks you to find a token file.

## The browser session ended

Sign in again. Session expiry and logout do not delete protected monitor data. If the local hub does not respond, use the service checks above.

## Preserve files before deeper recovery

Use the product-owned keep-data path rather than manual LaunchAgent or file deletion:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" uninstall --keep-data --preview
```

The preview enumerates binaries, LaunchAgents, sockets, logs and retained protected state. Do not manually change database files while the hub is running. Backup/restore, password reset and migration recovery are completed in later lifecycle chunks and are not claimed by this foundation.
