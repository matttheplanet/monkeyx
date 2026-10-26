# Custom MonkeyX Plugin Example

This folder demonstrates how end users can add custom modules/workflows without
modifying the `monkeyx` repository.

## Files

- `monkeyx_plugin.py` plugin declaration consumed by `core/plugin_loader.py`
- `custom_module.py` example module implementation

## Run

```bash
export MONKEYX_PLUGINS=/absolute/path/to/monkeyx/examples/custom_plugin
python monkeyx.py --list-plugins
```

You should see:

- Module: `custom_echo`
- Workflow: `custom_demo`
