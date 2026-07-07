"""The startup hook caps the core generation-volume knobs when h5py is the target.

h5py's per-instance code generation is far heavier than a normal class (a File recurses into
groups/datasets, each create_dataset method call spawns a dataset, and every dataset emits many
slice/resize/astype/asstr/fields/iter/fancy-index op blocks). At the core's default volume knobs
(50 classes / 100 objects / 15 methods, tuned for lightweight classes) a single session's
source.py explodes to ~600k lines / ~50s. The startup hook caps those knobs to h5py-sane values
so sessions stay a few seconds -- but only when h5py is the *target* module, not when --fuzz-h5py
merely injects h5py args into a different, lighter target.
"""

import unittest
from types import SimpleNamespace

import fusil_h5py_plugin


class _StubManager:
    """Collects the hooks the plugin registers; every other add_*/declare_* is a no-op."""

    def __init__(self):
        self.hooks = {}

    def add_hook(self, name, func):
        self.hooks.setdefault(name, []).append(func)

    def __getattr__(self, _name):
        return lambda *a, **k: None


def _startup_hook():
    m = _StubManager()
    fusil_h5py_plugin.register(m)
    return m.hooks["startup"][0]


DEFAULTS = dict(methods_number=15, classes_number=50, objects_number=100, functions_number=250)


@unittest.skipUnless(
    getattr(fusil_h5py_plugin, "_H5PY_AVAILABLE", False),
    "h5py/numpy not importable; plugin register() is a no-op",
)
class TestStartupHookCaps(unittest.TestCase):
    def test_caps_applied_when_h5py_is_target(self):
        hook = _startup_hook()
        cfg = SimpleNamespace(modules="h5py", fuzz_h5py=False, **DEFAULTS)
        hook(cfg)
        self.assertEqual(
            (cfg.methods_number, cfg.classes_number, cfg.objects_number, cfg.functions_number),
            (5, 10, 5, 25),
        )

    def test_not_capped_when_h5py_only_injected_into_other_target(self):
        # --fuzz-h5py on a lighter target: h5py classes are never deeply fuzzed, so the
        # target module keeps its full budget.
        hook = _startup_hook()
        cfg = SimpleNamespace(modules="json", fuzz_h5py=True, **DEFAULTS)
        hook(cfg)
        self.assertEqual(
            (cfg.methods_number, cfg.classes_number, cfg.objects_number, cfg.functions_number),
            (15, 50, 100, 250),
        )

    def test_h5py_in_a_module_list_is_capped(self):
        hook = _startup_hook()
        cfg = SimpleNamespace(modules="h5py,json", fuzz_h5py=False, **DEFAULTS)
        hook(cfg)
        self.assertEqual(cfg.methods_number, 5)

    def test_already_low_knobs_are_not_raised(self):
        hook = _startup_hook()
        cfg = SimpleNamespace(
            modules="h5py",
            fuzz_h5py=False,
            methods_number=2,
            **{k: v for k, v in DEFAULTS.items() if k != "methods_number"},
        )
        hook(cfg)
        self.assertEqual(cfg.methods_number, 2)  # cap only lowers, never raises

    def test_not_capped_when_not_h5py_target_at_all(self):
        hook = _startup_hook()
        cfg = SimpleNamespace(modules="json", fuzz_h5py=False, **DEFAULTS)
        hook(cfg)  # register()'s _is_h5py_target is False -> hook returns early
        self.assertEqual(cfg.methods_number, 15)


if __name__ == "__main__":
    unittest.main()
