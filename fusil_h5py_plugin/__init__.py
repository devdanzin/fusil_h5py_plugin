"""
Fusil h5py plugin.

Provides fusil's Python fuzzer with deep, h5py-specific fuzzing support:
  * ``genH5PyObject`` argument generator (injects references to pre-built "tricky"
    h5py objects into fuzzed calls),
  * a definitions provider that emits the tricky-object setup code plus the runtime
    slice/link helper functions,
  * an instance dispatcher that fuzzes Dataset / Group / File / AttributeManager
    instances with type-specific operations, and
  * a class handler that instantiates h5py's File / Dataset / Group correctly
    (they need a backing file, not a generic ``callFunc``).

This code used to live in-tree under ``fusil/python/h5py/``. It was extracted into a
plugin so the ~4.6k LOC of optional, heavyweight h5py machinery does not sit in the
core generator. The three moved modules (``h5py_argument_generator``, ``h5py_tricky_weird``,
``write_h5py_code``) are unchanged apart from having their intra-package imports rewritten
to ``fusil_h5py_plugin.*``.

Activates when the fuzzed module is ``h5py`` (``--modules h5py``) or when ``--fuzz-h5py``
is passed. It has no effect on runs targeting other modules.
"""

import sys

# The moved modules import h5py and numpy at load time; if those aren't installed the
# plugin simply does nothing rather than breaking fusil startup.
try:
    from . import h5py_tricky_weird
    from .h5py_argument_generator import H5PyArgumentGenerator
    from .write_h5py_code import WriteH5PyCode

    _H5PY_AVAILABLE = True
except ImportError as _e:  # pragma: no cover - depends on optional deps
    _H5PY_AVAILABLE = False
    _IMPORT_ERROR = _e


def _is_h5py_target(config, module_name) -> bool:
    """True when this run should get h5py fuzzing support.

    Active when the ``--fuzz-h5py`` flag is set, or when ``h5py`` appears in the target
    module(s). ``module_name`` may be a single module or a comma-separated list depending
    on the calling hook, so handle both.
    """
    if getattr(config, "fuzz_h5py", False):
        return True
    mods = module_name or ""
    return "h5py" in [m.strip() for m in mods.split(",")]


class _StringCaptureParent:
    """Minimal stand-in for ``WritePythonCode`` that captures ``write``/``emptyLine``
    output into a string, used to render the writer's header helpers as a definitions
    block. The header helpers are all emitted at level 0 with pre-dedented text."""

    def __init__(self):
        self._lines: list[str] = []
        self.base_level = 0

    def write(self, level, text):
        self._lines.append(("    " * level) + text)

    def emptyLine(self):
        self._lines.append("")

    def getvalue(self) -> str:
        return "\n".join(self._lines)


_header_helpers_cache: str | None = None


def _h5py_header_helpers() -> str:
    """The runtime helper functions (``_fusil_h5_create_dynamic_slice_for_rank`` and
    ``_fusil_h5_get_link_target_in_file``) plus the numpy import that the writer emits.

    Rendered once by driving ``WriteH5PyCode._write_h5py_script_header_and_imports``
    through a string-capturing parent, so the plugin stays the single source of truth
    for that code rather than duplicating it."""
    global _header_helpers_cache
    if _header_helpers_cache is None:
        shim = _StringCaptureParent()
        WriteH5PyCode(shim)._write_h5py_script_header_and_imports()
        _header_helpers_cache = shim.getvalue()
    return _header_helpers_cache


def _ensure_h5py_arg_gen(writer):
    """Ensure ``writer.arg_generator`` carries a live ``H5PyArgumentGenerator``.

    The writer reaches its per-type value generators via
    ``self.parent.arg_generator.h5py_argument_generator.genH5Py*``. Since the core no
    longer builds that instance, attach one here (its ``parent`` is the ArgumentGenerator,
    which provides ``genInt``/``genFloat``/``genString`` used by ``genH5PyAttributeValue_expr``)."""
    arg_gen = writer.arg_generator
    if getattr(arg_gen, "h5py_argument_generator", None) is None:
        arg_gen.h5py_argument_generator = H5PyArgumentGenerator(arg_gen)


def register(manager):
    """Plugin entry point (``fusil.plugins`` group)."""
    if not _H5PY_AVAILABLE:
        print(
            f"[h5py plugin] h5py/numpy unavailable ({_IMPORT_ERROR}); h5py fuzzing disabled.",
            file=sys.stderr,
        )
        return

    # Advertise the plugin's hard numpy requirement (h5py itself pulls numpy in, but the
    # tricky-object machinery uses numpy directly). Reached only when _H5PY_AVAILABLE, i.e.
    # numpy imported successfully above, so this documents the dep rather than gating on it.
    manager.declare_dependency("numpy")

    # --- CLI: force h5py support on for any target module ---
    manager.add_cli_option(
        "--fuzz-h5py",
        action="store_true",
        default=False,
        help="Enable h5py-specific fuzzing support even when h5py is not the target module.",
    )

    # --- Argument generator: inject references to pre-built tricky h5py objects ---
    # genH5PyObject only reads the module-level tricky_h5py_names, so a parent-less
    # instance suffices for this one method. weight=50 matches the historical in-core
    # injection (`simple_argument_generators += (genH5PyObject,) * 50`).
    _obj_gen = H5PyArgumentGenerator(parent=None)
    manager.add_argument_generator(
        _obj_gen.genH5PyObject, "simple", weight=50, condition=_is_h5py_target
    )

    # --- Definitions: tricky-object setup + runtime slice/link helpers ---
    def provide_h5py_definitions(config, module_name):
        if not _is_h5py_target(config, module_name):
            return None
        return "\n".join(
            [
                "# --- BEGIN h5py plugin definitions ---",
                _h5py_header_helpers(),
                h5py_tricky_weird.tricky_h5py_code,
                "# --- END h5py plugin definitions ---",
            ]
        )

    manager.add_definitions_provider(provide_h5py_definitions)

    # --- Instance dispatcher: type-specific fuzzing for h5py object instances ---
    # Emits `elif isinstance(target, h5py.Dataset): ...` branches (plus Group/File/
    # AttributeManager) and opens the trailing `else:` for the core's generic fallback,
    # returning the level to restore. Gated on the target so non-h5py runs (where h5py
    # isn't imported in the generated script) don't emit these branches.
    def h5py_instance_dispatcher(
        writer, current_prefix, target_obj_expr_str, class_name_hint, generation_depth
    ):
        if not _is_h5py_target(writer.options, writer.module_name):
            return None
        _ensure_h5py_arg_gen(writer)
        return WriteH5PyCode(writer)._dispatch_fuzz_on_h5py_instance(
            class_name_hint, current_prefix, generation_depth, target_obj_expr_str
        )

    manager.add_instance_dispatcher(h5py_instance_dispatcher)

    # --- Class handler: correct instantiation of h5py File / Dataset / Group ---
    def h5py_class_handler(writer, class_name_str, class_type, instance_var_name, prefix):
        if not _is_h5py_target(writer.options, writer.module_name):
            return False
        _ensure_h5py_arg_gen(writer)
        return WriteH5PyCode(writer).fuzz_one_h5py_class(
            class_name_str, class_type, instance_var_name, prefix
        )

    manager.add_class_handler(h5py_class_handler)

    def h5py_startup_hook(config):
        if _is_h5py_target(config, getattr(config, "modules", "") or ""):
            print("[h5py plugin] h5py fuzzing support loaded", file=sys.stderr)

    manager.add_hook("startup", h5py_startup_hook)
