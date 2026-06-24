"""CIRIS Server — the fabric node, as a mixed Rust+Python wheel.

The compiled Rust extension (PyO3 abi3) is built by maturin as the in-package
submodule ``ciris_server._native`` (see ``[tool.maturin] module-name`` in
pyproject.toml). This ``__init__`` re-exports its entire public surface so the
historical flat imports the substrate consumers depend on keep working:

    from ciris_server import Engine, NotFound, LensClient   # persist + lens
    import ciris_server; ciris_server.main()                # the node entrypoint

i.e. moving from a pure-Rust top-level extension to a mixed layout is
*transparent* to importers — ``ciris_server`` is still the module that carries
``Engine``/``Edge``/``LensClient``/``main``/``import_traces`` and the
``ciris_server.persist`` / ``ciris_server.edge`` submodules.

What the Python layer adds on top of the Rust core:
  * ``ciris_server.cli`` — the desktop-first launcher (default ``ciris-server``
    starts the node AND the desktop UI; ``serve`` / ``--home`` stays headless).
  * ``ciris_server.desktop_launcher`` — locates the bundled per-platform JAR
    and runs it with the system ``java`` (Java 17+, no bundled JRE).
"""

# Re-export the compiled extension's surface. ``*`` covers main / import_traces
# / the re-hosted persist+lens pyclasses (Engine, NotFound, LensClient, …) that
# the macro-registered ``#[pymodule]`` adds to the module dict. The explicit
# ``main`` re-export below guarantees ``ciris_server.main`` resolves even if a
# future ext drops it from ``__all__``.
from ._native import *  # noqa: F401,F403
from ._native import main, import_traces  # noqa: F401

# Make the substrate submodules importable as ``ciris_server.persist`` /
# ``ciris_server.edge``. The Rust ``#[pymodule]`` registers these into
# ``sys.modules`` at extension-init time (see src/lib.rs::add_child_module), so
# they are already present once ``._native`` is imported above; this is belt-
# and-suspenders for ``from ciris_server.persist import Engine`` static tools.
try:  # pragma: no cover - defensive; submodules are registered by the ext
    from . import _native as _ext  # noqa: F401
except Exception:  # pragma: no cover
    pass

__all__ = ["main", "import_traces"]
