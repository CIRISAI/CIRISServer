# PyInstaller entry point for the Windows ciris-server desktop installer.
#
# Bare invocation = desktop mode (cli.main spawns the headless node child, waits
# on the read API, launches the Compose JAR). When the parent re-invokes this
# same frozen exe with `--headless` (see cli._spawn_headless_node), cli.main
# routes straight to the in-process Rust node. One exe, both roles.
import multiprocessing

from ciris_server.cli import main

if __name__ == "__main__":
    # Harmless when unused; required hygiene if any dependency ever spawns via
    # multiprocessing under a frozen build.
    multiprocessing.freeze_support()
    main()
