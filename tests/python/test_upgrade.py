"""ciris_server.upgrade: run by tests/upgrade_helper.rs. Standard library only, so
it needs no installed wheel, like the module it tests."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "python" / "ciris_server"
spec = importlib.util.spec_from_file_location("upgrade_under_test", SRC / "upgrade.py")
upgrade = importlib.util.module_from_spec(spec)
sys.modules["upgrade_under_test"] = upgrade
spec.loader.exec_module(upgrade)


def dist(site, name, version, files=()):
    d = site / f"{name}-{version}.dist-info"
    d.mkdir()
    (d / "RECORD").write_text("".join(f"{f},,\n" for f in files))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name)


class Jars(Base):
    def test_newest_is_by_version_not_by_sort(self):
        jars = [Path(f"CIRIS-windows-x64-0.5.{n}.jar") for n in (99, 100, 237)]
        self.assertEqual(upgrade.newest_jar(jars).name, "CIRIS-windows-x64-0.5.237.jar")
        self.assertIsNone(upgrade.newest_jar([]))

    def test_private_copy_is_outside_the_install_and_old_copies_go(self):
        home = self.site / "home"
        old = self.site / "CIRIS-1.0.jar"
        new = self.site / "CIRIS-2.0.jar"
        old.write_bytes(b"old")
        new.write_bytes(b"newer")
        first = upgrade.private_jar(old, home)
        self.assertEqual(first.parent, home / "runtime" / "desktop")
        second = upgrade.private_jar(new, home)
        self.assertEqual(second.read_bytes(), b"newer")
        self.assertFalse(first.exists(), "the older private copy is removed")

    def test_the_class_path_comes_with_the_private_copy(self):
        import zipfile

        # The installed layout: the jar two levels under site-packages, FFmpeg in
        # ciris_holon/media/jars, named relative to the jar by its manifest.
        jar_dir = self.site / "ciris_client" / "_artifacts"
        jar_dir.mkdir(parents=True)
        media = self.site / "ciris_holon" / "media" / "jars"
        media.mkdir(parents=True)
        (media / "ffmpeg-7-linux.jar").write_bytes(b"ffmpeg")
        (media / "SHA256SUMS").write_text("x  ffmpeg-7-linux.jar\n")
        names = "../../ciris_holon/media/jars/ffmpeg-7-linux.jar ../../ciris_holon/media/jars/javacpp-1-linux.jar"
        manifest = "Manifest-Version: 1.0\r\nClass-Path: " + names[:58] + "\r\n " + names[58:] + "\r\n\r\n"
        jar = jar_dir / "CIRIS-3.0.jar"
        with zipfile.ZipFile(jar, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", manifest)
        self.assertEqual(upgrade.manifest_class_path(jar), names.split())
        home = self.site / "home"
        run = upgrade.private_jar(jar, home)
        got = (run.parent / "../../ciris_holon/media/jars/ffmpeg-7-linux.jar").resolve()
        self.assertEqual(got.read_bytes(), b"ffmpeg", "FFmpeg resolves from the private copy")
        self.assertTrue((got.parent / "SHA256SUMS").is_file())
        # javacpp is missing from the install: skipped, not invented.
        self.assertFalse((got.parent / "javacpp-1-linux.jar").exists())

        # The doctor resolves the copy the launcher runs: ffmpeg OK, javacpp FAIL.
        rows = {r["entry"].rsplit("/", 1)[-1]: r["ok"] for r in upgrade.check_class_path(run)}
        self.assertEqual(rows, {"ffmpeg-7-linux.jar": True, "javacpp-1-linux.jar": False})
        rep = upgrade.doctor(site=self.site, home=home, probe_pythons=False)
        self.assertFalse(rep.healthy, "a Class-Path entry the JVM cannot find is a FAIL")

        # The holon jars' version moves: the old copy goes, the new one lands.
        (media / "ffmpeg-7-linux.jar").rename(media / "ffmpeg-8-linux.jar")
        names8 = names.replace("ffmpeg-7", "ffmpeg-8")
        jar8 = jar_dir / "CIRIS-4.0.jar"
        with zipfile.ZipFile(jar8, "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nClass-Path: " + names8 + "\r\n\r\n")
        upgrade.private_jar(jar8, home)
        self.assertTrue((got.parent / "ffmpeg-8-linux.jar").is_file())
        self.assertFalse(got.exists(), "the old holon copy is removed when the version moves")

    def test_pythons_on_path_lists_this_interpreter(self):
        rows = upgrade.pythons_on_path()
        self.assertTrue(all("executable" in r and "agent" in r for r in rows))


class Watcher(Base):
    def test_a_tilde_dir_or_a_changed_version_is_an_upgrade(self):
        dist(self.site, "ciris_server", "0.5.244")
        base = upgrade.dist_versions(self.site)
        self.assertIsNone(upgrade.upgrade_started(self.site, base))
        (self.site / "~iris_server").mkdir()
        self.assertIn("~iris_server", upgrade.upgrade_started(self.site, base))
        (self.site / "~iris_server").rmdir()
        shutil.rmtree(self.site / "ciris_server-0.5.244.dist-info")
        dist(self.site, "ciris_server", "0.5.245")
        self.assertIn("0.5.245", upgrade.upgrade_started(self.site, base))

    def test_watch_fires_once_on_a_real_rename(self):
        (self.site / "ciris_client").mkdir()
        seen = []
        upgrade.watch(seen.append, site=self.site, interval_secs=0.02)
        time.sleep(0.1)
        self.assertEqual(seen, [], "quiet while nothing happens")
        (self.site / "ciris_client").rename(self.site / "~iris_client")
        time.sleep(0.2)
        self.assertEqual(len(seen), 1)


class Doctor(Base):
    def half_install(self):
        """Run 41850556394: the agent's dist-info gone, ciris_engine partial,
        ciris_adapters empty, client and server new, `~` leftovers."""
        for pkg in ("ciris_engine", "ciris_adapters", "ciris_server", "ciris_client"):
            (self.site / pkg).mkdir()
        (self.site / "ciris_server" / "__init__.py").touch()
        dist(self.site, "ciris_server", "0.5.244", ["ciris_server/__init__.py"])
        dist(self.site, "ciris_client", "0.5.237")
        (self.site / "~iris_engine").mkdir()
        (self.site / "~iris_agent-2.18.0.dist-info").mkdir()

    def test_a_healthy_install_is_healthy(self):
        (self.site / "ciris_server").mkdir()
        (self.site / "ciris_server" / "__init__.py").touch()
        dist(self.site, "ciris_server", "0.5.244", ["ciris_server/__init__.py"])
        self.assertTrue(upgrade.doctor(site=self.site, home=self.site / 'nohome', probe_pythons=False).healthy)

    def test_the_half_install_from_the_field_is_named_and_repaired(self):
        self.half_install()
        seen = upgrade.doctor(site=self.site, home=self.site / 'nohome', probe_pythons=False)
        self.assertFalse(seen.healthy)
        self.assertIn("ciris_agent", seen.half_installed)
        self.assertEqual(len(seen.tilde), 2)
        self.assertTrue((self.site / "~iris_engine").exists(), "report only: nothing touched")
        fixed = upgrade.doctor(repair=True, site=self.site, home=self.site / 'nohome', probe_pythons=False)
        self.assertFalse(list(self.site.glob("~iris*")))
        self.assertIn("--force-reinstall", fixed.pip_command)
        self.assertIn("ciris-agent", fixed.pip_command)

    def test_a_file_missing_from_record_is_half_installed(self):
        (self.site / "ciris_server").mkdir()
        dist(self.site, "ciris_server", "0.5.244", ["ciris_server/gone.py"])
        self.assertIn("ciris_server", upgrade.doctor(site=self.site, home=self.site / 'nohome', probe_pythons=False).half_installed)

    def test_stale_jars_keep_the_newest(self):
        app = self.site / "ciris_engine" / "desktop_app"
        app.mkdir(parents=True)
        for v in ("2.18.0", "2.19.1"):
            (app / f"CIRIS-windows-x64-{v}.jar").touch()
        dist(self.site, "ciris_agent", "2.19.1")
        upgrade.doctor(repair=True, site=self.site, home=self.site / 'nohome', probe_pythons=False)
        self.assertEqual([p.name for p in app.iterdir()], ["CIRIS-windows-x64-2.19.1.jar"])


class ReachableFromABrokenInstall(Base):
    def run_py(self, *args):
        env = {k: v for k, v in os.environ.items() if k != "PYTHONHOME"}
        env["PYTHONPATH"] = str(self.site)
        return subprocess.run([sys.executable, *args], env=env, capture_output=True, text=True, timeout=30)

    def setUp(self):
        super().setUp()
        pkg = self.site / "ciris_server"
        pkg.mkdir()
        for name in ("__init__.py", "upgrade.py"):
            shutil.copy(SRC / name, pkg / name)
        # No `_native`: what an interrupted pip can leave.

    def test_the_repair_command_runs_without_the_native_library(self):
        r = self.run_py("-m", "ciris_server.upgrade", "--json")
        self.assertIn('"healthy"', r.stdout, r.stderr)
        # Resolved on both sides: macOS's temp dir is /var -> /private/var, and
        # the helper reports the path the interpreter resolved.
        self.assertEqual(
            os.path.realpath(json.loads(r.stdout)["site"]), os.path.realpath(self.site)
        )

    def test_anything_else_still_fails_loudly(self):
        r = self.run_py("-c", "import ciris_server")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("_native", r.stderr, "a normal import must not hide a broken library")


if __name__ == "__main__":
    unittest.main()
