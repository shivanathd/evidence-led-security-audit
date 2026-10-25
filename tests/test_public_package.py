import os
import re
import shlex
import unittest
from pathlib import Path

import support
import check_public_package as cpp


class PackageSelfCheck(unittest.TestCase):
    def test_this_package_has_no_rule_matches(self):
        pkg = support.package_copy()
        rep = cpp.scan(pkg, [], cpp.DEFAULT_ALLOWED_HOSTS)
        self.assertEqual(rep.errors, [], rep.errors)

    def test_readme_commands_run(self):
        pkg = support.package_copy()
        out = support.tmpdir()
        readme = (pkg / "README.md").read_text(encoding="utf-8")
        block = re.search(r"<!-- tested-commands -->\s*```bash\n(.*?)```", readme, re.S)
        self.assertIsNotNone(block, "README needs a tested-commands block")
        cmds = [c for c in block.group(1).splitlines() if c.startswith("python3 ")]
        self.assertGreaterEqual(len(cmds), 5)
        for cmd in cmds:
            if "unittest" in cmd:
                continue  # this suite is already running
            argv = shlex.split(cmd.replace("$OUT", out))
            res = support.run_script(argv[1].split("/", 1)[1], *argv[2:], cwd=pkg)
            self.assertEqual(res.returncode, 0, "%s\n%s%s" % (cmd, res.stdout, res.stderr))


class GitMetadata(unittest.TestCase):
    def setUp(self):
        self.pkg = support.package_copy()

    def test_root_git_dir_is_a_warning_not_a_pass_or_block(self):
        (self.pkg / ".git").mkdir()
        (self.pkg / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        rep = cpp.scan(self.pkg, [], cpp.DEFAULT_ALLOWED_HOSTS)
        self.assertEqual(rep.errors, [], rep.errors)
        self.assertIn("GIT_HISTORY", {i["code"] for i in rep.items})

    def test_nested_git_dir_is_still_forbidden(self):
        (self.pkg / "assets" / "vendored" / ".git").mkdir(parents=True)
        rep = cpp.scan(self.pkg, [], cpp.DEFAULT_ALLOWED_HOSTS)
        self.assertIn("FORBIDDEN_ARTIFACT", {i["code"] for i in rep.errors})


class BadPackage(unittest.TestCase):
    def setUp(self):
        self.d = Path(support.tmpdir()) / "bad-skill"
        self.d.mkdir()
        (self.d / "SKILL.md").write_text("---\nname: other\ndescription: x\n---\n", encoding="utf-8")
        # Leak-shaped fixtures are assembled at runtime so this file passes the
        # package's own self-check.
        self.host = "intranet." + "acme-internal" + ".com"
        text = ("Contact jane" + "@" + "corp-mail" + ".com, see https://" + self.host + "/x and " + ".".join(["10", "1", "2", "3"])
                + ", account " + "1234" * 3 + ".\nBuilt at /" + "home/jdoe/projects. Private codename Bluebird.\n")
        (self.d / "README.md").write_text(text, encoding="utf-8")
        (self.d / "notes.txt").write_text("key = %s\n" % support.PLACEHOLDERS["{{FAKE_AWS_KEY}}"], encoding="utf-8")
        (self.d / "package.json").write_text('{"scripts": {"postinstall": "node x.js"}}', encoding="utf-8")
        os.symlink("/etc/hostname", self.d / "link")

    def test_flags_and_does_not_echo(self):
        rep = cpp.scan(self.d, ["Bluebird"], cpp.DEFAULT_ALLOWED_HOSTS)
        got = {i["code"] for i in rep.errors}
        for code in ("SKILL_NAME", "MISSING_FILE", "PUBLIC_LEAK", "SECRET", "INSTALL_HOOK", "SYMLINK", "LOCAL_PATH"):
            self.assertIn(code, got)
        kinds = " ".join(i["message"] for i in rep.errors)
        for kind in ("email_address", "non_reserved_url_host", "ip_address", "account_id_like", "denylisted_term"):
            self.assertIn(kind, kinds)
        dump = repr(rep.items)
        self.assertNotIn("Bluebird", dump)
        self.assertNotIn("acme-internal", dump)
        self.assertNotIn("corp-mail", dump)
        self.assertNotIn(support.PLACEHOLDERS["{{FAKE_AWS_KEY}}"], dump)

    def test_cli_exit_code(self):
        res = support.run_script("check_public_package.py", self.d)
        self.assertEqual(res.returncode, 1)
        self.assertIn("PACKAGE_BLOCKED", res.stdout)


if __name__ == "__main__":
    unittest.main()
