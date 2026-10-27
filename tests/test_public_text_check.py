# SPDX-License-Identifier: EUPL-1.2
"""The contribution-time gate (decision 0027) fails on identity and paths, flags attack detail, hides private patterns."""
import tools.public_text_check as ptc


def _check(tmp_path, capsys, text, *extra, env=None, monkeypatch=None):
    if env is not None:
        monkeypatch.setenv("RELIKEY_PRIVATE_PATTERNS", env)
    body = tmp_path / "body.md"
    body.write_text(text, encoding="utf-8")
    code = ptc.main(["--text", str(body), *extra])
    return code, capsys.readouterr().out


def test_a_plain_change_description_is_clean(tmp_path, capsys):
    code, out = _check(tmp_path, capsys, "The agent asks again for an address it lacked.\nTests: agent_test.go.\n")
    assert code == 0 and "clean" in out


def test_a_local_path_fails_hard(tmp_path, capsys):
    # Assembled at run time: the literal path would trip the gate on this file itself.
    code, out = _check(tmp_path, capsys, "Seen in /" + "home/alice/build.log\n")
    assert code == 3 and "HARD-FAIL line 1" in out
    # Tools write Windows paths with forward slashes too (uv's "via -r" lines did).
    code, out = _check(tmp_path, capsys, "# via -r c:" + "/Users/x/req.in\n")
    assert code == 3


def test_attack_detail_is_a_flag_until_a_human_read_it(tmp_path, capsys):
    code, out = _check(tmp_path, capsys, "Found in the red team.\n")
    assert code == 1 and "flag line 1" in out
    code, out = _check(tmp_path, capsys, "Found in the red team.\n", "--flags-ok")
    assert code == 0


def test_a_private_pattern_fails_without_publishing_itself(tmp_path, capsys, monkeypatch):
    code, out = _check(tmp_path, capsys, "Ran on box-zeta-9 last night.\n", env="box-zeta-[0-9]",
                       monkeypatch=monkeypatch)
    assert code == 3 and "private pattern" in out and "box-zeta" not in out
