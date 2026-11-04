import auth


def test_browser_login_does_not_autoload_windows_extensions():
    assert not hasattr(auth, "_KNOWN_EXTENSION_IDS")
    assert not hasattr(auth, "_WIN_EXTENSION_DIRS")
