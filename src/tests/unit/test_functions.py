import firewall.functions


def test_wrong_args_for_callable():
    w = firewall.functions.wrong_args_for_callable

    assert w(lambda: 1) is True
    assert w(lambda x: 1) is False
    assert w(lambda x: 1, 5) is True
    assert w(lambda x: 1, x=5) is True
    assert w(lambda x: 1, y=5) is False
