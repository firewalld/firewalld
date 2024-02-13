import firewall.functions


def test_iter_split_every():
    def f_split(iterable, n):
        return list(firewall.functions.iter_split_every(iterable, n))

    assert f_split([0, 1, 2, 3, 4, 5], 2) == [[0, 1], [2, 3], [4, 5]]
    assert f_split([0, 1, 2, 3, 4, 5, 6], 2) == [[0, 1], [2, 3], [4, 5], [6]]
    assert f_split([], 2) == []
