from seedfuz.mutation import Mutator


def test_bit_flip_changes_exactly_one_bit() -> None:
    result = Mutator().bit_flip(b"\x00\xff", offset=0, bit=3)
    assert result.data == b"\x08\xff"
    assert result.offsets == (0,)


def test_operator_rotation_includes_smart_mutation() -> None:
    results = list(Mutator(random_seed=7, smart_selection=True).generate(b"\x08name=admin", 6))
    assert [item.operator for item in results] == [
        "bit-flip",
        "byte-boundary",
        "smart-field",
        "bit-flip",
        "byte-boundary",
        "smart-field",
    ]
    assert all(item.data != b"\x08name=admin" for item in results)


def test_mutations_are_reproducible() -> None:
    first = [item.data for item in Mutator(42).generate(b"abcdef", 12)]
    second = [item.data for item in Mutator(42).generate(b"abcdef", 12)]
    assert first == second


def test_preserve_session_keeps_token_bytes_intact() -> None:
    seed = b"POST /x HTTP/1.1\r\nCookie: sid=SECRETTOKEN\r\n\r\nbody=1"
    start = seed.index(b"SECRETTOKEN")
    token = range(start, start + len(b"SECRETTOKEN"))
    mutator = Mutator(random_seed=3, smart_selection=True, preserve_session=True)
    for item in mutator.generate(seed, 30):
        assert all(offset not in token for offset in item.offsets)
        assert item.data[start : start + len(b"SECRETTOKEN")] == b"SECRETTOKEN"
