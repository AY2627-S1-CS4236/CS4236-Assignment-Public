import importlib
import math

import pytest


def _module():
    return importlib.import_module("educrypto.number_theory")


@pytest.mark.parametrize(
    ("a", "b"),
    [(240, 46), (0, 9), (9, 0), (-25, 10), (25, -10), (-25, -10)],
)
def test_extended_gcd_identity(a, b):
    module = _module()
    g, x, y = module.extended_gcd(a, b)
    assert g == math.gcd(a, b)
    assert g >= 0
    assert a * x + b * y == g


def test_extended_gcd_zero_pair():
    assert _module().extended_gcd(0, 0) == (0, 0, 0)


def test_inverse_mod_examples_and_normalization():
    module = _module()
    assert module.inverse_mod(3, 11) == 4
    assert module.inverse_mod(-3, 11) == 7
    result = module.inverse_mod(17, 43)
    assert 0 <= result < 43
    assert (17 * result) % 43 == 1


def test_inverse_mod_rejects_invalid_cases():
    module = _module()
    with pytest.raises(ValueError):
        module.inverse_mod(2, 4)
    with pytest.raises(ValueError):
        module.inverse_mod(1, 0)
    with pytest.raises(TypeError):
        module.extended_gcd(1.5, 2)

