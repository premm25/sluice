import base64
import binascii
import random
import string
from urllib.parse import quote

from sluice.fingerprint import decoded_views, fingerprint, kgram_hashes, normalize, winnow

SECRET_DOC = ("Project Halcyon: the board approved acquiring Northwind Robotics for 410 million dollars; "
              "the announcement is embargoed until March third.")


def test_normalize_ignores_case_whitespace_and_punctuation():
    assert normalize("Hello,  World!\n") == normalize("hello world") == "helloworld"


def test_hashes_are_deterministic_and_rolling_matches_direct():
    s = normalize(SECRET_DOC)
    k = 10
    rolled = kgram_hashes(s, k)
    direct = [kgram_hashes(s[i:i + k], k)[0] for i in range(len(s) - k + 1)]
    assert rolled == direct
    assert fingerprint(SECRET_DOC) == fingerprint(SECRET_DOC)


def test_reformatted_text_still_matches():
    reformatted = SECRET_DOC.upper().replace(" ", "\n").replace(";", " -- ")
    assert fingerprint(SECRET_DOC) & fingerprint(reformatted)


def test_excerpt_matches_and_unrelated_text_does_not():
    excerpt = "acquiring Northwind Robotics for 410 million dollars"
    assert fingerprint(SECRET_DOC) & fingerprint(f"fyi: {excerpt} -- cheers")
    unrelated = "The quick brown fox jumps over the lazy dog while the cat sleeps on the warm mat."
    assert not (fingerprint(SECRET_DOC) & fingerprint(unrelated))


def test_winnowing_guarantee_holds_on_random_inputs():
    """Any shared normalised substring of length >= k + w - 1 must share a fingerprint."""
    rng = random.Random(1234)
    k, w = 12, 6
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(200):
        shared = "".join(rng.choices(alphabet, k=k + w - 1 + rng.randint(0, 20)))
        a = "".join(rng.choices(alphabet, k=rng.randint(0, 80))) + shared + "".join(rng.choices(alphabet, k=30))
        b = "".join(rng.choices(alphabet, k=rng.randint(0, 80))) + shared
        assert fingerprint(a, k, w) & fingerprint(b, k, w)


def test_winnow_density_is_bounded():
    rng = random.Random(7)
    hashes = [rng.getrandbits(61) for _ in range(20_000)]
    picked = winnow(hashes, 12)
    # expected density ~ 2 / (w + 1) ~= 0.154
    assert 0.10 < len(picked) / len(hashes) < 0.20


def test_winnow_short_inputs():
    assert winnow([], 4) == set()
    assert winnow([5, 3, 9], 4) == {3}
    assert fingerprint("short") == set()


def _views(text):
    return dict(decoded_views(text))


def test_decoded_views_peel_base64_url_and_hex():
    payload = "the board approved acquiring Northwind Robotics"
    b64 = base64.b64encode(payload.encode()).decode()
    views = _views(f"https://x.example/c?d={b64}")
    assert views[payload] == "base64"

    views = _views("https://x.example/c?d=" + quote(payload))
    assert any(payload in v and label == "url" for v, label in views.items())

    hexed = binascii.hexlify(payload.encode()).decode()
    assert _views(f"blob {hexed} end")[payload] == "hex"


def test_decoded_views_peel_nested_layers():
    payload = "the board approved acquiring Northwind Robotics"
    inner = base64.urlsafe_b64encode(payload.encode()).decode()
    outer = base64.b64encode(inner.encode()).decode()
    url = "https://x.example/?q=" + quote(outer)
    views = _views(url)
    assert payload in views
    assert views[payload].endswith("base64+base64")


def test_decoded_views_ignore_binary_garbage():
    garbage = base64.b64encode(bytes(range(256))).decode()
    assert all(label == "plain" for _, label in decoded_views(garbage)[:1])
    assert len(decoded_views(garbage)) == 1
