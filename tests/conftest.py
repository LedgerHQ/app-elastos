import pytest
from ragger.conftest import configuration

# Public test phrase from test-data.txt; the audit vectors pay its address. Never fund it.
configuration.OPTIONAL.CUSTOM_SEED = (
    "unhappy despair twin kitten satisfy axis skill initial express surround seat excess "
    "gossip blame session eternal essence memory shrimp girl bamboo viable float output"
)

# A fresh app per test, so no test leaks state into the next.
configuration.OPTIONAL.BACKEND_SCOPE = "function"

pytest_plugins = ("ragger.conftest.base_conftest",)


@pytest.fixture(autouse=True)
def use_supported_devices(skip_tests_for_unsupported_devices, device):
    """Skips unlisted devices and the Nano S, which Speculos no longer emulates."""
    if device.name == "nanos":
        pytest.skip("Speculos has no Nano S model; see tests/host/state_machine")
