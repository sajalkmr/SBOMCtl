import pytest
from cpabe import cpabe_setup

@pytest.fixture(scope="session")
def cpabe_keys():
    """Fixture to provide CP-ABE keys for tests"""
    pk, mk = cpabe_setup()
    return {"public_key": pk, "master_key": mk}
