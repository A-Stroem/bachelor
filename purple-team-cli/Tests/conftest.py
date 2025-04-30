import pytest

@pytest.fixture
def sample_data():
    return {"key": "value"}

@pytest.fixture(autouse=True)
def setup_teardown():
    # Setup code here
    yield
    # Teardown code here