import pytest
from satosa.context import Context
from satosa.state import State


@pytest.fixture
def context():
    context = Context()
    context.state = State()
    return context
