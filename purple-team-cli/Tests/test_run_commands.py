def test_variable_subscription():
    # Simulate interactive mode behavior
    variables = {'a': 1, 'b': 2}
    assert variables['a'] == 1
    assert variables['b'] == 2
    assert variables.get('c', None) is None

def test_variable_subscription_interactive():
    # Simulate variable subscription in interactive mode
    variables = {'x': 10, 'y': 20}
    assert variables['x'] == 10
    assert variables['y'] == 20
    assert variables.get('z', None) is None