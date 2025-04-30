def test_variable_subscription_interactive_mode():
    # Simulate interactive mode behavior
    variables = {'var1': 10, 'var2': 20}
    result = subscribe_to_variable('var1', variables)
    assert result == 10

def test_variable_subscription_non_interactive_mode():
    # Simulate non-interactive mode behavior
    variables = {'var1': 10, 'var2': 20}
    result = subscribe_to_variable('var3', variables)
    assert result is None

def subscribe_to_variable(var_name, variables):
    return variables.get(var_name)