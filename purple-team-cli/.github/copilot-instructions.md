# Purple Team CLI Development Guidelines

This section outlines the recommended technology stack, best practices, and programming paradigm for developing the Purple Team CLI tool using Python 3.x.

## 4.1. Recommended Technology Stack (MVP)

- **Language**: Python 3.8+
  - _Rationale_: Leverages newer features like assignment expressions and improved type hinting support relevant for frameworks like `Typer`.
- **Core Execution**: `subprocess` module (Built-in)
  - _Rationale_: Essential for invoking external commands, specifically `powershell` or `pwsh` to run `Invoke-AtomicTest`.
- **CLI Framework**: `Typer`
  - _Rationale_: `Typer` builds on `Click`, offering a modern, intuitive interface based on Python type hints. It reduces boilerplate code compared to `argparse` and even `Click` for many common patterns, leading to cleaner and more maintainable CLI code. It provides automatic help generation, robust type validation, and good support for subcommands. While `argparse` is built-in and `Click` is powerful and established, `Typer` strikes a good balance of power, ease of use, and modern Python features suitable for this project.
- **Dependency Management**: `pyproject.toml` managed via `uv` or `Poetry`.
  - _Rationale_: `pyproject.toml` is the modern standard for Python project configuration. Tools like `uv` (very fast) or `Poetry` provide robust dependency resolution, lock file generation (`uv.lock` / `poetry.lock`), virtual environment management, and build capabilities, ensuring reproducible environments and simplifying dependency management compared to manual `requirements.txt` handling.
- **Testing Framework**: `pytest`.
  - _Rationale_: `pytest` offers a less verbose, more powerful, and more Pythonic testing experience compared to the built-in `unittest` module, with strong support for fixtures, parametrization, and plugins. It integrates well with `Typer`/`Click`'s `CliRunner` for testing CLI interactions.

## 4.2. Python Best Practices

Adhering to best practices ensures code quality, maintainability, and robustness.

### 4.2.1. Code Structure and Modularity

- **Goal**: Organize code logically for readability and maintainability as the application grows.
- **Structure**:
  - Use a standard project layout (e.g., `src/` layout or flat layout with `pyproject.toml` at the root).
  - Separate CLI interface logic (argument parsing, user interaction - likely in modules using `Typer` commands) from core application logic (test execution orchestration, result processing, configuration management).
  - Group related functions and classes into modules (e.g., `config.py`, `executor.py`, `reporting.py`, `cli_commands/`).
  - Use relative imports within the application package.
- **Do**:
  - Create separate modules for distinct concerns (e.g., CLI definition, test execution, configuration).
  - Use `Typer`'s app structure or `Click` groups to organize commands logically.
  - Example structure (simplified):
    ```
    # pyproject.toml
    # src/
    #   purple_cli/
    #     __init__.py
    #     __main__.py  # Entry point calling cli.app()
    #     cli.py       # Typer app definition, imports commands
    #     commands/
    #       __init__.py
    #       run.py     # Defines the 'run' command
    #       config.py  # Defines the 'config' command
    #     core/
    #       __init__.py
    #       executor.py # Logic for running tests via subprocess
    #       config.py   # Logic for handling configuration
    # tests/
    #  ... test files...
    ```
- **Don't**:
  - Put all code into a single large script file.
  - Avoid circular dependencies between modules.
  - Mix UI/CLI code deeply within core business logic.

### 4.2.2. Error Handling (`subprocess`, User Input)

- **Goal**: Handle potential errors gracefully, providing informative feedback to the user without crashing.

- **`subprocess` Handling**:

  - Use `try...except` blocks specifically targeting subprocess exceptions: `FileNotFoundError` (command not found), `subprocess.TimeoutExpired`, and `subprocess.CalledProcessError` (non-zero exit code when `check=True`).
  - When using `subprocess.run`, set `check=True` to automatically raise `CalledProcessError` on non-zero exit codes, simplifying error checking.
  - Always use the `timeout` parameter in `subprocess.run` to prevent indefinite hangs.
  - Capture `stdout` and `stderr` (`capture_output=True`, `text=True`) to provide context in error messages. `text=True` (or `encoding='utf-8'`) decodes output as text.
  - Prefer passing commands as a list of arguments (`subprocess.run(['powershell', '-Command', script_path])`) rather than using `shell=True` to avoid shell injection vulnerabilities, especially if paths or arguments involve user input.

- **User Input Handling**:

  - Use the CLI framework's (`Typer`/`Click`) capabilities for type validation and prompting.
  - Validate file paths provided by the user (e.g., existence, permissions) before attempting to use them.
  - Handle potential `ValueError` or other exceptions during type conversion or validation.

- **Do**:

  ```python
  import subprocess
  import sys

  def execute_command(command_list, timeout=60):
      """Executes an external command safely."""
      try:
          result = subprocess.run(
              command_list,
              check=True,          # Raise CalledProcessError on non-zero exit
              capture_output=True, # Capture stdout/stderr
              text=True,           # Decode output as text
              timeout=timeout      # Prevent hangs
          )
          print(f"Command successful:\\n{result.stdout}")
          return True, result.stdout
      except FileNotFoundError:
          print(f"Error: Command not found: {command_list}", file=sys.stderr)
          return False, f"Error: Command not found: {command_list}"
      except subprocess.CalledProcessError as e:
          print(f"Error: Command '{' '.join(e.cmd)}' failed with exit code {e.returncode}", file=sys.stderr)
          print(f"Stderr:\\n{e.stderr}", file=sys.stderr)
          return False, e.stderr
      except subprocess.TimeoutExpired:
          print(f"Error: Command timed out after {timeout} seconds", file=sys.stderr)
          return False, f"Error: Command timed out after {timeout} seconds"
      except Exception as e: # General fallback for unexpected errors
           print(f"An unexpected error occurred: {e}", file=sys.stderr)
           return False, f"An unexpected error occurred: {e}"

  # Example usage:
  # success, output = execute_command(['powershell', '-Command', 'Get-Location'])
  # success, output = execute_command(['non_existent_command'])
  # success, output = execute_command(['sleep', '5'], timeout=3) # Example timeout
  ```

- **Don't**:
  - Ignore `subprocess` return codes or exceptions.
  - Use `shell=True` with unvalidated user input.
  - Let exceptions propagate unhandled to the user.
  - Catch generic `Exception` without logging details or handling specific errors first.

### 4.2.3. Dependency Management

- **Goal**: Ensure reproducible environments and clearly define project dependencies.
- **Tooling**:
  - Use `pyproject.toml` as the central configuration file.
  - Manage dependencies and virtual environments using `uv` or `Poetry`.
- **Specification**:
  - Define direct runtime dependencies under `[project.dependencies]` in `pyproject.toml`. Pin versions loosely (e.g., `click>=8.0,<9.0`) or using compatible release specifiers (`~=`, `^` depending on tool).
  - Define development/testing dependencies (e.g., `pytest`, `flake8`, `black`, `mypy`) under `[project.optional-dependencies]` (e.g., `[project.optional-dependencies.dev]`).
  - Generate and commit a lock file (`uv.lock`, `poetry.lock`) to ensure reproducible installs across different environments.
- **Do**:
  - Use `uv add <package>` or `poetry add <package>` (and `--group dev` for development dependencies).
  - Commit `pyproject.toml` and the generated lock file.
  - Keep dependencies minimal for the core package.
- **Don't**:
  - Manually edit `requirements.txt` without a tool or lock file for applications.
  - Commit virtual environment folders (e.g., `.venv/`).
  - Mix runtime and development dependencies without clear separation in `pyproject.toml`.

### 4.2.4. Docstrings and Commenting

- **Goal**: Document code effectively for understanding, maintainability, and potential auto-documentation generation.
- **Docstrings (PEP 257)**:
  - Use triple double quotes (`"""Docstring."""`).
  - Write a concise one-line summary for simple functions/methods/classes.
  - For multi-line docstrings: summary line, blank line, detailed explanation.
  - Document parameters (`Args:`), return values (`Returns:`), and raised exceptions (`Raises:`) using a consistent style (e.g., Google, NumPy). Be explicit about types.
  - Document modules (at top of file), classes (immediately after `class` line), functions, and methods (immediately after `def` line).
- **Comments (`#`)**:
  - Use inline comments sparingly to clarify complex or non-obvious logic.
  - Keep comments concise and up-to-date with the code.
  - Avoid comments that merely restate the code.
- **Do**:

  ```python
  """
  Module for handling application configuration.

  Loads configuration from standard locations and provides access
  to settings.
  """

  class AppConfig:
      """Represents the application configuration."""

      def __init__(self, config_path: str = None):
          """
          Initializes the configuration object.

          Args:
              config_path: Optional path to a specific config file.
                         If None, uses default locations.
          """
          self.config_path = config_path
          self._load_config() # Load configuration details

      def _load_config(self):
          """Loads configuration from file or defaults."""
          # Complex logic here might warrant an inline comment
          pass

      def get_setting(self, key: str) -> str | None:
          """
          Retrieves a configuration setting.

          Args:
              key: The configuration key to retrieve.

          Returns:
              The value of the setting, or None if not found.
          """
          # Implementation...
          pass
  ```

- **Don't**:
  - Write trivial docstrings (`"""Does stuff"""`).
  - Leave out parameter/return documentation.
  - Write comments explaining obvious code (`x = x + 1 # Add one to x`).
  - Let comments or docstrings become outdated.

### 4.2.5. PEP 8 Adherence

- **Goal**: Ensure code follows the standard Python style guide for readability and consistency.
- **Key Guidelines**:
  - **Indentation**: 4 spaces.
  - **Line Length**: Aim for 79-100 characters (tools like `black` often default to 88).
  - **Imports**: Separate imports (`import os`, `import sys`). Group standard library, third-party, and local imports.
  - **Whitespace**: Use appropriately around operators and commas, but avoid extraneous whitespace.
  - **Naming**: `lowercase_with_underscores` for variables/functions/modules, `CapWords` for classes, `CONSTANT_CASE` for constants.
  - **Comparisons**: Use `is` / `is not` for singletons like `None`. Use `is not None` instead of `not ... is None`.
- **Tooling**:
  - Use linters (`flake8`, `pylint`) and auto-formatters (`black`, `isort`) integrated into the development workflow (e.g., pre-commit hooks) to automatically check and enforce PEP 8.
- **Do**:
  - Run `black .` and `isort .` before committing.
  - Configure linters in `pyproject.toml` or a dedicated config file.
  - Follow the naming conventions.
- **Don't**:
  - Mix tabs and spaces.
  - Write overly long lines.
  - Ignore linter warnings/errors.
  - Use inconsistent naming styles.

### 4.2.6. Basic Testing Strategies

- **Goal**: Verify application correctness, prevent regressions, and ensure reliability through automated tests.
- **Framework**: Use `pytest`.
- **Unit Tests**:
  - Test individual functions and methods in isolation.
  - Mock external dependencies like `subprocess.run`, file system operations, or network calls using `unittest.mock` or `pytest-mock`. Focus on testing the logic within the function/method.
  - Cover different code paths, edge cases, and expected error conditions.
- **CLI/Integration Tests**:
  - Use `Typer`'s/`Click`'s `CliRunner` to invoke CLI commands programmatically.
  - Assert the expected `stdout`, `stderr`, and `exit_code` for various command invocations, including valid and invalid inputs.
  - Test interactions between different parts of the application (e.g., command parsing triggers correct core logic).
- **Structure**:
  - Organize tests in a `tests/` directory, mirroring the application structure where appropriate.
  - Use descriptive test function names (e.g., `test_execute_command_success`, `test_cli_run_invalid_technique_id`).
- **Do**:

  - Write tests for all core logic.
  - Use `CliRunner` for testing the CLI layer.
  - Mock external calls in unit tests.
  - Parametrize tests (`@pytest.mark.parametrize`) to cover multiple scenarios efficiently.
  - Example using `pytest` and `CliRunner` (assuming Typer app in `src/purple_cli/cli.py`):

    ```python
    # Example using pytest and CliRunner (assuming Typer app in src/purple_cli/cli.py)
    from typer.testing import CliRunner
    from purple_cli.cli import app # Assuming 'app' is the typer.Typer() instance
    import pytest

    runner = CliRunner()

    def test_cli_version():
        """Test the --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "Purple CLI version:" in result.stdout # Check for version string

    def test_cli_run_command_success(mocker):
        """Test the 'run' command with mocked successful execution."""
        # Mock the core execution function to simulate success
        # Assuming the function to mock is 'run_atomic_test' in 'executor' module
        mock_executor = mocker.patch("purple_cli.core.executor.run_atomic_test", return_value=(True, "Success output"))
        # Example: Invoke run command with a specific technique ID
        result = runner.invoke(app, ["run", "T1234"])
        assert result.exit_code == 0
        assert "Executing test T1234..." in result.stdout # Adjust based on actual output
        assert "Success output" in result.stdout
        mock_executor.assert_called_once_with("T1234") # Verify mock was called correctly

    def test_cli_run_command_failure(mocker):
        """Test the 'run' command with mocked failed execution."""
        mock_executor = mocker.patch("purple_cli.core.executor.run_atomic_test", return_value=(False, "Error executing"))
        # Example: Invoke run command with another technique ID
        result = runner.invoke(app, ["run", "T5678"])
        assert result.exit_code != 0 # Expect non-zero exit code on failure
        assert "Executing test T5678..." in result.stdout # Adjust based on actual output
        assert "Error executing" in result.stdout # Or check stderr if printed there
        mock_executor.assert_called_once_with("T5678")

    def test_cli_run_invalid_id():
         """Test 'run' command with an invalid technique ID format (if validation exists)."""
         result = runner.invoke(app, ["run", "InvalidID"])
         assert result.exit_code != 0
         assert "Invalid Technique ID format" in result.stdout # Check for specific error message
    ```

- **Don't**:
  - Rely solely on manual testing.
  - Write tests that depend on specific external environments without mocking.
  - Make tests overly complex or brittle by testing private implementation details.
  - Ignore failing tests.

## 4.3. Programming Paradigm Recommendation (OOP vs. Functional)

Choosing between Object-Oriented Programming (OOP) and Functional Programming (FP) paradigms, or a blend of both, impacts structure, state management, maintainability, and testability.

### 4.3.1. State Handling

- **Key State**: The CLI tool needs to manage application configuration (e.g., path to atomics, API keys, logging settings) and potentially runtime state (e.g., results of executed tests, current session info).
- **OOP Approach**:
  - Encapsulates state within objects. A `Config` object could hold settings, loaded from a file or environment variables. A `TestRunner` object might manage the execution process and store results in a list of `TestResult` objects.
  - State is mutable within these objects.
  - Aligns well with modeling distinct entities like "configuration" or "a test run".
- **FP Approach**:
  - Emphasizes immutability. Configuration would be loaded into immutable structures (like tuples, frozen dataclasses, or immutable dicts).
  - Functions performing actions (like running a test) would take the configuration and test details as input and return a new state or result, rather than modifying existing structures.
  - Managing accumulated results might involve techniques like recursion or building new lists/collections in each step.
- **Consideration**: The tool inherently involves managing configuration and accumulating results, which involves state. While FP promotes statelessness where possible, managing application-level configuration and aggregating results over time often fits more naturally with OOP's encapsulation model, where objects hold and manage their own state.

### 4.3.2. Complexity Management

- **OOP Approach**:
  - Manages complexity by grouping related data and behavior into classes. This modularity helps organize the codebase as features (new commands, reporting formats, execution options) are added.
  - Inheritance and polymorphism offer ways to handle variations, though overuse can increase complexity.
- **FP Approach**:
  - Manages complexity by decomposing problems into small, pure, composable functions. The lack of side effects makes functions easier to reason about independently.
  - Complexity can arise in managing state flow between functions if not carefully designed.
- **Consideration**: Both paradigms offer tools for complexity management. For a CLI tool, OOP provides a natural way to structure the different commands and their associated logic (e.g., a class per command group). FP principles are highly valuable for the core processing logic – parsing test files, formatting output, executing the external process – ensuring these parts are predictable and isolated.

### 4.3.3. Maintainability and Testability

- **OOP Approach**:
  - Encapsulation can aid maintainability by hiding implementation details.
  - Mutable state and dependencies between objects can make testing more complex, requiring careful setup and teardown of object states.
  - Refactoring can sometimes be challenging due to tangled object relationships.
- **FP Approach**:
  - Pure functions are inherently testable due to their deterministic nature (same input yields same output) and lack of side effects.
  - Immutability prevents bugs caused by unintended state changes, enhancing maintainability.
  - Code composed of small, pure functions is often easier to reason about and refactor.
- **Consideration**: Functional programming generally offers significant advantages in testability and maintainability for the parts of the code where it can be applied effectively, primarily due to purity and immutability.

### 4.3.4. Justified Recommendation: Hybrid Approach

A **Hybrid Approach** is recommended for the Purple Team CLI tool.

- **Justification**: This approach leverages the strengths of both paradigms where they fit best within the application's architecture. Python is a multi-paradigm language well-suited for this.

- **Use OOP for**:

  - **Overall Structure**: Defining the main application structure, CLI command groups (especially if using `Click`/`Typer` programmatically), and potentially managing long-lived state like application configuration (`AppConfig` class) or encapsulating external service interactions. This provides clear organization and encapsulation for distinct components.
  - **State Management**: Managing application configuration and potentially aggregating test results over a session where mutable state is convenient.

- **Use FP Principles for**:

  - **Core Logic**: Implementing functions for parsing test definitions (YAML/Markdown), processing/transforming data (test results), formatting output, and potentially the core test execution orchestration logic. Aim for pure functions where possible (functions whose output depends only on input, with no side effects).
  - **Data Structures**: Use immutable data structures (tuples, `frozenset`, potentially libraries like `attrs` with `frozen=True`, or simple data classes) for passing data between functions where appropriate, especially for test results or parsed test data.
  - **Testability/Maintainability**: Prioritize FP for components requiring high reliability and easy testing, as pure functions simplify unit testing significantly.

- **Conclusion**: This hybrid strategy combines the organizational benefits of OOP for the application's structure and stateful components with the robustness, testability, and predictability of FP for data processing and core logic execution.
