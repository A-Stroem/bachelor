import subprocess
import sys

# Define the PowerShell command to execute
# This is the command that works when run directly in PowerShell
powershell_command = ["powershell", "-Command", "Invoke-AtomicTest T1218.010 -TestNumbers 3"]

print(f"Attempting to execute PowerShell command: {' '.join(powershell_command)}")

try:
    # Execute the command using subprocess.run
    # setting capture_output=False allows interactive programs to display
    # check=True will raise a CalledProcessError if the command returns a non-zero exit code
    result = subprocess.run(
        powershell_command,
        check=True,
        capture_output=False, # Set to False to allow GUI applications to display
        text=True, # Decode stdout and stderr as text
        timeout=60 # Add a timeout in seconds to prevent hanging
    )

    # If check=True and no exception was raised, the command was successful
    print("\nPowerShell command executed successfully.")
    print(f"Return code: {result.returncode}")
    # Note: With capture_output=False, stdout/stderr will be None or empty
    # The output from Invoke-AtomicTest might still print directly to the console

except FileNotFoundError:
    print(f"\nError: PowerShell executable not found.", file=sys.stderr)
    print("Please ensure 'powershell' is in your system's PATH or provide the full path.", file=sys.stderr)

except subprocess.CalledProcessError as e:
    print(f"\nError: PowerShell command failed with exit code {e.returncode}", file=sys.stderr)
    print(f"Stderr: {e.stderr}", file=sys.stderr)
    print(f"Stdout: {e.stdout}", file=sys.stderr)

except subprocess.TimeoutExpired:
    print(f"\nError: PowerShell command timed out.", file=sys.stderr)

except Exception as e:
    print(f"\nAn unexpected error occurred: {e}", file=sys.stderr)

print("\nScript finished.")
