# integrations/tool_runner.py
import subprocess
import shutil
import logging

logger = logging.getLogger(__name__)

def is_tool_installed(name):
    return shutil.which(name) is not None

def run_command(command: list) -> str | None:
    tool_name = command[0]
    if not is_tool_installed(tool_name):
        logger.warning(f"Tool '{tool_name}' is not installed or not in PATH. Skipping.")
        return None
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode != 0:
            logger.error(f"Error running '{tool_name}': {result.stderr}")
            return None
        return result.stdout
    except FileNotFoundError:
        logger.error(f"Command '{tool_name}' not found.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred with '{tool_name}': {e}")
        return None
