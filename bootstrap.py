#!/usr/bin/env python3
"""
PhantomLite Auto-Setup Bootstrap
Handles virtual environment creation and dependency installation automatically.
"""
import sys
import os
import subprocess
import venv
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.resolve()
VENV_PATH = PROJECT_ROOT / "venv"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"
MAIN_SCRIPT = PROJECT_ROOT / "cli.py"


class Bootstrap:
    def __init__(self):
        self.python_path = sys.executable
        self.platform = sys.platform
    
    def check_venv_exists(self) -> bool:
        return VENV_PATH.exists() and (VENV_PATH / "Scripts" / "python.exe").exists() or (VENV_PATH / "bin" / "python").exists()
    
    def get_venv_python(self) -> Path:
        if self.platform == "win32":
            return VENV_PATH / "Scripts" / "python.exe"
        return VENV_PATH / "bin" / "python"
    
    def create_venv(self) -> bool:
        try:
            logger.info("[+] Creating virtual environment...")
            venv.create(VENV_PATH, with_pip=True, clear=False)
            
            if self.platform != "win32":
                pip_path = VENV_PATH / "bin" / "pip"
            else:
                pip_path = VENV_PATH / "Scripts" / "pip.exe"
            
            logger.info("[+] Installing dependencies...")
            subprocess.run(
                [str(pip_path), "install", "-r", str(REQUIREMENTS_FILE)],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("[+] Dependencies installed successfully!")
            return True
        except Exception as e:
            logger.error(f"[-] Failed to create virtual environment: {e}")
            return False
    
    def ensure_dependencies(self) -> bool:
        if not REQUIREMENTS_FILE.exists():
            logger.error("[-] requirements.txt not found!")
            return False
        
        try:
            result = subprocess.run(
                [self.python_path, "-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("[+] Dependencies verified!")
                return True
            else:
                logger.warning("[-] Some dependencies failed. Creating venv...")
                return self.create_venv()
        except Exception:
            return self.create_venv()
    
    def run_with_venv(self):
        if not self.check_venv_exists():
            logger.info("[*] First run detected. Setting up environment...")
            if not self.create_venv():
                logger.error("[-] Auto-setup failed. Please ensure pip is available.")
                sys.exit(1)
        
        venv_python = self.get_venv_python()
        
        if not venv_python.exists():
            logger.warning("[*] Virtual environment corrupted. Recreating...")
            if not self.create_venv():
                sys.exit(1)
            venv_python = self.get_venv_python()
        
        os.chdir(PROJECT_ROOT)
        result = subprocess.run([str(venv_python), "main.py"] + sys.argv[1:])
        sys.exit(result.returncode)


def main():
    bootstrap = Bootstrap()
    
    if "--no-auto-setup" in sys.argv:
        sys.argv.remove("--no-auto-setup")
        if not bootstrap.ensure_dependencies():
            sys.exit(1)
        return
    
    if not bootstrap.check_venv_exists():
        logger.info("[*] First run detected. Setting up environment...")
        if not bootstrap.create_venv():
            logger.error("[-] Auto-setup failed. Please ensure pip is available.")
            sys.exit(1)
    
    venv_python = bootstrap.get_venv_python()
    
    if not venv_python.exists():
        logger.warning("[*] Virtual environment corrupted. Recreating...")
        if not bootstrap.create_venv():
            sys.exit(1)
        venv_python = bootstrap.get_venv_python()
    
    os.chdir(PROJECT_ROOT)
    result = subprocess.run([str(venv_python), str(MAIN_SCRIPT)] + sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
