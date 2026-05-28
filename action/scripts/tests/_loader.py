"""Load hyphenated pipeline scripts as importable modules for tests."""
import importlib.util
import pathlib

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]


def load(filename):
    """Import a script from action/scripts/ by filename (handles hyphens)."""
    path = SCRIPTS / filename
    mod_name = filename.replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
