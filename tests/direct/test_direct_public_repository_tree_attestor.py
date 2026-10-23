from pathlib import Path

def test_package_shape():
    root = Path(__file__).parents[2]
    assert (root / 'contracts/public_repository_tree_attestor.py').is_file()
    assert (root / 'README.md').is_file()
