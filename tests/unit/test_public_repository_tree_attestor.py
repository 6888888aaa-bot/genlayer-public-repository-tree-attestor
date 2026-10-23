from pathlib import Path

def test_tree_attestor_shape():
    text = (Path(__file__).parents[2] / 'contracts/public_repository_tree_attestor.py').read_text(encoding='utf-8')
    assert 'expected_paths' in text and 'tree_digest' in text
    assert 'gl.nondet.web.get' in text
    assert 'gl.nondet.exec_prompt' in text
    assert 'gl.vm.run_nondet_unsafe' in text
