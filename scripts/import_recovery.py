"""One-time, allowlisted extraction of Sigma and its transitive shared runtime.

The source tree is read-only. No sibling checkout is required at runtime.
"""
import ast
import hashlib
import json
import shutil
from pathlib import Path


def extract(source: Path, destination: Path):
    engine = Path('packages/omnikit-migration-engine')
    base = source / engine / 'src'
    modules = {}
    for path in base.rglob('*.py'):
        name = '.'.join(path.relative_to(base).with_suffix('').parts)
        modules[name.removesuffix('.__init__')] = path
    pending = [n for n in modules if n.startswith('omni_migrator.extractors.sigma')]
    pending += ['omni_migrator.bridge', 'omni_migrator.orchestration.sigma_cli']
    selected = set()
    while pending:
        name = pending.pop()
        if name == 'omni_migrator.core.registry' or name in selected or name not in modules:
            continue
        selected.add(name)
        parent = name.rpartition('.')[0]
        if parent:
            pending.append(parent)
        if name == 'omni_migrator.extractors.domo':
            continue  # Only shared models are retained, not the acquisition implementation.
        for node in ast.walk(ast.parse(modules[name].read_text())):
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('omni_migrator'):
                pending.append(node.module)
                pending.extend(node.module + '.' + alias.name for alias in node.names)
            elif isinstance(node, ast.Import):
                pending.extend(alias.name for alias in node.names if alias.name.startswith('omni_migrator'))
    files = {modules[n].relative_to(source) for n in selected}
    for name in ['LICENSE', 'PROVENANCE.json']:
        files.add(engine / name)
    for pattern in ['contracts/*.schema.json', 'contracts/sigma/**/*.json',
                    'agents/sigma/**/*', 'docs/*sigma*.md',
                    str(engine / 'tests/test_sigma*.py'),
                    str(engine / 'contracts/*.json'),
                    str(engine / 'src/omni_migrator/rulebook/v2/sigma/*.md'),
                    str(engine / 'src/omni_migrator/rulebook/v2/common/*.md')]:
        files.update(p.relative_to(source) for p in source.glob(pattern) if p.is_file())
    records = []
    for relative in sorted(files):
        path = source / relative
        if path.is_symlink():
            raise ValueError('symlink in import')
        target = destination / relative
        if target.exists():
            raise ValueError(f'refusing to overwrite {relative}')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        records.append({'path': relative.as_posix(), 'source_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'ownership': 'Sigma adapter' if '/sigma' in relative.as_posix() else 'selected shared dependency'})
    (destination / 'IMPORT-MANIFEST.json').write_text(json.dumps({
        'source_baseline': '912e56d80431b50738397605d346ff5bf6c1b1be',
        'recovery_archive_sha256': 'e0cfcabe9412bfb11f3e786fee0cc023bfb3d5b6bbea3d030b20ae568431ae66',
        'shared_code_origin': 'atx-omni/DomoMigrationAgent and exploreomni/omni-migrator; see retained PROVENANCE.json',
        'import_is_not_release_acceptance': True, 'files': records}, indent=2) + '\n')
    print(f'Imported {len(files)} selected files; {len(selected)} runtime modules')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    extract(args.source, args.destination)
