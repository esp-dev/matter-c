"""Create/verify the pinned standalone mbedTLS checkout. No ESP-IDF required."""
import argparse
import json
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[2]
    dependency = json.loads((root / 'cmake/dependencies.json').read_bytes())['mbedtls']
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', default=dependency['url'], help='Upstream URL or local offline Git checkout')
    parser.add_argument('--destination', type=Path, default=root / 'third_party/mbedtls')
    args = parser.parse_args()
    destination = args.destination.resolve()
    def git(*command):
        return subprocess.check_output(['git', '-C', str(destination), *command], text=True).strip()
    if not destination.exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git', '-c', 'core.autocrlf=false', 'clone', '--no-hardlinks', '--no-checkout',
                        args.source, str(destination)], check=True)
        git('config', 'core.autocrlf', 'false')
        git('checkout', '--detach', dependency['revision'])
        # A local source is an offline seed, never a continuing dependency.
        git('remote', 'set-url', 'origin', dependency['url'])
    if git('rev-parse', '--show-toplevel').replace('\\', '/') != destination.as_posix():
        raise ValueError('Expected a standalone dependency checkout')
    if git('rev-parse', 'HEAD') != dependency['revision']:
        raise ValueError('Unexpected mbedTLS revision (existing checkout is not modified)')
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Modified or untracked dependency files')
    if (destination / '.git/objects/info/alternates').exists():
        raise ValueError('Dependency objects must not depend on another checkout')
    print('Verified standalone mbedTLS:', dependency['revision'], destination)


if __name__ == '__main__':
    main()
