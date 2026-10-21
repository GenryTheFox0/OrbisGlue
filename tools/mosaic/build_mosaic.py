"""Builds the lifted C of a title into its mosaic DLL.

    python tools/mosaic/build_mosaic.py <lifted dir> <out.dll> [--jobs 6]

Needs LLVM (clang-cl, lld-link) and the Visual Studio Build Tools (C++ workload), found on their
own; MOSAIC_LLVM / MOSAIC_VCVARS point elsewhere. At most 6 compilers at once by default: the
lifted C is large and some PCs do not take more.
"""
import argparse
import concurrent.futures
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def find_llvm():
    if os.environ.get('MOSAIC_LLVM'):
        return os.environ['MOSAIC_LLVM']
    for d in (r'C:\Program Files\LLVM\bin', r'C:\Program Files (x86)\LLVM\bin'):
        if os.path.exists(os.path.join(d, 'clang-cl.exe')):
            return d
    sys.exit('LLVM not found: install it (https://github.com/llvm/llvm-project/releases) or set MOSAIC_LLVM')


def find_vcvars():
    if os.environ.get('MOSAIC_VCVARS'):
        return os.environ['MOSAIC_VCVARS']
    vswhere = os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'),
                           r'Microsoft Visual Studio\Installer\vswhere.exe')
    if os.path.exists(vswhere):
        out = subprocess.run([vswhere, '-latest', '-products', '*', '-property', 'installationPath'],
                             capture_output=True, text=True).stdout.strip()
        cand = os.path.join(out, r'VC\Auxiliary\Build\vcvars64.bat') if out else ''
        if cand and os.path.exists(cand):
            return cand
    sys.exit('Visual Studio Build Tools (C++) not found: install them or set MOSAIC_VCVARS')


def msvc_env():
    # bytes, decoded here: under some parents the text-mode capture came back as None
    r = subprocess.run(f'"{find_vcvars()}" >nul && set', shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, check=True)
    out = (r.stdout or b'').decode('mbcs', errors='replace')
    env = dict(line.split('=', 1) for line in out.splitlines() if '=' in line)
    if 'INCLUDE' not in env:
        sys.exit('vcvars64 gave no environment')
    env['PATH'] = find_llvm() + ';' + env.get('PATH', '')
    return env


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('src')
    ap.add_argument('out')
    ap.add_argument('--jobs', type=int, default=6)
    ap.add_argument('--opt', default='/O1')
    ap.add_argument('--link-only', action='store_true', help='objects are up to date: link them')
    a = ap.parse_args()
    env = msvc_env()
    obj = os.path.join(a.src, 'obj')
    os.makedirs(obj, exist_ok=True)
    sources = sorted(f for f in os.listdir(a.src) if f.endswith('.c'))

    def compile_one(name):
        o = os.path.join(obj, name[:-2] + '.obj')
        cmd = [os.path.join(find_llvm(), 'clang-cl.exe'), '/nologo', '/c', a.opt, '/MD', '/GS-', '-Wno-everything', '-mavx2',
               '/I', HERE, '/Fo' + o, os.path.join(a.src, name)]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        return name, r.returncode, (r.stdout + r.stderr)[-3000:]

    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, a.jobs)) as pool:
        for name, rc, log in pool.map(compile_one, [] if a.link_only else sources):
            print(f'{"ok " if rc == 0 else "ERR"} {name}')
            if rc:
                failed += 1
                print(log)
    if failed:
        sys.exit(1)
    objs = [os.path.join(obj, f) for f in sorted(os.listdir(obj)) if f.endswith('.obj')]
    cmd = [os.path.join(find_llvm(), 'lld-link.exe'), '/nologo', '/DLL', '/OUT:' + a.out,
           '/MAP:' + a.out[:-4] + '.map'] + objs + \
          ['msvcrt.lib', 'vcruntime.lib', 'ucrt.lib', 'kernel32.lib']
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    print(r.stdout + r.stderr)
    if r.returncode:
        sys.exit(2)
    print('MOSAIC DLL OK', a.out, os.path.getsize(a.out))


if __name__ == '__main__':
    main()
