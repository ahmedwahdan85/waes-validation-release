"""Build the benchmark ELF for each Cortex-A53 core against the Vitis BSPs.
Each core gets its own DDR region; 0x7FE00000 (2 MB) is shared, non-cacheable."""
import os
import subprocess
import sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
gcc = r'C:\AMDDesignTools\2025.2\Vitis\gnu\aarch64\nt\aarch64-none\bin\aarch64-none-elf-gcc.exe'
sw = os.path.join(root, 'ws', 'ps_plat', 'export', 'ps_plat', 'sw')
tmpl = open(os.path.join(root, 'ws', 'ps_plat', 'zynqmp_fsbl', 'linker_files', 'lscript_a53.ld.in')).read()
out = os.path.join(root, 'build')
os.makedirs(out, exist_ok=True)

NBLK = int(sys.argv[1]) if len(sys.argv) > 1 else 8
REGIONS = [(0x00100000, 0x0FF00000), (0x10000000, 0x10000000),
           (0x20000000, 0x10000000), (0x30000000, 0x10000000)]

for core, (org, length) in enumerate(REGIONS):
    bsp = os.path.join(sw, f'sa_a53_{core}')
    ld = (tmpl.replace('@STACK_SIZE@', '0x20000').replace('@HEAP_SIZE@', '0x20000')
          .replace('@MEMORY_SECTION@',
                   f'MEMORY\n{{\n   ddr_core{core} : ORIGIN = 0x{org:08X}, LENGTH = 0x{length:08X}\n}}')
          .replace('@CODE@', f'ddr_core{core}').replace('@DATA@', f'ddr_core{core}'))
    ldf = os.path.join(out, f'lscript_core{core}.ld')
    open(ldf, 'w').write(ld)
    elf = os.path.join(out, f'waes_bench_core{core}.elf')
    cmd = [gcc, '-O3', '-mcpu=cortex-a53+crypto', '-DSDT', '-Wall', f'-DNBLK={NBLK}',
           f'-specs={os.path.join(bsp, "Xilinx.spec")}', f'-I{os.path.join(bsp, "include")}',
           os.path.join(root, 'src', 'main.c'), os.path.join(root, 'src', 'waes_a53.c'),
           f'-L{os.path.join(bsp, "lib")}', f'-Wl,-T,{ldf}', '-Wl,--gc-sections',
           '-Wl,--start-group', '-lxil', '-lxilstandalone', '-lxiltimer', '-lgcc', '-lc',
           '-Wl,--end-group', '-o', elf]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        print(r.stdout, r.stderr)
        sys.exit(f'core {core}: build failed')
    if r.stderr.strip():
        print(r.stderr.strip())
    print(f'core {core}: {elf}')
