# Vitis platform: one standalone domain per Cortex-A53 core.
# Usage: vitis -s scripts/make_platform.py
import os
import shutil
import vitis

root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ws = os.path.join(root, 'ws')
xsa = os.path.join(root, 'hw', 'ps_only.xsa')
shutil.rmtree(ws, ignore_errors=True)

client = vitis.create_client()
client.set_workspace(path=ws)
plat = client.create_platform_component(name='ps_plat', hw_design=xsa, os='standalone',
                                        cpu='psu_cortexa53_0', domain_name='sa_a53_0')
plat = client.get_component(name='ps_plat')
for i in range(1, 4):
    plat.add_domain(cpu=f'psu_cortexa53_{i}', os='standalone', name=f'sa_a53_{i}',
                    display_name=f'sa_a53_{i}')
plat.build()
print('PLATFORM BUILT')
vitis.dispose()
