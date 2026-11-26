#!/usr/bin/env python3
"""Build a draft cloud image from this rebuild's verified BIN, never a disk device."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--workdir',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--hy2-core-archive',type=Path,required=True,help='Pinned offline HY2 core from the same release');a=p.parse_args()
W=a.workdir.resolve();O=W/'port-3726/output';v=json.loads((O/'verification.json').read_text())
destination=a.output.resolve()
assert destination!=ROOT and ROOT not in destination.parents,'Keep generated images outside the checkout'
assert not destination.exists(),'Output directory already exists; choose a new one'
firmware=O/v['output_filename'];assert hashlib.sha256(firmware.read_bytes()).hexdigest()==v['output_sha256']
assert v['roundtrip_decryption'] and v['final_container_checks'] and v['kernel_verified_through_rootfs_unpack_call']
spec=importlib.util.spec_from_file_location('cloud_builder',ROOT/'materials/cloud/build_cloud_image.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
mod.SHA=v['output_sha256'];mod.NAME=firmware.stem+'_EFI_eth0-WAN-Web.img'
sys.argv=['cloud_builder','--firmware',str(firmware),'--template',str(W/'inputs/efi-boot-template.img.gz'),
          '--tools',str(W/'toolbuild/e2fsprogs-1.47.3'),'--output',str(a.output.resolve()),'--hy2-core-archive',str(a.hy2_core_archive.resolve())]
mod.main()
print('Draft image only. Test BIOS/UEFI and initialization on copies before publishing.')
