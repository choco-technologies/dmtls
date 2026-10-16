#!/usr/bin/env python3
"""Prove the audit accepts GOT pointers and rejects mixed static aggregates."""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('audit',ROOT/'scripts/check_dmod_pointers.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class PointerAudit(unittest.TestCase):
    def fixture(self,bad=False,metadata=True):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source='''
#include <stdint.h>
__attribute__((section(".header"),used)) const uint32_t header[60]={0x444d4f44,240,256,8};
static void callback(void) {__asm__ volatile("nop");}
static void (*const volatile pointer)(void) __attribute__((section(".got")))=callback;
void entry(void) {pointer();}
'''
            if bad:source+='struct mixed {int value;void (*callback)(void);}; const struct mixed bad={7,callback};\n'
            (root/'source.c').write_text(source)
            (root/'layout.ld').write_text('SECTIONS { . = 0; .header : {KEEP(*(.header))} .text : {*(.text*)} .data : {*(.data*)} .got : {*(.got*)} /DISCARD/ : {*(.note*) *(.eh_frame*)} }')
            command=['gcc','-fPIC','-fPIE','-O2','-nostdlib','-static','-Wl,--no-relax',
                     '-T',str(root/'layout.ld'),str(root/'source.c'),'-o',str(root/'module')]
            if metadata:command.insert(1,'-Wl,--emit-relocs')
            subprocess.run(command,check=True,capture_output=True)
            subprocess.run(['objcopy','-O','binary',str(root/'module'),str(root/'module.dmf')],check=True)
            return (root/'module').read_bytes(),(root/'module.dmf').read_bytes()

    def test_existing_got_format_is_accepted(self):
        elf,dmf=self.fixture();self.assertEqual(audit.check(elf,dmf),1)
        self.assertEqual(struct.unpack_from('<I',dmf,4)[0],240)

    def test_pointer_in_mixed_structure_is_rejected(self):
        elf,dmf=self.fixture(bad=True)
        with self.assertRaisesRegex(ValueError,'outside legacy'):audit.check(elf,dmf)

    def test_missing_relocation_metadata_is_rejected(self):
        elf,dmf=self.fixture(metadata=False)
        with self.assertRaisesRegex(ValueError,'missing ELF'):audit.check(elf,dmf)

if __name__=='__main__':unittest.main()
