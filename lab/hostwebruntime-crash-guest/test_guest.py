"""Offline parser/admission tests. Import never prepares or launches a guest."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('crash_guest_under_test',Path(__file__).with_name('crash_guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)

class AdmissionTests(unittest.TestCase):
    def value(self):
        a = dict(schema_version=2,kind='trusted-disposable-alma9-controller-crash',nonce='a'*24,zero_external_nics=True)
        for k in ['prepared_image','fixture','library','helper','source_catalog','package_report','driver','test']:
            a[k+'_sha256'] = 'b'*64
        a['library_sha256'] = guest.LIBRARY_SHA
        a['helper_sha256'] = guest.HELPER_SHA
        return a

    def test_exact_current_admission(self):
        self.assertEqual(guest.admission(self.value()),self.value())

    def test_reference_library_and_helper_bound(self):
        for key in ['library_sha256','helper_sha256']:
            with self.subTest(key=key):
                a=self.value();a[key]='c'*64
                with self.assertRaises(guest.Failure):guest.admission(a)

    def test_old_schema_and_aliases_refused(self):
        for key,value in [('schema_version',1),('schema_version',True),('schema_version',2.0),('kind','trusted-disposable-alma9-runtime-serving'),('nonce','a'*32),('zero_external_nics',1),('driver_sha256','c'*63)]:
            with self.subTest(key=key,value=value):
                a=self.value();a[key]=value
                with self.assertRaises(guest.Failure):guest.admission(a)
        a=self.value();a['Kind']=a.pop('kind')
        with self.assertRaises(guest.Failure):guest.admission(a)
        a=self.value();a['unapproved']='value'
        with self.assertRaises(guest.Failure):guest.admission(a)

    def test_json_duplicates_trailing_nonfinite_and_bounds(self):
        for raw in [b'{"a":1,"a":2}',b'{"a":{"b":1,"b":2}}',b'{"a":NaN}',b'{"a":Infinity}',b'{}{}',b'{',b'\xff',b'']:
            with self.subTest(raw=raw):
                with self.assertRaises(guest.Failure):guest.strict_json(raw)
        with self.assertRaises(guest.Failure):guest.strict_json(b'{"a":1}',6)
        self.assertEqual(guest.strict_json(b'{"a":[1,true]}'),{'a':[1,True]})

    def test_framing_identity_is_separate_from_driver_nonce(self):
        self.assertEqual(len(guest.run_id('a'*24)),32)
        self.assertNotEqual(guest.run_id('a'*24),guest.run_id('b'*24))
        self.assertNotEqual(guest.run_id('a'*24),guest.digest(('sifruno-serving:'+'a'*24).encode())[:32])

if __name__=='__main__':
    unittest.main()
