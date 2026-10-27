"""Independent ordered catalog expectations: extra captures cannot disappear in restore."""
import copy
import unittest
import test_catalog as catalog
bundle=catalog.bundle


class MultiCaptureBackupTests(unittest.TestCase):
    setUp=catalog.CatalogBackupTests.setUp
    add_preflight=catalog.CatalogBackupTests.add_preflight
    def multi(self):
        first=self.catalog['v3_source_files'][0]
        extra=copy.deepcopy(first);extra['id']='network-two';extra['storage_path']='inputs/catalog/d1/second.pcap'
        path=self.root/extra['storage_path'];path.write_bytes((self.root/first['storage_path']).read_bytes()+b'\x00')
        extra.update(sha256=bundle.sha(path),size_bytes=path.stat().st_size)
        self.catalog['v3_source_files'].append(extra)
        self.catalog['v3_dataset_files'].append({'id':'network-two-link','dataset_id':'d1','source_file_id':extra['id'],
            'role':'network','filename':'second.pcap','created_by':'u1','created_at':'2026-10-27T00:00:00Z'})
        self.catalog['v3_run_bindings'][0]['network_file_ids']=['network-link','network-two-link']
        self.job['payload']['networks']=[self.job['payload']['network'],{'path':extra['storage_path'],'sha256':extra['sha256']}]
        self.catalog['v3_config_versions']=[c for c in self.catalog['v3_config_versions'] if c['id']!='intakecfg']
        self.add_preflight()

    def audit(self):
        return bundle.audit_catalog(self.catalog,[self.job],self.root)

    def test_all_capture_bindings_validated(self):
        self.multi();self.assertTrue(self.audit()['valid'],self.audit())
        self.job['payload']['networks'].reverse();self.assertFalse(self.audit()['valid'])

    def test_missing_capture_binding_not_silently_ignored(self):
        self.multi();self.catalog['v3_run_bindings'][0]['network_file_ids']=None
        self.assertFalse(self.audit()['valid'])

    def test_extra_original_tamper_rejected(self):
        self.multi();ref=self.job['payload']['networks'][1];(self.root/ref['path']).write_bytes(b'changed')
        self.assertFalse(self.audit()['valid'])

    def test_duplicate_ordered_capture_rejected(self):
        self.multi();self.job['payload']['networks']=[self.job['payload']['network']]*2
        self.assertFalse(self.audit()['valid'])
