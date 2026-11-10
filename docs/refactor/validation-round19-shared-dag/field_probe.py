"""Read-only bounded top-level JSON scan of retained synthetic S100 artifacts."""
import hashlib
import json
from pathlib import Path
import resource
import sys
import time

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'services/analysis/src'))
from cpag_core.pipeline import canonical,file_hash


class Cursor:
    def __init__(self,path):self.stream=Path(path).open(encoding='utf-8');self.buffer='';self.pos=0;self.eof=False;self.decoder=json.JSONDecoder();self.peak=0
    def more(self):
        self.buffer=self.buffer[self.pos:];self.pos=0
        text=self.stream.read(65536);self.eof=not text;self.buffer+=text;self.peak=max(self.peak,len(self.buffer))
    def char(self):
        while True:
            while self.pos<len(self.buffer) and self.buffer[self.pos].isspace():self.pos+=1
            if self.pos<len(self.buffer):return self.buffer[self.pos]
            if self.eof:raise ValueError('unexpected_eof')
            self.more()
    def expect(self,value):
        if self.char()!=value:raise ValueError('unexpected_json_delimiter')
        self.pos+=1
    def value(self):
        self.char()
        while True:
            try:
                value,end=self.decoder.raw_decode(self.buffer,self.pos)
                if end<len(self.buffer) or self.eof:self.pos=end;return value
            except json.JSONDecodeError:
                if self.eof:raise
            self.more()
    def rows(self):
        self.expect('{')
        while self.char()!='}':
            key=self.value();self.expect(':')
            if self.char()=='[':
                self.expect('[')
                while self.char()!=']':
                    yield key,self.value()
                    if self.char()==',':self.expect(',')
                    else:break
                self.expect(']')
            else:yield key,self.value()
            if self.char()==',':self.expect(',')
            else:break
        self.expect('}')


def main():
    root=Path(sys.argv[1]);path=root/'analysis.json';manifest=json.loads((root/'run_manifest.json').read_text())
    expected=next(row['sha256'] for row in manifest['artifacts'] if row['path']=='analysis.json')
    if file_hash(path)!=expected:raise ValueError('retained_analysis_changed')
    totals={};unique={};counts={};ref_count=ref_bytes=0;unique_refs={};candidate_count=0
    def field(name,value):
        raw=canonical(value);key=hashlib.sha256(raw).hexdigest();totals[name]=totals.get(name,0)+len(raw);counts[name]=counts.get(name,0)+1;unique.setdefault(name,{})[key]=len(raw)
    def refs(value):
        nonlocal ref_count,ref_bytes
        if isinstance(value,dict):
            if {'file_sha256','frame_number','record_number','column','raw_time'}<=set(value):
                raw=canonical(value);ref_count+=1;ref_bytes+=len(raw);unique_refs[hashlib.sha256(raw).hexdigest()]=len(raw)
            else:
                for child in value.values():refs(child)
        elif isinstance(value,list):
            for child in value:refs(child)
    cursor=Cursor(path);start=time.perf_counter();cpu=time.process_time()
    for key,row in cursor.rows():
        if key=='candidates':
            candidate_count+=1;field('candidate_full',row)
            for name in ('counterevidence','unknown_reasons','support'):field('candidate_'+name,row[name])
            for name in ('counterevidence','evidence_refs','assumptions'):field('claim_'+name,row['claim'][name])
            refs(row)
    cursor.stream.close()
    if file_hash(path)!=expected:raise ValueError('retained_analysis_changed_during_probe')
    report={'scope':'read-only retained S100 fields; not new analysis, M/L runtime, compression result or industrial acceptance',
            'artifact':str(root),'source_measurement_commit':'3e7340ea0e923820b21881dcb33740e0f2d0ec20',
            'analysis_sha256':expected,'analysis_bytes':path.stat().st_size,'candidate_count':candidate_count,
            'wall_seconds':time.perf_counter()-start,'cpu_seconds':time.process_time()-cpu,
            'process_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024),
            'cursor_peak_characters':cursor.peak,
            'fields':{name:{'occurrences':counts[name],'encoded_total_bytes':totals[name],
                            'unique_payloads':len(unique[name]),'unique_encoded_bytes':sum(unique[name].values())} for name in totals},
            'all_candidate_source_reference_occurrences':{'count':ref_count,'encoded_total_bytes':ref_bytes,'unique_payloads':len(unique_refs),'unique_encoded_bytes':sum(unique_refs.values())}}
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
