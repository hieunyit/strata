#!/usr/bin/env python3
"""ASan NGINX/SQLite probe for the signed fixture exported by policy_exceptions.rs."""
import argparse,json,os,sys,hashlib
from pathlib import Path
from urllib.parse import quote
sys.path.insert(0,str(Path(__file__).resolve().parent))
import header_probe as probe
sql="-1 UNION SELECT '"+probe.MARKER+"'--"
probe.cases=lambda:[
 {'id':'header-allowed-by-exception','uri':'/header-sql','headers':{'X-Example-Filter':sql},'malicious':True,'oracle':True},
 {'id':'other-field-still-blocked','uri':'/header-sql?id='+quote(sql),'headers':{'X-Example-Filter':sql},'malicious':True,'oracle':True},
 {'id':'benign','uri':'/header-sql','headers':{'X-Example-Filter':'1'},'malicious':False},
]
out=Path('build/m2-runtime-http/probe').resolve();out.mkdir(parents=True,exist_ok=True)
os.environ['ASAN_OPTIONS']='detect_leaks=0:detect_odr_violation=0:abort_on_error=1:log_path='+str(out/'asan')
os.environ['UBSAN_OPTIONS']='print_stacktrace=1:halt_on_error=1:log_path='+str(out/'ubsan')
probe.run(argparse.Namespace(nginx='build/nginx-1.30.5-asan/objs/nginx',module='build/nginx-1.30.5-asan/objs/ngx_http_strata_module.so',mkbundle='target/release/mkbundle',bundle='build/m2-runtime-http-fixture/bundle.sbn',pubkey='build/m2-runtime-http-fixture/bundle.pub',out=str(out),policy='example-api',rounds=1,http_check_command=[]))
rows=[json.loads(x) for x in (out/'requests.jsonl').read_text().splitlines()]
assert [r['classification'] for r in rows]==['backend_sql_oracle_reached','signature_block','benign_pass'],rows
assert rows[1]['proxy']['rules']=='700011',rows[1]
assert not list(out.glob('asan.*')) and not list(out.glob('ubsan.*'))
metadata=json.loads((out/'metadata.json').read_text())
metadata['exception_probe_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
metadata['scope']='explicit_header_exception_and_other_field_enforcement'
(out/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
print('exception HTTP assertions PASS; no sanitizer reports')
