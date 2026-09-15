"""Fetch official, checksum-verified AIT-ADS and pinned labels for four scenarios."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import urllib.request
import zipfile

SCENARIOS = ('russellmitchell','shaw','wardbeck','santos')
LABEL_COMMIT = 'ce927ddaeaa674f6909e1de676fa7dc293e393bd'

def digest(path, algorithm='sha256'):
    h=hashlib.new(algorithm)
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(__doc__);p.add_argument('--output', default='work/ait_validation_data');a=p.parse_args()
    root=Path(a.output);root.mkdir(parents=True,exist_ok=True)
    archive=root/'ait_ads.zip'
    if not archive.exists():
        urllib.request.urlretrieve('https://zenodo.org/api/records/8263181/files/ait_ads.zip/content', archive)
    if digest(archive,'md5')!='43db6b1f0996e0024befd617706c50e9':
        raise ValueError('AIT-ADS archive checksum mismatch')
    labels=root/'alerts_csv.zip'
    urllib.request.urlretrieve(f'https://raw.githubusercontent.com/ait-aecid/alert-data-set/{LABEL_COMMIT}/alerts_csv/alerts_csv.zip',labels)
    manifest={'zenodo_record':8263181,'archive_md5':digest(archive,'md5'),'labels_commit':LABEL_COMMIT,'labels_archive_sha256':digest(labels),'files':{}}
    for zip_path,folder,suffix in [(archive,'data','_wazuh.json'),(labels,'labels','_alerts.txt')]:
        out=root/folder;out.mkdir(exist_ok=True)
        with zipfile.ZipFile(zip_path) as z:
            for scenario in SCENARIOS:
                name=scenario+suffix
                matches=[i for i in z.infolist() if Path(i.filename).name==name]
                if len(matches)!=1:raise ValueError(f'Expected one archive member: {name}')
                # Never use archive-provided paths as extraction targets.
                with z.open(matches[0]) as src,(out/name).open('wb') as dst:shutil.copyfileobj(src,dst)
                manifest['files'][name]=digest(out/name)
    (root/'provenance.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(root.resolve())

if __name__=='__main__':main()
