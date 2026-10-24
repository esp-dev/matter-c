import json,unittest
from report_blocks_decode import validate,decode

def record(kind='read',mode='peak-bytes'):
    a=dict(kind=kind,phase='complete',mode=mode,samples=1,item_size=32,value_size=16,instances=1,logical=17,slots=25,blocks=2,headers=16,padding=256,retired=32,
           value_slots=0,value_selected=0,value_headers=0,value_padding=0,value_retired=0,requested_bytes=816)
    if kind=='subscribe':a.update(value_slots=16,value_selected=1,value_headers=8,value_padding=240,value_retired=16,requested_bytes=1080)
    if mode=='current':
        for k in a:
            if k not in ('kind','phase','mode','samples','item_size','value_size'):a[k]=0
    return a

def fixture():
    lines=[]
    for kind in ('read','subscribe'):
        for mode in ('peak-bytes','peak-padding','peak-joint','current'):lines.append('BLOCK_AUDIT '+json.dumps(record(kind,mode)))
        lines.append('BLOCK_REGISTRY '+json.dumps(dict(kind=kind,phase='complete',empty=True)))
    return '\n'.join(lines)

class Inventory(unittest.TestCase):
    def test_conservation(self):
        self.assertEqual(decode(fixture())['joint_peak']['requested_bytes'],1896)
    def test_wrong_bytes(self):
        a=record();a['requested_bytes']+=4
        with self.assertRaises(ValueError):validate(a)
    def test_occupancy(self):
        for key,value in (('logical',26),('padding',0),('retired',1000),('samples',True),('item_size',0)):
            a=record();a[key]=value
            with self.assertRaises(ValueError):validate(a)
    def test_sparse_values(self):
        for key,value in (('value_selected',17),('value_padding',0),('value_retired',32)):
            a=record('subscribe');a[key]=value
            with self.assertRaises(ValueError):validate(a)
    def test_read_separate_values(self):
        a=record('subscribe');a['kind']='read'
        with self.assertRaises(ValueError):validate(a)
    def test_incomplete(self):
        with self.assertRaises(ValueError):decode('\n'.join(fixture().splitlines()[:-1]))
    def test_live(self):
        with self.assertRaises(ValueError):decode(fixture().replace('"empty": true','"empty": false'))
    def test_partial_phase(self):
        with self.assertRaises(ValueError):decode(fixture().replace('complete','checkpoint'))
    def test_duplicate_mode(self):
        lines=fixture().splitlines()
        with self.assertRaises(ValueError):decode('\n'.join([lines[0],*lines]))
    def test_unknown_fields(self):
        a=record();a['address']=123
        with self.assertRaises(ValueError):validate(a)
    def test_no_data(self):
        with self.assertRaises(ValueError):decode('normal UART text')

if __name__=='__main__':unittest.main(verbosity=2)
