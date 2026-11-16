import json,struct,unittest
from pathlib import Path
import analyze as a
F=Path(__file__).resolve().parent.parent/'targeted3/trace'
class DecodeTests(unittest.TestCase):
 def setUp(self):self.before=(F/'before.bin').read_bytes();self.after=(F/'after.bin').read_bytes()
 def reject(self,b):
  with self.assertRaises(ValueError):a.decode(b)
 def test_valid_and_ring_overwrite(self):
  r=a.report(a.decode(self.after),a.decode(self.before));self.assertEqual(r['retained'],128);self.assertGreater(r['overwritten_cumulative'],0);self.assertGreater(r['whole']['Attempts'],0)
 def test_invalid_clock_retained(self):self.assertGreater(a.decode((F/'clock-invalid.bin').read_bytes())['InvalidTimings'],0)
 def test_partial_and_identity(self):
  self.reject(self.before[:-1]);b=bytearray(self.before);b[0]=0;self.reject(b)
 def test_ring(self):
  for off in (184,188):
   b=bytearray(self.before);struct.pack_into('<I',b,off,127);self.reject(b)
 def test_flags_and_generation(self):
  for off,v in [(1724,0),(1724,9),(32,1)]:
   b=bytearray(self.before);struct.pack_into('<I',b,off,v);self.reject(b)
 def test_cross_instance_and_reset(self):
  x=a.decode(self.before);y=a.decode(self.after)
  for n in ('Frequency','InstanceQpc','InstanceSystemTime'):
   z=dict(y);z[n]+=1
   with self.assertRaises(ValueError):a.compare(x,z)
  with self.assertRaises(ValueError):a.compare(y,x)
 def test_overflow(self):
  with self.assertRaises(ValueError):a.total([a.MAX,1])
  b=bytearray(self.before);struct.pack_into('<Q',b,216+16,a.MAX);struct.pack_into('<Q',b,216+24,1);self.reject(b)
 def test_no_interval_max_or_p99(self):
  r=a.report(a.decode(self.after),a.decode(self.before));self.assertNotIn('MaxTotalTicks',r['kinds']['READ4K']);self.assertNotIn('p99',r['kinds']['READ4K'])
if __name__=='__main__':unittest.main()
