"""Render only ARMASM directives/symbol decoration; retain every instruction."""
from pathlib import Path
NAMES=('NufNcFillWords','NufNcCopyWords','NufNcMatchWords')
def render(source):
 lines=['.text','.p2align 2']
 for raw in Path(source).read_text().splitlines():
  s=raw.split(';',1)[0].strip()
  if not s:continue
  if s.startswith(('AREA ','EXPORT ')) or s in ('END','ENDP'):continue
  if s.endswith(' PROC'):
   name=s.split()[0];assert name in NAMES
   lines+=['.globl _'+name,'_'+name+':'];continue
  if not raw[0].isspace():
   assert ' ' not in s;lines.append(s+':')
  else:lines.append('    '+s)
 return '\n'.join(lines)+'\n'
