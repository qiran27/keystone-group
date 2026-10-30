"""Compile the real EPM reservation routine with allocation/locking test stubs."""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / '../../linux-keystone-driver/keystone-page.c').resolve().read_text(encoding='utf-8')
constants = []
for name in ('KEYSTONE_GROUP_MIN_SLICE_PAGES', 'KEYSTONE_GROUP_FUTURE_SLICE_CAP_PAGES',
             'KEYSTONE_GROUP_SLICE_ALIGN_PAGES'):
    constants.append(re.search(r'^#define ' + name + r' .+$', source, re.M).group())
start = source.index('int epm_group_slice_init(')
brace = source.index('{', start)
depth = 1
end = brace + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
pathlib.Path(sys.argv[1]).write_text('\n'.join(constants) + '\n' + source[start:end] + '\n', encoding='utf-8')
