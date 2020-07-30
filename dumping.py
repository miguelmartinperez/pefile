import MySQLdb, os
from subprocess import check_output, call, Popen, PIPE
import json

OSs = ['Win7', 'Win8', 'Win10'] #
PROF = ['Win7SP1x{0}', 'Win8SP1x{0}', 'Win10x{0}_14393'] #
ARCHs = ['86', '64']
experiment_list = [''] #'', , '--unaslr-disassembler'] '--unaslr-sys'

sections = 'PE'
programs = 'winlogon,wininit,lsass,explorer.exe,vlc.exe,notepad\+\+,spoolsv'
dlls =     'kernel32,user32,ntdll,advapi32,msvcrt'


for oss, profile in zip(OSs, PROF):
	for experiment in experiment_list:
		for arch in ARCHs:
			print 'dumps/'+oss+'x'+arch+ ' profile: ' + profile.format(arch)
			print '/home/main/fuzzy-experiments/dumps/{0}x{1}/{0}x{1}dump9.elf'.format(oss, arch)
			p = Popen(['python', '../volatility/vol.py', '--plugins=/home/main/Drive/git/SUM/',
							'-f', '/home/main/fuzzy-experiments/dumps/{0}x{1}/{0}x{1}dump9.elf'.format(oss, arch), '--profile='+profile.format(arch), 'processfuzzyhash', '--mode', 'dll', '-A', 'dcfldd', '-S', sections, '-E', programs, '-D', programs, '-t', experiment, '--json', '-T', 'dump_test/{0}/{1}/'.format(oss, arch)], stdout=PIPE)
			for hash_list in p.stdout:
					pass
			p = Popen(['python', '../volatility/vol.py', '--plugins=/home/main/Drive/git/SUM/',
							'-f', '/home/main/fuzzy-experiments/dumps/{0}x{1}/{0}x{1}dump9.elf'.format(oss, arch), '--profile='+profile.format(arch), 'processfuzzyhash', '--mode', 'dll', '-A', 'dcfldd', '-S', sections, '-N', 'spoolsv.exe', '-D', dlls, '-t', experiment, '--json', '-T', 'dump_test/{0}/{1}/'.format(oss, arch)], stdout=PIPE)
			for hash_list in p.stdout:
					pass
db.commit()
cursor.close()