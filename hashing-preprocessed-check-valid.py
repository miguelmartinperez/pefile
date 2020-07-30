import MySQLdb, os
from subprocess import check_output, call, Popen, PIPE
import json

OSs = ['Win10'] #'Win7', 'Win8', 
PROF = ['Win10x{0}_14393'] #'Win7SP1x{0}', 'Win8SP1x{0}', 
ARCHs = ['86'] #, '64']
experiment_list = ['--unaslr-disassembler'] #'', , '--unaslr-disassembler'] '--unaslr-sys'

sections = 'header,.text'
programs = 'winlogon,wininit,lsass,explorer.exe,vlc.exe,notepad\+\+,spoolsv'
dlls =     'kernel32,user32,ntdll,advapi32,msvcrt'


db = MySQLdb.connect(host="localhost",
						user="fuzzy",
						passwd="fuzzy",
						db="fuzzyRPPGood5")

cursor = db.cursor()


def GetCreateOsId(os_name, os_arch):
	query = ("SELECT id FROM OperatingSystem WHERE name=%s and arch=%s")
	cursor.execute(query, (os_name, os_arch))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: OS does not exist {} {}".format(os_name, os_arch)
		exit()
		query = ("INSERT INTO OperatingSystem (name, arch) VALUES (%s, %s)")
		cursor.execute(query, (os_name, os_arch))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateDumpId(os_id, dump_name):
	query = ("SELECT id FROM Dump WHERE os_id=%s and name=%s")
	cursor.execute(query, (os_id, dump_name))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: dump does not exist {}".format(dump_name)
		exit()
		query = ("INSERT INTO Dump (os_id, name) VALUES (%s, %s)")
		cursor.execute(query, (os_id, dump_name))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateProcessId(dump_id, process_name, pid):
	query = ("SELECT id FROM Process WHERE dump_id=%s and processName=%s and pid=%s")
	cursor.execute(query, (dump_id, process_name, pid))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: process does not exist {} {}".format(process_name, pid)
		exit()
		query = ("INSERT INTO Process (dump_id, processName, pid) VALUES (%s, %s, %s)")
		cursor.execute(query, (dump_id, process_name, pid))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateModuleId(process_id, module_name, base_address, module_path, pe_memo_time, preProcessing, pre_process_time):
	query = ("SELECT id FROM Module WHERE process_id=%s AND baseAddress=%s AND preProcessing=%s")
	cursor.execute(query, (process_id, base_address, preProcessing))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: module does not exist {} {}".format(module_name, module_path)
		exit()
		query = ("INSERT INTO Module (process_id, peName, baseAddress, modulePath, PEMemoryTime, preProcessing, PreProcessingTime) VALUES (%s, %s, %s, %s, %s, %s, %s)")
		cursor.execute(query, (process_id, module_name, base_address, module_path, pe_memo_time, preProcessing, pre_process_time))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateSectionId(module_id, section_name, offset, size, numPage, ValidPages):

	query = ("SELECT id FROM Section WHERE module_id=%s and section=%s")
	cursor.execute(query, (module_id, section_name if section_name=='header' else section_name[1:5]))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: section does not exist {}".format(section_name if section_name=='header' else section_name[1:5])
		exit()
		query = ("INSERT INTO Section (module_id, section, offset, size, numPage, validPage) VALUES (%s, %s, %s, %s, %s, %s)")
		cursor.execute(query, (module_id, section_name, offset, size, numPage, ValidPages))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateHashSection(section_id, algorithm):
	query = ("SELECT id FROM SectionHash WHERE section_id=%s and algorithm=%s")
	cursor.execute(query, (section_id, algorithm))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: algorithm does not exist {}; section id {}".format(algorithm, section_id)
		exit()
		query = ("INSERT INTO SectionHash (section_id, algorithm) VALUES (%s, %s)")
		cursor.execute(query, (section_id, algorithm))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0]

def GetCreateHashPage(section_hash_id, indexPage, hash, hashingTime):
	query = ("SELECT id, hash FROM HashPage WHERE section_hash_id=%s and indexPage=%s")
	cursor.execute(query, (section_hash_id, indexPage))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		print "Error: hashPage does not exist {}; section algorithm id {}".format(indexPage, section_hash_id)
		exit()
		query = ("INSERT INTO HashPage (section_hash_id, indexPage, hash, hashingTime) VALUES (%s, %s, %s, %s)")
		cursor.execute(query, (section_hash_id, indexPage, hash, hashingTime))
		db.commit()
		return cursor.lastrowid
	else:
		return id_list[0][0], id_list[0][1]

def GetCreateHashPageEmpty(section_hash_id, indexPage, hash, hashingTime):
	query = ("SELECT id, hash FROM HashPage WHERE section_hash_id=%s and indexPage=%s")
	cursor.execute(query, (section_hash_id, indexPage))
	id_list =  cursor.fetchall()
	if len(id_list) == 0:
		return
	else:
		print "Error: hashPage exist when it must not {}; section algorithm id {}".format(indexPage, section_hash_id)
		exit()

for oss, profile in zip(OSs, PROF):
	for experiment in experiment_list:
		for arch in ARCHs:
			for dump_file in os.listdir('dumps/' + oss + 'x' + arch):
				print 'dumps/'+oss+'x'+arch+'/'+dump_file+ ' profile: ' + profile.format(arch) +' ' + experiment
				p = Popen(['python', 'volatility/vol.py', '--plugins=/home/mmarpe/drive/git/SUM',
								'-f', 'dumps/' + oss + 'x' + arch+'/'+dump_file, '--profile='+profile.format(arch), 'processfuzzyhash', '--mode', 'dll', '-A', 'dcfldd,sdhash,tlsh', '-S', sections, '-E', programs, '-D', programs, '-t', experiment, '--json'], stdout=PIPE)
				for hash_list in p.stdout:
					hash_dic = json.loads(hash_list)
					OsId = GetCreateOsId(oss, arch)
					DumId = GetCreateDumpId(OsId, dump_file)
					ProcessId = GetCreateProcessId(DumId, hash_dic.get('Process'), hash_dic.get('Pid'))
					ModulId = GetCreateModuleId(ProcessId, hash_dic.get('Module Name'), hash_dic.get('Module Base'), hash_dic.get('Path'), hash_dic.get('PEMemory time'), experiment if experiment else 'Raw', hash_dic.get('Pre-processing Time') if hash_dic.get('Pre-processing Time') != 'None' else 0)
					SectionId = GetCreateSectionId(ModulId, hash_dic.get('Section'), hash_dic.get('Section Offset'), hash_dic.get('Size'), hash_dic.get('Num Page'), hash_dic.get('Num Valid Pages'))
					SectionHashID = GetCreateHashSection(SectionId, hash_dic.get('Algorithm'))
					hash_list = hash_dic.get('Generated Hash')
					time_hahsing_list = hash_dic.get('Computation Time')
					index = 0
					for hash_element, time_elemet in zip(hash_dic.get('Generated Hash').split(';'), hash_dic.get('Computation Time').split(';')):
						if hash_element != '*':
							hash_id, hashOld = GetCreateHashPage(SectionHashID, index, hash_element, time_elemet)
							if hash_element!=hashOld:
								print 'Error: Different hashes. {} {} {} {} {} {} {} {}'.format(hash_dic.get('Process'), hash_dic.get('Module Name'), hash_dic.get('Section'), index, hash_dic.get('Algorithm'), hash_id, hash_element, hashOld)
						else:
							GetCreateHashPageEmpty(SectionHashID, index, hash_element, time_elemet)
						index += 1
					
					db.commit()
				p = Popen(['python', 'volatility/vol.py', '--plugins=/home/mmarpe/drive/git/SUM',
								'-f', 'dumps/' + oss + 'x' + arch+'/'+dump_file, '--profile='+profile.format(arch), 'processfuzzyhash', '--mode', 'dll', '-A', 'dcfldd,sdhash,tlsh', '-S', sections, '-N', 'spoolsv.exe', '-D', dlls, '-t', experiment, '--json', '-T', 'files-dumps-fuzzyRPPGood5/{0}/{1}/{2}/{3}'.format(oss, arch, experiment if experiment else 'Raw', dump_file)], stdout=PIPE)
				for hash_list in p.stdout:
					hash_dic = json.loads(hash_list)
					OsId = GetCreateOsId(oss, arch)
					DumId = GetCreateDumpId(OsId, dump_file)
					ProcessId = GetCreateProcessId(DumId, hash_dic.get('Process'), hash_dic.get('Pid'))
					ModulId = GetCreateModuleId(ProcessId, hash_dic.get('Module Name'), hash_dic.get('Module Base'), hash_dic.get('Path'), hash_dic.get('PEMemory time'), experiment if experiment else 'Raw', hash_dic.get('Pre-processing Time') if hash_dic.get('Pre-processing Time') != 'None' else 0)
					SectionId = GetCreateSectionId(ModulId, hash_dic.get('Section'), hash_dic.get('Section Offset'), hash_dic.get('Size'), hash_dic.get('Num Page'), hash_dic.get('Num Valid Pages'))
					SectionHashID = GetCreateHashSection(SectionId, hash_dic.get('Algorithm'))
					hash_list = hash_dic.get('Generated Hash')
					time_hahsing_list = hash_dic.get('Computation Time')
					index = 0
					for hash_element, time_elemet in zip(hash_dic.get('Generated Hash').split(';'), hash_dic.get('Computation Time').split(';')):
						if hash_element != '*':
							hash_id, hashOld = GetCreateHashPage(SectionHashID, index, hash_element, time_elemet)
							if hash_element!=hashOld:
								print 'Error: Different hashes. {} {} {} {} {} {} {} {}'.format(hash_dic.get('Process'), hash_dic.get('Module Name'), hash_dic.get('Section'), index, hash_dic.get('Algorithm'), hash_id, hash_element, hashOld)
						else:
							GetCreateHashPageEmpty(SectionHashID, index, hash_element, time_elemet)
						index += 1
					
					db.commit()
db.commit()
cursor.close()