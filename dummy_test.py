import sys, os
import pefile

if len(sys.argv) == 1:
    print ("Error: file is not declareted")
    exit(1)

if not os.path.exists(sys.argv[1]):
    print ("Error: File does not exist")
    exit(1)

file = open(sys.argv[1], 'rb')
content = file.read()
file.close()

peMemory = pefile.PE(data=content, from_memory=True, )

peMemory.print_info()
exit(0)
