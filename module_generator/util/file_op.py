
import os

def WriteFile(name_file,buffer):
 file = open(name_file,"w") 
 file.write(buffer) 
 file.close()

def File_to_string(file_name):
 content=""
 content_lines=""
 with open(file_name) as f:
  content = f.readlines()
 for line in content:
  content_lines+=line
 return content_lines

