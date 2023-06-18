#!/usr/bin/python3
# WallGen v0.2'/'
#You nd yaml, pyyaml modules... 
from util import parser

template_filename=""
rules_filename=""

# Get argvs of user's input
template_filename,rules_filename = parser.arguments()

# load rules of firewall at directory rules
try:
    rules_wall=parser.Get_config(rules_filename)
except Exception as e:
    print(" log error in config parser rules: "+str(e))
    exit(0)

# Load templates and generate
try:
    parser.start_generator(template_filename, rules_wall)
except Exception as e:
    print(" log error in rule generator: "+str(e))
    exit(0)
