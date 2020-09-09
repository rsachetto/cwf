#!/bin/bash
sudo gdb todo_list/cgi-bin/cwf.cgi $(pgrep cwf.cgi) -x gdb_commands
