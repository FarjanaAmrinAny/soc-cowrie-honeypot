import json
import csv 
with open("var/log/cowrie/cowrie.json")as f,\
open("cowrie_report.csv","W",newline="")as out:
fields =["timestamp","eventid","src_ip","username","input","session"]
writer =csv.Dictwriter(out,fieldnames=fields)
writer.writeheader()
for line in f:
event = json.loads(line)
write.writerow({key:event.get(key,"")
for key in fields})
print("CSV report created successfully!")

