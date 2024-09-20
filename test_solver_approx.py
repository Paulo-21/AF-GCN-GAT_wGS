import subprocess
import os
import time
import csv

dir = "../benchmarks/main/"
#all_task = ["DC-CO","DC-ID", "DC-SST", "DC-ST","DC-STG", "DS-PR", "DS-SST", "DS-ST", "DS-STG"]
all_task = ["DC-CO", "DC-ST", "DS-PR", "DS-ST"]
#all_task = ["DC-ST"]
max_time = 39
all_time = {}
all_good = {}
all_error = {}
all_timeout = {}
all_instance = {}
for ta in all_task:
    all_time[ta] = 0
    all_good[ta] = 0
    all_error[ta] = 0
    all_timeout[ta] = 0
    all_instance[ta] = 0

t , err, tot_t, n_error, n_timeout = 0,0,0,0,0
reader = open("../reduce_results2023.csv", 'r')
cr = csv.reader(reader, delimiter=';')

for row in cr:
    task = row[0]
    instance_name = row[1]
    arg_id = row[2]
    truth_answer = eval(row[3])
    if task not in all_task:
        continue
    path = os.path.join(dir, instance_name)
    print("-----------------------------------------")
    print("FILE : ", instance_name, " TASK : ", task)
    all_instance[task] += 1
    try:
        tic = time.perf_counter()
        run = subprocess.run(["python3", "-OO", "-W ignore", "afgcnv3_f11.py", path, task, arg_id],stdout=subprocess.PIPE, timeout=max_time)
        #run = subprocess.run(["python3", "-OO", "-W ignore", "afgcnv3_f11_gatv2.py", path, task, arg_id],stdout=subprocess.PIPE, timeout=max_time)
        #run = subprocess.run(["../harperpp_v1.1.1/taas-harper++", "-f", path, "-p", task, "-a", arg_id],stdout=subprocess.PIPE, timeout=max_time)
        #run = subprocess.run(["../fargo-limited_v1.1.2/src/taas-fargo", "-limit", "500", "-f", path, "-p", task, "-a", arg_id, "-fo", "i23"],stdout=subprocess.PIPE, timeout=max_time)
        toc = time.perf_counter()
        res = run.stdout.decode('utf-8').strip()
        print(res, " ", arg_id, " ", truth_answer, "  eval : ", row[3])
        if (res.startswith("YES") and truth_answer == True) or (res.startswith("NO") and truth_answer == False):
            all_good[task] +=1
            print("CORRECT : ", all_good[task]," / ", all_instance[task], " acc : ",  (all_good[task] / all_instance[task])*100, "%")
        else:
            print("INCORRECT : ", all_good[task]," / ", all_instance[task], " acc : ",  (all_good[task] / all_instance[task])*100, "%")
        t = toc - tic
        
    except subprocess.TimeoutExpired:
        t = "Timeout"
        all_timeout[task] +=1
        t = 39
    if run.returncode != 0:
        t = "Error"
        toc = time.perf_counter()
        t = toc - tic
        all_error[task] +=1

    all_time[task] += t
    print(t, "sec")

print("---------------------------------------------------")
print("Result Finale :")
for ta in all_task:
    print("TASK : ", ta)
    print("Score : ", all_good[ta])
    print("Timeout : ", all_timeout[ta])
    print("Error : ", all_error[ta])
    print("Time Taken : ", all_time[ta])
