import os
import argparse
import datetime
import tempfile

def main():
    daysToKeep = 100

    parser = argparse.ArgumentParser(description="Enter the history file to purge")   
    parser.add_argument("--file", help="History file", type=str)
    parser.add_argument("--days", help="Days to keep", type=int)

    args = parser.parse_args()    

    if args.file == None or not os.path.exists(args.file):
        print("[-] Error: the history file ", args.file, " does not exist")
        exit(-1)

    if args.days == None:
        print("[+] Setting the number of days to keep to ", daysToKeep, " since none specified" )
    else:
        daysToKeep = args.days

    print("[+] Reading ", args.file)    

    dtNow = datetime.datetime.now()

    fdTemp, temppath = tempfile.mkstemp()
    with os.fdopen(fdTemp, "w") as tmpFile:
        with open(args.file, "r") as historyFile:
            for line in historyFile:
                strColumns = line.strip().split(",")

                if(len(strColumns) > 1):
                    strDate = strColumns[1]
                    dtObj = datetime.datetime.strptime(strDate, "%Y-%m-%d %H:%M:%S")  
                    dtStartDate = dtObj + datetime.timedelta(days=daysToKeep)         

                    if(dtStartDate < dtNow):
                        print("[+] This line is too old ", line)
                    else:
                        print("[+] Adding ", line) 
                        tmpFile.write(line)
    historyFile.close()
    os.remove(args.file)
    os.rename(temppath, args.file)
    
    print("[+] Done purging history!")

# Old fashioned python syntax
if __name__ == "__main__":    
    main()

