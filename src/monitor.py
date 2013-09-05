#!/usr/bin/python
###################################################################
#
# This one monitors file system integrity
#
###################################################################
import os,re, hashlib, time, subprocess, thread,datetime, shutil
from src.core import *
from src.smtp import *

send_email = check_config("ALERT_USER_EMAIL=")
exclude = check_config("EXCLUDE=")
excluding = exclude != ""
exclude_dirs = exclude.split(",")

def exclude_check(file):
    if excluding:
        for exclude_dir in exclude_dirs:
            match = re.search(exclude_dir, file)

            if match:
                return 0

    return 1

def monitor_system(time_wait):
    # total_compare is a tally of all sha512 hashes
    total_compare = ""
    check_folders = check_config("MONITOR_FOLDERS=")
    check_folders = check_folders.replace('"', "")
    check_folders = check_folders.replace("MONITOR_FOLDERS=", "")
    check_folders = check_folders.rstrip()
    check_folders = check_folders.split(",")

    for directory in check_folders:
        time.sleep(0.1)
        # we need to check to see if the directory is there first, you never know
        if os.path.isdir(directory):
            if exclude_check(directory):
                for path, subdirs, files in os.walk(directory):
                    for name in files:
                        filename = os.path.join(path, name)

                        if exclude_check(filename):
                            if os.path.isfile(filename):
                                try:
                                    fileopen = file(filename, "rb")
                                    data = fileopen.read()

                                except: pass

                                hash = hashlib.sha512()
                                try:
                                    hash.update(data)
                                except: pass
                                # here we split into : with filename : hexdigest
                                compare = filename + ":" + hash.hexdigest() + "\n"
                                # this will be all of our hashes
                                total_compare = total_compare + compare

    # write out temp database
    filewrite = file("/var/artillery/database/temp.database", "w")
    filewrite.write(total_compare)
    filewrite.close()

    # once we are done write out the database, if this is the first time, create a database then compare
    if not os.path.isfile("/var/artillery/database/integrity.database"):
        # prep the integrity database to be written for first time
        filewrite = file("/var/artillery/database/integrity.database", "w")
        # write out the database
        filewrite.write(total_compare)
        # close the database
        filewrite.close()

    # hash the original database
    if os.path.isfile("/var/artillery/database/integrity.database"):
        fileopen1 = file("/var/artillery/database/integrity.database", "r")
        data1 = fileopen1.read()
        if os.path.isfile("/var/artillery/database/temp.database"):
            fileopen2 = file("/var/artillery/database/temp.database", "r")
            data2 = fileopen2.read()
            # hash the databases then compare
            hash1 = hashlib.sha512()
            hash1.update(data1)
            hash1 = hash1.hexdigest()
            # this is the temp integrity database
            hash2 = hashlib.sha512()
            hash2.update(data2)
            hash2 = hash2.hexdigest()
            # if we don't match then there was something that was changed
            if hash1 != hash2:
                # using diff for now, this will be rewritten properly at a later time
                compare_files = subprocess.Popen("diff /var/artillery/database/integrity.database /var/artillery/database/temp.database", shell=True, stdout=subprocess.PIPE)
                output_file = compare_files.communicate()[0]
                if output_file == "":
                    # no changes
                    pass

                else:
                    output_file = "********************************** The following changes were detect at %s **********************************\n" % (datetime.datetime.now()) + output_file + "\n********************************** End of changes. **********************************\n\n"
                    email_alerts = check_config("EMAIL_ALERTS=").lower()
                    # check email frequency
                    email_frequency = check_config("EMAIL_FREQUENCY=").lower()
                    # if alerts and frequency are off then just send email
                    if email_alerts == "on" and email_frequency == "off":
                        mail(send_email,
                        "[!] Artillery has detected a change. [!]",
                        output_file)
                    # if we are using email frequency
                    if email_alerts == "on" and email_frequency == "on":
                        prep_email(output_file+"\n")
                    # write out to log
                    write_log(output_file)

    # put the new database as old
    if os.path.isfile("/var/artillery/database/temp.database"):
        shutil.move("/var/artillery/database/temp.database", "/var/artillery/database/integrity.database")

def start_monitor():
    # check if we want to monitor files
    monitor_check = check_config("MONITOR=")
    if monitor_check.lower() == "on":
        # start the monitoring
        time_wait = check_config("MONITOR_FREQUENCY=")

        # loop forever
        while 1:
            thread.start_new_thread(monitor_system, (time_wait,))
            time_wait = int(time_wait)
            time.sleep(time_wait)

# start the thread only if its running posix will rewrite this module to use difflib and some others butfor now its reliant on linux
operating_system = check_os()
if operating_system == "posix":
    thread.start_new_thread(start_monitor, ())
