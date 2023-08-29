#!/usr/bin/python3
# This file handles the running of tool at its
# scheduled time

import os 
import DbManager

class Engine:
    """ 
    This class can be used by other files to start the runner for tools
    """

    def __init__(self):
        # check out the next line. Fix it
        self.db_manager = DbManager.Manager(db_file)
    def start():
        """ 
        Call this function to start an infinite loop, which checks the time to run the tool every moment
        """
        while True:
            checkSchedule()

def checkSchedule():
    pass