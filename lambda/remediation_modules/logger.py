from botocore.exceptions import ClientError
import datetime
import time

response = {
        "messages": [],
        "status": "success" # will be failed when failed (one of the messages is an error)
    }

def reset_logs():
    global response
    response = {
        "messages": [],
        "status": "success"
    }

def log(message, logLevel="INFO"):
    ## print the message for debug purposes
    print(str(message))
    
    # get the current time int UTC
    now = datetime.datetime.utcnow()

    # if we got this message in an ERROR, it means that it is not a real error
    # so we set the logLevel to info
    if('Request would have succeeded, but DryRun flag is set' in str(message)):
        logLevel="INFO"
    
    # set the status to fail if there was an actual error
    if(logLevel.upper() == "ERROR"):
        response["status"] = "failed"
    
    # constract the log message with the the time and add it to the list of messages
    log_message = str(round(time.time() * 1000)) + ": "   + logLevel.upper() + ": " + str(message)
    response["messages"].append(str(log_message))

def get_logs():
    return response