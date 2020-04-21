import datetime


def time_to_python(time):
    if 'utcTime' in time:
        return time['utcTime'].asDateTime
    else:
        return time['generalTime'].asDateTime


def accuracy_to_python(accuracy):
    delta = datetime.timedelta()
    if 'seconds' in accuracy and accuracy['seconds'].isValue:
        delta += datetime.timedelta(seconds=int(accuracy['seconds']))
    if 'millis' in accuracy and accuracy['millis'].isValue:
        delta += datetime.timedelta(milliseconds=int(accuracy['millis']))
    if 'micros' in accuracy and accuracy['micros'].isValue:
        delta += datetime.timedelta(microseconds=int(accuracy['micros']))
    return delta
