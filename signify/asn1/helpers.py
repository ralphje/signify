from __future__ import annotations

import datetime

from asn1crypto import tsp


def accuracy_to_python(accuracy: tsp.Accuracy) -> datetime.timedelta:
    delta = datetime.timedelta()
    if not accuracy:
        return delta

    if accuracy["seconds"].native:
        delta += datetime.timedelta(seconds=accuracy["seconds"].native)
    if accuracy["millis"].native:
        delta += datetime.timedelta(milliseconds=accuracy["millis"].native)
    if accuracy["micros"].native:
        delta += datetime.timedelta(microseconds=accuracy["micros"].native)
    return delta
