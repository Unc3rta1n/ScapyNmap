from enum import Enum


class TimeoutEnum(Enum):
    T0 = (600.0, 5.0, 0)  # (inter-packet delay, timeout, retry)
    T1 = (15.0, 3.0, 1)
    T2 = (1.5, 1.0, 1)
    T3 = (0.8, 0.5, 2)
    T4 = (0.1, 0.5, 3)
    T5 = (0.05, 0.5, 1)


# TODO побаловаться с параметрами, определить более быстрые, при T5 сейчас долго работает
