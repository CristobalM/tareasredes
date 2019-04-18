

LOGGING = True


def cond_print(s_msg):
    global LOGGING
    if LOGGING:
        print(s_msg)
