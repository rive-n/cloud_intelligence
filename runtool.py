#!/usr/bin/env python3

from classes import *

if __name__ == '__main__':
    args = argument_parser()
    system("cls" if name == "nt" else "clear")
    k8s_object = K8s_info(**args.__dict__)
    loop = new_event_loop()
    loop.run_until_complete(k8s_object.run_tool())
    print(k8s_object)
