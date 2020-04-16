from multiprocessing import Manager

manger = Manager()

host_map = manger.dict()
tokens = manger.Queue()
