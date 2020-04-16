from queue import Queue
import threading
import time
from typing import Any


class ExpiringQueue(Queue):
    def __init__(self, timeout: int, maxsize=0):
        super().__init__(maxsize)
        self.lock = threading.Lock()
        self.timeout = timeout
        self.threads: Queue[threading.Timer] = Queue()

    def put(self, item: Any) -> None:
        with self.lock:
            thread = threading.Timer(self.timeout, self.expire)
            thread.start()
            self.threads.put(thread)
            super().put(item)

    def get(self, block=True, timeout=None) -> Any:
        with self.lock:
            thread = self.threads.get(block, timeout)
            thread.cancel()
            return super().get(block, timeout)

    def expire(self):
        self.get()


if __name__ == '__main__':
    eq = ExpiringQueue(timeout=1)
    eq.put(1)
    time.sleep(.5)
    eq.put(2)
    print(list(eq.queue))
    time.sleep(.6)
    print(eq.get_nowait())
    print(eq.get_nowait())
