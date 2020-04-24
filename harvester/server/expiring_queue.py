from queue import Queue, SimpleQueue, Empty
from threading import Timer
from typing import Any


class ExpiringQueue(Queue):
    def __init__(self, timeout: int, maxsize=0):
        super().__init__(maxsize)
        self.timeout = timeout
        self.timers: 'SimpleQueue[Timer]' = SimpleQueue()

    def put(self, item: Any) -> None:
        thread = Timer(self.timeout, self.expire)
        thread.start()
        self.timers.put(thread)
        super().put(item)

    def get(self, block=True, timeout=None) -> Any:
        thread = self.timers.get(block, timeout)
        thread.cancel()
        return super().get(block, timeout)

    def expire(self):
        self.get()

    def to_list(self):
        with self.mutex:
            return list(self.queue)


if __name__ == '__main__':
    import time
    eq = ExpiringQueue(timeout=1)
    print(eq)
    eq.put(1)
    time.sleep(.5)
    eq.put(2)
    print(eq.to_list())
    time.sleep(.6)
    print(eq.get_nowait())
    print(eq.get_nowait())
