from queue import SimpleQueue
from threading import Timer
from typing import Any


class ExpiringQueue(SimpleQueue):
    def __init__(self, timeout: int):
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


if __name__ == '__main__':
    import time
    eq = ExpiringQueue(timeout=1)
    eq.put(1)
    time.sleep(.5)
    eq.put(2)
    print(list(eq.queue))
    time.sleep(.6)
    print(eq.get_nowait())
    print(eq.get_nowait())
