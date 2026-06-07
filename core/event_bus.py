from queue import Queue

event_queue = Queue()


def push_event(event):
    event_queue.put(event)
