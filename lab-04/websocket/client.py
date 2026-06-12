import tornado.ioloop
import tornado.websocket

class WebSocketClient:
    def __init__(self, io_loop):
        self.connection = None
        self.io_loop = io_loop

    def start(self):
        self.connect_and_read()

    def stop(self):
        self.io_loop.stop()

    def connect_and_read(self):
        print("Reading...", flush=True)
        future = tornado.websocket.websocket_connect(
            url="ws://localhost:8888/websocket/",
            ping_interval=10,
            ping_timeout=10,
        )
        future.add_done_callback(self.maybe_retry_connection)

    def maybe_retry_connection(self, future) -> None:
        try:
            self.connection = future.result()
        except:
            print('Could not reconnect, retrying in 3 seconds...', flush=True)
            self.io_loop.call_later(3, self.connect_and_read)
            return

        self.connection.read_message(callback=self.on_message)

    def on_message(self, future):
        message = future.result()

        if message is None:
            print('Disconnected, reconnecting...', flush=True)
            self.connect_and_read()
            return

        print(f"Received word from server: {message}", flush=True)

        self.connection.read_message(callback=self.on_message)

def main():
    io_loop = tornado.ioloop.IOLoop.current()

    client = WebSocketClient(io_loop)
    io_loop.add_callback(client.start)

    io_loop.start()

if __name__ == "__main__":
    main()
