from time import time
import threading

class Webhook:
    def __init__(self, main: str, trace: str):
        self.main = main
        self.trace = trace

class LogManager(threading.Thread):
     def __init__(self, message, webhook: Webhook, importance: str, filename: str):
        super(LogManager, self).__init__()
        self.daemon = True
        self.webhook = webhook
        self.importance = importance
        self.file_name = filename
        self.message = message


class Logger:
    def __init__(self,filename:str):
        self.filename=filename

    @staticmethod
    def get_color(importance:str) -> int:
        default = 7912703
        values = {
            "warning":15232515,
            "permission":221928,
            "error":16724523,
            "critical":9505280
        }
        return values.get(importance,default)

    def send_to_webhook(self,importance:str, message:str) -> None:
        LogManager(
            message = message,
            webhook = Webhook(self.webhook, self.trace_url),
            importance = importance,
            filename = self.filename
        ).start()

    def time_log(self,message:str) -> None:
        return
        self.trace(message)

    def trace(self,message:str) -> None:
        return
        print(f"{self.filename} - TRACE: {message}")

    def info(self,message:str) -> None:
        print(f"{self.filename} - INFO: {message}")

    def warn(self,message:str) -> None:
        print(f"{self.filename} - WARNING: {message}")

    def permission(self,message:str) -> None:
        print(f"{self.filename} - PERMISSION: {message}")

    def error(self,message:str) -> None:
        print(f"{self.filename} - ERROR: {message}")

    def critical(self,message:str) -> None:
        print(f"{self.filename} - CRITICAL: {message}")



    def time(self,func):
       def wrap(*args, **kwargs):
           start = time()
           result = func(*args,**kwargs)
           end = time()
           self.time_log(f"{func.__name__}: {abs(end-start)}")
           return result
       return wrap
