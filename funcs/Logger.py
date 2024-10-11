from time import time
import requests
import json
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

     def start(self):
        return # Using this function causes the backend to become unresponsive for how long the request lasts
        try:
             if(self.importance in ["warning","permission","error","critical"]):
                 url = self.webhook.main
             else:
                 url = self.webhook.trace
             headers_ = {"Content-Type":"application/json"}
             body_ = {
                 "embeds":[{
                         "title":self.importance.capitalize(),
                         "description":f"`{self.file_name}` - {self.message}",
                         "color": Logger.get_color(self.importance)
                 }]
             }
             _ = requests.post(
                url,
                data = json.dumps(body_),
                headers = headers_
            )
        except Exception:
            print("Failed to send to webhook")



class Logger:
    def __init__(self,filename:any, webhook_url:str,trace_url:str):
        self.filename=filename
        self.webhook = webhook_url
        self.trace_url = trace_url

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
        self.send_to_webhook("trace",message)

    def info(self,message:str) -> None:
        print(f"{self.filename} - INFO: {message}")
        self.send_to_webhook("info",message)

    def warn(self,message:str) -> None:
        print(f"{self.filename} - WARNING: {message}")
        self.send_to_webhook("warning",message)

    def permission(self,message:str) -> None:
        print(f"{self.filename} - PERMISSION: {message}")
        self.send_to_webhook("permission",message)

    def error(self,message:str) -> None:
        print(f"{self.filename} - ERROR: {message}")
        self.send_to_webhook("error",message)

    def critical(self,message:str) -> None:
        print(f"{self.filename} - CRITICAL: {message}")
        self.send_to_webhook("critical",message)


    def time(self,func):
       def wrap(*args, **kwargs):
           start = time()
           result = func(*args,**kwargs)
           end = time()
           self.time_log(f"{func.__name__}: {abs(end-start)}")
           return result
       return wrap
