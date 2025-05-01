import requests
import time
from .Logger import Logger
from .Session import Session
from .Database import Database
import os
from dotenv import load_dotenv
load_dotenv()

l = Logger("Translations.py",os.getenv("DC_WEBHOOK"),os.getenv("DC_TRACE"))

class Translations:
   

    def get_percentages(self) -> dict:
        """Gets completion percentages of languages

        Returns:
            dict: {lang:0 to 1}
        """
        return self.percentages


    @Session.requires_auth
    def contribute(self,session:Session) -> bool:
        """Contributes to a specified language

        Args:
            lang (str): Two letter language code (German -> de, English -> en)
            keys (list): {key:string,val:string} where key is the translation key, and val being the translation

        Returns:
            bool: If contributed
        """


