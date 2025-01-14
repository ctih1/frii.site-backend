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
    def __init__(self,api_key:str,database:Database):
        self.api_key = api_key
        headers_ = {
            "Accept": "application/json",
            "Authorization":f"Bearer {self.api_key}",
            "X-GitHub-Api-Version":"2022-11-28"
        }
        self.db:Database = database
        response = requests.get("https://api.github.com/repos/ctih1/frii.site-frontend/contents/src/locales?ref=dev",headers=headers_)

        self.languages: dict = {}
        for file in response.json():
            filename = file["name"].split(".")[0]
            self.languages[filename] = requests.get(file["download_url"]).json()
        self.keys = {}
        self.percentages = self.__calculate_percentages__()

    @l.time
    def __calculate_percentages__(self,use_int:bool=False):
        main_language =  self.languages["en"]
        missing_keys:dict = {}
        total_keys = len(main_language)

        for language in self.languages:
            preview_keys:dict = self.db.translation_collection.find_one({"_id":language})
            if(preview_keys is None or preview_keys.get("keys",None) is None):
                l.warn(f"`preview_keys` doesn't exist for language {language}")
                preview_keys = {}
            for key in main_language:
                if (language not in missing_keys):
                    missing_keys[language] = {}
                    missing_keys[language]["misses"] = 0
                    missing_keys[language]["keys"] = []
                print(f"{(key in self.languages[language])} - {(key in preview_keys.get('keys',{}))}")
                if(key not in self.languages[language] and key not in preview_keys.get("keys",{})):
                    missing_keys[language]["misses"] += 1
                    missing_keys[language]["keys"].append({"key":key,"ref":main_language.get(key)})
        percentages = {}
        for language in missing_keys:
            self.keys[language] = missing_keys[language]["keys"]
            result = 1-(missing_keys[language]["misses"]/total_keys)
            if(use_int): result = round(result*100)
            percentages[language] = result
        return percentages

    def get_percentages(self) -> dict:
        """Gets completion percentages of languages

        Returns:
            dict: {lang:0 to 1}
        """
        return self.percentages

    def get_keys(self,language:str) -> dict:
        return self.keys[language]

    @Session.requires_auth
    def contribute(self, lang:str, keys: list,session:Session) -> bool:
        """Contributes to a specified language

        Args:
            lang (str): Two letter language code (German -> de, English -> en)
            keys (list): {key:string,val:string} where key is the translation key, and val being the translation

        Returns:
            bool: If contributed
        """

        language = {}

        for translation in keys:
            if(translation["val"]!=""):
                try:
                    self.keys[lang].pop(list(self.keys[lang]).index({"key":translation["key"], "ref":self.languages["en"].get(translation["key"])}))
                except ValueError:
                    l.warn(f"Got a value error trying to delete key {translation['key']}")
                language["keys."+translation["key"]] = {}
                language["keys."+translation["key"]]["val"] = translation["val"]
                language["keys."+translation["key"]]["contributor"] = session.username

        self.db.translation_collection.update_one(
            {"_id":lang},
            {"$set": language},upsert=True
        ) # upsert creates a new document if one does not exist
        return True
