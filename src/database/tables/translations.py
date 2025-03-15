import logging
import os
from typing_extensions import Dict, List
import requests
from pymongo import MongoClient
from database.table import Table

logger:logging.Logger = logging.getLogger("frii.site")

class Translations(Table):
    def __init__(self, mongo_client:MongoClient):
        super().__init__(mongo_client, "translations")

        self.api_key = os.getenv("GH_API_KEY")

        response = requests.get(
            "https://api.github.com/repos/ctih1/frii.site-frontend/contents/src/locales?ref=dev",
            headers =  {
                "Accept": "application/json",
                "Authorization":f"Bearer {self.api_key}",
                "X-GitHub-Api-Version":"2022-11-28"
            }
        )

        self.languages: dict = {}

        for file in response.json():
            filename:str = file["name"].split(".")[0]
            self.languages[filename] = requests.get(file["download_url"]).json()

        self.keys:dict = {}
        self.percentages:Dict[str,float] = self.__calculate_percentages()

    def __calculate_percentages(self,use_int:bool=False) -> float | int:
        main_language =  self.languages["en"]
        missing_keys:dict = {}
        total_keys = len(main_language)

        for language in self.languages:
            preview_keys:dict = self.db.translation_collection.find_one({"_id":language})
            if(preview_keys is None or preview_keys.get("keys",None) is None):
                logger.warning(f"`preview_keys` doesn't exist for language {language}")
                preview_keys = {}
            for key in main_language:
                if (language not in missing_keys):
                    missing_keys[language] = {}
                    missing_keys[language]["misses"] = 0
                    missing_keys[language]["keys"] = []
                if(key not in self.languages[language] and key not in preview_keys.get("keys",{})):
                    missing_keys[language]["misses"] += 1
                    missing_keys[language]["keys"].append({"key":key,"ref":main_language.get(key)})
                    
        percentages = {}

        for language in missing_keys:
            self.keys[language] = missing_keys[language]["keys"]
            result = 1-(missing_keys[language]["misses"]/total_keys)

            if use_int:
                result = round(result*100)

            percentages[language] = result

        return percentages
    
    
    def add(self, lang:str, keys: List[str], username:str):
        language = {}

        for translation in keys:
            if(translation["val"]!=""):
                try:
                    self.keys[lang].pop(list(self.keys[lang]).index({"key":translation["key"], "ref":self.languages["en"].get(translation["key"])}))
                except ValueError:
                    logger.warning(f"Faced a value error trying to delete key {translation['key']}")
                language["keys."+translation["key"]] = {}
                language["keys."+translation["key"]]["val"] = translation["val"]
                language["keys."+translation["key"]]["contributor"] = username

        self.table.update_one(
            {"_id":lang},
            {"$set": language},upsert=True
        )

    def get_missing_keys(self,language:str) -> List[str]:
        return self.keys[language]
