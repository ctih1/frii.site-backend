import logging
import time
import os
import threading
from typing_extensions import Dict, List, Any, TypedDict
import requests # type: ignore[import-untyped]
from pymongo import MongoClient
from database.table import Table

logger:logging.Logger = logging.getLogger("frii.site")


DatabaseKeyFormat = TypedDict("DatabaseKeyFormat", {
    "val": str,
    "contributor": str
})

DatabaseLanguageFormat = TypedDict("DatabaseLanguageFormat", {
    "_id": str,
    "keys": Dict[str,DatabaseKeyFormat]
})


class Translations(Table):
    def __init__(self, mongo_client:MongoClient):
        super().__init__(mongo_client, "translations")

        self.api_key = os.getenv("GH_KEY")

        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        try:
            response = requests.get(
                "https://api.github.com/repos/ctih1/frii.site-frontend/contents/src/locales?ref=dev",
                headers =  {
                    "Accept": "application/json",
                    "Authorization":f"Bearer {self.api_key}",
                    "X-GitHub-Api-Version":"2022-11-28"
                }
            )
        except Exception as e:
            logger.error(f"Retrieving translation files failed {e}")

        self.languages: Dict[str, Dict[str,str]] = {}
        
        threads: List[threading.Thread] = []
        for file in response.json():
            thread: threading.Thread = threading.Thread(target=self.__init_language,args=(file,))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join() # wait for threads to fetch language data to process them

        self.keys:dict = {}
        self.percentages:Dict[str,float] = self.__calculate_percentages()

        
    def __init_language(self,file: Dict) -> None:
        filename:str = file["name"].split(".")[0]
        try:
            self.languages[filename] = requests.get(file["download_url"]).json()
        except Exception as e:
            logger.error(f"Failed to GET {file} ({e})")
        
    def __process_missing_keys(self,language:str, keys: dict) -> None:
        preview_keys:Dict = {} # AKA the keys that are in the database
        
        for lang in keys:
            if lang["_id"] == language: 
                preview_keys = lang
                
        if preview_keys is None or preview_keys.get("keys") is None:
            logger.info(f"`preview_keys` doesn't exist for language {language}")
            preview_keys = {}
        else:
            logger.info(f"preview_keys exists for language {language}")
            
        for key in self.main_language:
            if language not in self.missing_keys:
                self.missing_keys[language] = {}
                self.missing_keys[language]["misses"] = 0
                self.missing_keys[language]["keys"] = []
            if key not in self.languages[language] and key not in preview_keys.get("keys",{}):
                self.missing_keys[language]["misses"] += 1
                self.missing_keys[language]["keys"].append({"key":key,"ref":self.main_language.get(key)})

    def __calculate_percentages(self,use_int:bool=False) -> Dict[str, float | int]:
        threads: List[threading.Thread] = []
        self.main_language =  self.languages["en"]
        self.missing_keys:dict = {}
        total_keys = len(self.main_language)
        self.database_entries: List[DatabaseLanguageFormat] = self.get_table() # type: ignore[assignment]

        for language in self.languages:
            thread = threading.Thread(target=self.__process_missing_keys, args=(language,self.database_entries,))
            threads.append(thread)
            thread.start()
            
        for thread in threads:
            thread.join() # wait for every thread to finish to analyze the final keys
                     
        percentages = {}

        for language in self.missing_keys:
            self.keys[language] = self.missing_keys[language]["keys"]
            result = 1-(self.missing_keys[language]["misses"]/total_keys)

            if use_int:
                result = round(result*100)

            percentages[language] = result

        return percentages
    
    def add(self, lang:str, keys: List[Dict[Any,Any]], username:str):
        language: dict = {}
    
        for translation in keys:
            if translation["val"] != "":
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

    def get_missing_keys(self,language:str) -> List[Dict[str,str]]:
        return self.keys[language]

    def combine_preview_and_commited(self, language: str) -> Dict[str,str]:
        result: Dict[str,str] = {}
        codes_on_github: Dict[str,str] = self.languages[language]

        print(self.database_entries)

        database_language: Dict[str, DatabaseKeyFormat] = {}

        for entry in self.database_entries:
            if entry["_id"] == language:
                database_language = entry["keys"]
                break

        if len(database_language) < 1:
            raise ValueError(f"Language {language} not found")

        result = codes_on_github

        result.update({ k:v["val"] for k,v in database_language.items()})

        return result