from database.tables.general import General

class Domains(General):
    def __init__(self, mongo_client):
        super().__init__(mongo_client)

    
    def __clean_domain_name(self,input:str) -> str:
        return input.replace(".","[dot]")
    
    
    def add_domain(self, target_user:str, domain:str, domain_data:dict) -> bool:
        cleaned_domain:str = self.__clean_domain_name(domain)

        self.modify_document(
            {"_id":target_user},
            operation="$set",
            key=f"domains.{cleaned_domain}",
            value=domain_data
        )

    def modify_domain(
            self,
            target_user:str,
            domain:str,
            value:str=None,
            type:str=None,
        ) -> None:
        cleaned_domain:str = self.__clean_domain_name(domain)

        user_data:dict | None = self.find_item({"_id":target_user})
        if user_data is None:
            raise ValueError("Failed to find user")
        
        
        domain_data:dict = user_data["domains"][cleaned_domain]

        domain_data = {
            "ip": value or domain_data["ip"] ,
            "registered": domain_data["registered"],
            "type": type or domain_data["type"],
            "id": domain_data["id"]
        }

        self.modify_document(
            {"_id":target_user},
            operation="$set",
            key=f"domains.{cleaned_domain}",
            value=domain_data
        )

    def delete_domain(self, target_user:str, domain:str) -> None:
        cleaned_domain = self.__clean_domain_name(domain)

        self.remove_key({"_id":target_user},key=f"domains.{cleaned_domain}")
