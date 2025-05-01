from database.table import Table

class Sessions(Table):
    def __init__(self, mongo_client):
        super().__init__(mongo_client, "sessions")
        