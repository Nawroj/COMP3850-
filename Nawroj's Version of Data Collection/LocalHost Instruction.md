##This code will be used to update your data in your localhost.

follow the instruction:
1. Download feed_urls.json file
2. Replace def load_feed_urls(filepath="YOUR feed_urls.json FILE PATH"):
3. Make a Database in your PGAdmin
4. Make a new table and add these columns:  
      1. id -> integer -> not null -> primary key
      2. type -> character varying
      3. value -> text
      4. source -> character varying
      5. timestamp -> timestamp without timezone
      6. listing_reason -> character_varying
5.  Now update these with your database informations:
         db_params = {
            dbname": "postgres",
            "user": "postgres",
            "password": "1234",
            "host": "localhost",
            "port": "5433"
        }

        dbname = "postgres"
        user = "postgres"
        password = "1234"
        host = "localhost"
        port = "5433"

6. Run the File.

Everytime you run it this should clear the previous table and update it with new ones.

To See the Tables and make Queries:
1. "Your Database Name"-> Database -> postgres -> Schemas -> public -> Tables -> indicators
2. Right click on the indicators and click on View/edit Data.