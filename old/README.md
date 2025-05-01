# The official backend for frii.site

I've decided to release the backend for frii.site, a project I've been developing for about 6 months now. 
I decided to open-source the backend, because I recently stopped working on the project. If you wish to set this up yourself, there's a guide linked below:

## How to run local instance (backend)

<details>
  <summary>.ENV Setup</summary>

  
You'll need the following keys:
P.S: These keys are listed in the following format: `Service (key name in .ENV file) - usage`

Optional:
  - [IPInfo](https://ipinfo.io/developers) (IPINFO_KEY) - Gets country details and associates them with users. WARN: Not setting up this key might cause instability / crashes.
  - Discord webhook (DC_TRACE and DC_WEBHOOK. Usage requires some slight code changes) - Sends logs to certain channels
  - [Sentry](https://sentry.io/welcome/) (SENTRY_URL) - Used for debugging. WARN: Not setting up this key might cause instability / crashes.
  - [GitHub](https://github.com/settings/tokens) (GH_KEY) - Used for translations 

Required:
  - [Resend](https://resend.com/) (RESEND_KEY) - Used for email verification
  - [MongoDB](https://www.mongodb.com/) (MONGODB_URL) - Used for storing data
  - [Cloudflare API key](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) (CF_KEY_W and CF_KEY_R) - Used for DNS management
  - Cloudflare Email (EMAIL) - Used for DNS management. (Make sure to use the email your cloudflare account is associated with)
  - [Cloudflare Zone](https://developers.cloudflare.com/fundamentals/setup/find-account-and-zone-ids/) (ZONEID) - DNS management
  - [Fernet encryption key](https://fernetkeygen.com/) (ENC_KEY) - Used for encrypting certain data in the database.

After setting up these keys, you can continue to Enviroment setup
  
</details>

<details>
  <summary>Enviroment setup</summary>

  1. Make sure you have Python >3.8 installed
  2. Clone this repository (`git clone https://github.com/ctih1/frii.site-backend`)
  3. Go to the directory (`cd frii.site-backend`)
  4. Install required dependencies (`pip install -r requirements.txt`)

  After this, you can run the server using `python server.py`, which will create an instance on localhost:5123
  
</details>

<details>
  <summary>Navigating the code</summary>

  So, now the hard part: navigating the code

  The frii.site backend has been rewritten multiple times, but it's still messy and barely organized. 

  1. `server.py` listens for requests to the server, and passes headers / the JSON body to `connector.py`
  2. `connector.py` routes the request information to the correct function
  3. `funcs/(?).py` executes the right functions, and returns data
  4. `connector.py` organizes the data in the flask "Response" class, and returns it to `server.py` 
</details>

Trouble setting the backend up? Join our discord for support (https://discord.gg/FjujyhvbMY)
