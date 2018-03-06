# Catalog App


## Google plus api configurations

- Create new application in https://console.developers.google.com .
- Go to your app's page in the Google APIs Console — https://console.developers.google.com/apis .
- Choose Credentials from the menu on the left.
- Create an OAuth Client ID.
- This will require you to configure the consent screen.
- When you're presented with a list of application types, choose Web application.
- Set the authorized JavaScript origins.
- Download credentials JSON file and name it `client_secret.json`.

## Facebook api configurations

- Go to your app on the Facebook Developers Page.
- Click + Add Product in the left column.
- Find Facebook Login in the Recommended Products list and click Set Up.
- Click Facebook Login that now appears in the left column.
- Add http://localhost:5000/ to the Valid OAuth redirect URIs section.
- Open fb_client_secrets.json in project root directory and add your app_id and app_secret.

## Database configuration

- Open terminal and run `python database_setup.py`.

## Run

- Open terminal and run `python project.py`.



