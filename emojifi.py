import argparse
from getpass import getpass
import hashlib
import json
import requests
from sys import exit
from time import sleep
import urllib3


# FUNCTIONS

def change_ssid(password, new_ssid, frequency='2.4', url='https://192.168.1.1', validate_https=False):
    print()

    # Turn off warnings caused by Verizon's self-signed certs
    if not validate_https:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create a session to store cookies, headers, etc. across calls
    session = requests.Session()

    # Make a GET request to the login API to see what the salt is
    res = session.get('https://192.168.1.1/api/login', verify=validate_https)    
    salt = res.json()['passwordSalt']

    # Encode the password so that it can be sent -- relies on logic from https://github.com/cisasteelersfan/quantum_gateway/blob/master/src/quantum_gateway.py#L52
    encodedpassword = hashlib.sha512((password + salt).encode('ascii')).hexdigest()

    # Log in
    print('Logging in...')
    res = session.post('https://192.168.1.1/api/login', validate_https, json={'password': encodedpassword})
    
    if res.status_code == 200:
        print('Successfully logged in!')
    else:
        print(f'There was an issue logging in. The router returned status code {res.status_code}.')
    
    # Set this header so that we have the authorization to update the SSID
    session.headers.update({'X-XSRF-TOKEN': session.cookies.get('XSRF-TOKEN')})

    # Try to get the current wireless settings
    print('Retrieving current wireless settings...')
    attempts = 0
    
    while attempts < 10:
        attempts += 1

        # Try to grab the settings
        res = session.get('https://192.168.1.1/api/wireless', verify=validate_https)
        
        # If we don't get a 401, assume we succeeded
        if res.status_code != 401:
            print('Successfully retrieved current wireless settings!', end='')
    
            if attempts > 1:
                print(f' [{attempts} attempts]')
            else:
                print()
    
            break
    
        # Otherwise, wait for the router to do its stuff and then try again
        sleep(1)
    
    # If we've gotten through 10 tries, exit
    else:
        print(f'There was an issue retrieving wireless settings. Attempted 10 times. The router returned status code {res.status_code}.')
        print('Please try again in a few seconds.')
        exit()

    # Modify the SSID
    wireless_settings = res.json()
    
    # Remove unnecessary parts (guest Wi-Fi) if they exist
    try:
        del wireless_settings[2]
        del wireless_settings[3]
    except IndexError:
        pass

    if frequency == '2.4':
        # The 0th element contains the 2.4GHz settings
        wireless_settings[0]['ssid'] = new_ssid
    elif frequency == '5':
        # The 1st element contains the 5GHz settings
        wireless_settings[1]['ssid'] = new_ssid
    else:
        raise ValueError(f"'frequency' must be '2.4' or '5'. Received '{frequency}'.")

    # Try to apply the new settings
    print(f"Applying new SSID '{new_ssid}' to {frequency}GHz access point...")
    
    # Let the router do its thing
    sleep(5)

    attempts = 0
    while attempts < 10:
        attempts += 1
        
        # This messy line is to ensure the emoji isn't treated as ASCII
        res = session.put('https://192.168.1.1/api/wireless', verify=validate_https, data=json.dumps({'wifi': wireless_settings}, ensure_ascii=False).encode('utf-8'), headers={'content-type': 'application/json'})

        # If we don't get a 404, assume we succeeded. 404's are usually caused by bad payloads, e.g. not sending as a JSON or not using th correct `'wifi'` key.
        if res.status_code != 404:
            print('Successfully applied the new SSID!', end='')
            if attempts > 1:
                print(f' [{attempts} attempts.]', end='')
            print('\nPlease wait around a minute for it to show up on your device\'s Wi-Fi list.\nYour devices may disconnect for a short while.')
            break
        # Otherwise, wait for the router to do its stuff and then try again
        sleep(1)
    # If we've gotten through 10 tries, exit
    else:
        print(f'There was an issue applying the new SSID. Attempted 10 times. The router returned status code {res.status_code}.')
        print('Please try again in a few seconds.')
        exit()
    
    print()
    print()


def main():
    print()
    frequency = input("Which AP's SSID do you want to change? Valid inputs are '2.4' and '5': ")
    ssid = input('Please input the new SSID: ')
    password = getpass('Please input your router admin password (NOT your Wi-Fi password): ')
    change_ssid(password, ssid, frequency)



# __main__ HANDLING

if __name__ == "__main__":
    main()
