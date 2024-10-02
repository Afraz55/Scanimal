import nmap3
import pydirbuster
import urllib.parse
from urllib.parse import urlparse
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from pprint import pprint
from colorama import Fore, init
import keyboard
import webtech
import sys
import re

print(Fore.LIGHTGREEN_EX + ''' ____    ____     _     _   _  ___  __  __     _     _     
/ ___|  / ___|   / \   | \ | ||_ _||  \/  |   / \   | |    
\___ \ | |      / _ \  |  \| | | | | |\/| |  / _ \  | |    
 ___) || |___  / ___ \ | |\  | | | | |  | | / ___ \ | |___ 
|____/  \____|/_/   \_\|_| \_||___||_|  |_|/_/   \_\|_____|

    Press '9' to terminate the program!''')
print(Fore.LIGHTWHITE_EX + "Select the option below and press '1','2','3' or '4':-")
print(Fore.LIGHTGREEN_EX + "1 - Decode a url into simple text.")
print(Fore.LIGHTGREEN_EX + '''2 - To select from a series of nmap scans.
                        - Full Scan.
                        - Firewall Present or Not
                        - Popular ports Scan''')
print(Fore.LIGHTGREEN_EX + '''3 - To run a directory enumeration on given URL.
                        - Scan Using small directory List.
                        - Scan Using Medium Directory List
                        - Scan Using Large Directory List''')
print(Fore.LIGHTGREEN_EX + "4 - To run XSS attack on any given URL.")
print(Fore.LIGHTGREEN_EX + "5 - To run a web technology detection")



init()

nmap_Variable = nmap3.Nmap()


while True:
    try:
        User_Choice = int(input(Fore.LIGHTWHITE_EX+"Your selection(1-5 or 9 to exit):- "))
        if User_Choice in [1,2,3,4,5,9]:
            break
        else:
            print(Fore.RED+"The input that you have entered is incorrect please enter again")
    except ValueError:
        print(Fore.RED+"Invalid input!, Enter the number again to proceed:- ")

# If User selects 1st function#

if User_Choice == 1 :
    User_url = input(Fore.LIGHTGREEN_EX+"Enter the URl that you want to decode:- ")
    # Add 9 to exit feature later if needed#

    Decoded_Url = urllib.parse.unquote(User_url)

    print(Fore.LIGHTWHITE_EX+f"- This is the decoded URL ->{Decoded_Url}")


# Second feature Nmap Scanner #

def is_valid_ip(Target_IP):
    pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(Target_IP)

if User_Choice == 2:
    print(Fore.LIGHTWHITE_EX + "Select from the below scans to run:-")
    print(Fore.LIGHTGREEN_EX + "1-Run a Full Scan")
    print(Fore.LIGHTGREEN_EX + "2-Run a Firewall presence check")
    print(Fore.LIGHTGREEN_EX + "3-Run a Popular ports test")

    Nmap_Choice = int(input("Enter which scan you would like to commence:- "))
    Target_IP = input("Enter the IP address of the target:- ")

    if not is_valid_ip(Target_IP):
        print(Fore.RED+"Your input is invalid type like this(192.0.0.1)")
        sys.exit()

    if Nmap_Choice == 1:
        Scan_Results = nmap_Variable.nmap_os_detection(Target_IP)
        pprint(Scan_Results)

    elif Nmap_Choice == 2:
        Scan_Results = nmap_Variable.nmap_detect_firewall(Target_IP)
        print(Fore.RED + f"Result:- {Scan_Results}")

    elif Nmap_Choice == 3:
        Scan_Results = nmap_Variable.scan_top_ports(Target_IP)
        pprint(Scan_Results)

    else:
        print("The input that you have entered is incorrect please restart the program.")

# If the User entered 3#

# This is the code for directory enumeration #
# Pydirbuster library is utilised for directory enumeration#
elif User_Choice == 3:
    Target_URL = input("Enter the URl of the website that you want to enumerate:-")
    print(Fore.LIGHTGREEN_EX + "Press - 1 To run small text File(Quick)")
    print(Fore.LIGHTGREEN_EX + "Press - 2 To run Medium size text file(More time consuming)")
    print(Fore.LIGHTGREEN_EX + "Press - 3 To run Large size text file (Most time consuming)")
    Dir_Choice = int(input("Select your choice:-"))

    if Dir_Choice == 1:
        DirectoryEnumeration = pydirbuster.Pybuster(url=Target_URL,
                                                    wordfile='directory-1.txt', exts=['php', 'html'])
        DirectoryEnumeration.Run()
    elif Dir_Choice == 2:
        DirectoryEnumeration = pydirbuster.Pybuster(url=Target_URL,
                                                    wordfile="directory-list-2.3-small.txt", exts=['php', 'html'])
        DirectoryEnumeration.Run()
    elif Dir_Choice == 3:
        DirectoryEnumeration = pydirbuster.Pybuster(url=Target_URL, wordfile="directory-list-2.3-medium",
                                                    exts=['php', 'html'])
        DirectoryEnumeration.Run()
    elif User_Choice == '9':
        keyboard.wait(quit())
        print("Exiting the program...")

# 4th Feature XSS#

init()

def Retrieve_All_Data(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # This will raise an HTTPError if the status code is 4xx, 5xx
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")  # You need to return the retrieved forms
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"An error occurred while retrieving data: {e}")
        sys.exit()

# Extract form details
def Extract_All_Data(Data):
    Details = {}

    action = Data.attrs.get("action", "").lower()
    method = Data.attrs.get("method", "get").lower()

    inputs = []  # Creating an empty list to store all retrieved data

    for Input_Info in Data.find_all("input"):
        Input_Type = Input_Info.attrs.get("type", "text")
        Input_Name = Input_Info.attrs.get("name")
        inputs.append({"type": Input_Type, "name": Input_Name})

    Details["action"] = action
    Details["method"] = method
    Details["inputs"] = inputs

    return Details

# Submit data to forms for XSS scanning
def Submit_Data(Form_Details, url, payloads):
    Target_URL = urljoin(url, Form_Details["action"])
    inputs = Form_Details["inputs"]

    for payload in payloads:  # Create a dictionary to store all of the payloads that will be parsed
        data = {}

        # This loop decides if input == any of the below mentioned names, then insert the payloads in that space
        for input in inputs:
            if input["type"] in ["text", "search", "submit", "btnSign", "Text", "name"]:
                input_name = input.get("name")
                if input_name:
                    data[input_name] = payload

        # Print where the payload is being injected
        print(f"--> Injecting the Malicious Payloads on the target {Target_URL}")
        print(Fore.LIGHTGREEN_EX + f"--> Data: {data}")

        if Form_Details["method"] == "post":
            response = requests.post(Target_URL, data=data)
        else:
            response = requests.get(Target_URL, params=data)

        content = response.content.decode()

        # If the sent payload is found in the response, print it in red (XSS found)
        if payload in content:
            print(Fore.RED + f"XSS Found on {url}")
            print(f"--> Form Details:")
            pprint(Form_Details)

# Main XSS scanning function
def XSS(url):
    forms = Retrieve_All_Data(url)
    if not forms:
        print(Fore.RED + "No forms detected on the provided URL.")
        return

    print(f"--> Detected {len(forms)} forms on {url}")
    with open("xss.txt", "r", encoding="UTF-8") as payload_file:
        payloads = payload_file.read().splitlines()  # This function is used because each payload in xss.txt is on a different line

        for form in forms:
            Form_Details = Extract_All_Data(form)
            Submit_Data(Form_Details, url, payloads)

# Main script logic for user choice
User_Choice = 4

if User_Choice == 4:
    url = input("Enter the URL you want to test: ")

    if url == '9':
        print(Fore.LIGHTRED_EX + "Exiting the program...")
        sys.exit()

    # Run XSS scanner
    XSS(url)

# 5th Feature#

elif User_Choice == 5:
    Target_Url = input("Enter the URl that you want to scan:-")
    wt = webtech.WebTech(options={'json': True})
    results = wt.start_from_url(Target_Url)
    print(Fore.LIGHTGREEN_EX + f"These are your results:-")
    pprint(results)

else:
    print(Fore.RED + "Program has terminated because you have entered wrong character")
