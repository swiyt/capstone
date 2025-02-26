import os
import sys

def runPE():
    print("running")

def runURL():
    os.system('python Extract/url_main.py')



def main():
    user = int(input("\nWelcome to malware detector \nSelect which way to proceed: \n\n1. PE scanner \n2. URL scanner \n3. Quit \n\n"))

    while (user != 3):
        
        #PE 
        if (user == 1):
            #runPE() function to be defined
            choice = input("Do you want to continue checking? Enter 1(y/n)")
            if (choice == "y" or choice == "Y"):
                main()
            elif (choice == "n" or choice == "N"):
                sys.exit()
        
        #URL
        elif (user == 2):
            #runURL function to be defined
            runURL()
            choice = input("Do you want to continue checking? Enter 2(y/n)")
            if (choice == "y" or choice == "Y"):
                main()
            elif (choice == "n" or choice == "N"):
                print("Thank you for using Malware detector. ")
                sys.exit()

    else: 
        print("Thank you for using malware detector. muahahhaaha  ")
        sys.exit()


main()

 