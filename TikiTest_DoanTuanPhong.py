######### INSTRUCTION #########
# 1. To run this file, use the command "python TikiTest_DoanTuanPhong.py" in CMD at this directory
# 2. The storage file "password.txt" is in the subfolder "./storage"

#use regular expression library to validate password
import re
#use pbkdf2_sha256 library to encrypt password
from passlib.hash import pbkdf2_sha256
#use os library to find the "password.txt" in subfolder
import os
#use prompt to input password with echoing asterisks (*)
from prompt_toolkit import prompt



class PasswordManager:
    def __init__(self):
        #member variable
        self.user_name = ''
        self.encrypted_pw = ''

    def _encrypt(self, raw_pw):
        #encrypt raw input password
        encrypted = pbkdf2_sha256.encrypt(raw_pw, rounds=200000, salt_size=16)
        
        return encrypted
        
    def _verifyPassword(self, pw_to_check):
        #verify with member variable
        verify_check = pbkdf2_sha256.verify(pw_to_check, self.encrypted_pw)
        if (verify_check):
            return True
        else:
            return False

    def validatePassword(self):
        error_check = 1
        while (error_check == 1):
            global input_str
            input_str = prompt('Enter your Password: ', is_password=True)
            
            #check whitespace
            white_space_chk = (input_str.count(' ') > 0)
            #check minimum length
            length_chk = ((len(input_str)) < 6)
            #check lowercase and uppercase
            upper_chk = (len(re.findall("[A-Z]",input_str)) == 0)
            lower_chk = (len(re.findall("[a-z]",input_str)) == 0)
            #check digit
            digit_chk = (len(re.findall("[0-9]",input_str)) == 0)
            #check symbol
            symbol_chk = (len(re.findall("[^a-zA-Z 0-9]",input_str)) == 0)

            #display error
            error_check = 0
            if (white_space_chk):
                print("The password must not contain any whitespace")
                error_check = 1
            if (length_chk):
                print("The password must be least 6 characters")
                error_check = 1
            if (upper_chk):
                print("The password must contain at lease one uppercase")
                error_check = 1
            if(lower_chk):
                print("The password must contain at lease one lowercase")
                error_check = 1
            if(digit_chk):
                print("The password must contain at lease one digit")
                error_check = 1
            if(symbol_chk):
                print("The password must contain at lease one symbol")
                error_check = 1

            if (error_check == 0):
                return True
        
    def setNewPassword(self):
        if (self.validatePassword() == True):
            self.encrypted_pw = self._encrypt(input_str)
            return True
        else:
            return False

    def setNewUserName(self):
        self.user_name = input("Enter your User Name: ")


def Main_Function():
    #Open .txt file for reading and writing
    global storage_text
    storage_text = open("./storage/password.txt", 'a+')
 
    #intialize Class's instance
    pw_instance = PasswordManager()
    
    #print menu
    welcome_str = "A. New User\nB. Validate Password\nC. Login\nD. Change Password\n"
    print(welcome_str)

    #Get user's option
    user_option = input("Choose your option: ")
    if (user_option == 'A'):
        OptionA_NewUser(pw_instance)
    if (user_option == 'B'):
        OptionB_ValidatePw(pw_instance)
    if (user_option == 'C'):
        OptionC_Login(pw_instance)
    if (user_option == 'D'):
        OptionD_ChangePw(pw_instance)
        

def OptionA_NewUser(pw_instance):
    pw_instance.setNewUserName()

    #Read all contents in txt file
    storage_text.seek(0)
    all_contents = storage_text.readlines()
    for i in range(len(all_contents)):
        all_contents[i] = all_contents[i].replace('\n','')

    #Check whether user name has been created
    check_user_existed = 0
    for line in (all_contents):
        if (line == pw_instance.user_name):
            print("Username already existed. Please choose another one !")
            check_user_existed = 1
            return

    #If username is available, get passsword and store in txt file
    if (check_user_existed == 0):
        pw_instance.setNewPassword()
        storage_text.write(pw_instance.user_name + '\n')
        storage_text.write(pw_instance.encrypted_pw + '\n')
        print("Set New User successfully !")


def OptionB_ValidatePw(pw_instance):
    pw_instance.validatePassword()
    print("Your password is valid !")


def OptionC_Login(pw_instance):
    print("Login")
    #get innput username and password
    login_username = input("Enter your username: ")
    login_pw = prompt('Enter your Password: ', is_password=True)

    #Read all contents in txt file
    storage_text.seek(0)
    all_contents = storage_text.readlines()
    for i in range(len(all_contents)):
        all_contents[i] = all_contents[i].replace('\n','')

    #Check whether user has been stored in txt file
    valid_username = 0
    for i in range(len(all_contents)):
        if (all_contents[i] == login_username):
            print("Valid username !")
            valid_username = 1
            #The line below the username stores the encrypted password
            pw_instance.encrypted_pw = all_contents[i+1]
            #verify the password in storage with the input one
            verify_login_pw = pw_instance._verifyPassword(login_pw)
            if (verify_login_pw == True):
                print("Login successfully !")
                return True, login_username
            else:
                print("Wrong password. Login failed !")
                return False, login_username
            break
    
    if (valid_username == 0):
        print("Username not created yet !")
        return False, login_username


def OptionD_ChangePw(pw_instance):
    (login_check, username) = OptionC_Login(pw_instance)
    #Login first
    if (login_check == False):
        print("Cannot change password")
    else:
        print("Changing password for username: " + username + "...")

        new_pw = prompt('Enter your new Password: ',is_password=True)
        
        storage_text.seek(0)
        all_contents = storage_text.readlines()
        for i in range(len(all_contents)):
            all_contents[i] = all_contents[i].replace('\n','')
        
        #Get the line of old encrypted password and replace the new one
        old_pw_index = 0
        for i in range(len(all_contents)):
            if (all_contents[i] == username):
                old_pw_index = i+1
                break
        all_contents[old_pw_index] = pw_instance._encrypt(new_pw)

        delete_file = open("./storage/password.txt", 'w')
        delete_file.close()
        for i in range(len(all_contents)):
            storage_text.write(all_contents[i])
            storage_text.write("\n")

        print("Change password successfully !")


Main_Function()