valid_emails, invalid_emails = [], []
while True:
    email = input("Enter your Email (or type 'quit' to exit): ")
    if email.lower() == 'quit':
        break
    k, j, d = 0, 0, 0
    is_valid = True
    error_message = ""
    if len(email) >= 6:
        if email[0].isalpha():
            if ("@" in email) and (email.count("@") == 1):
                if (email[-4] == ".") ^ (email[-3] == "."):
                    for i in email:
                        if i.isspace():  
                            k = 1
                        elif i.isalpha():
                            if i.isupper():  
                                j = 1
                        elif i.isdigit():
                            continue
                        elif i == "_" or i == "." or i == "@":
                            continue
                        else:
                            d = 1                 
                    if k == 1 or j == 1 or d == 1:
                        error_message = "Invalid email: Contains space/uppercase/invalid special characters(other than _ . @)"
                        is_valid = False
                else:
                    error_message = "Invalid email: Position of .(dot) is not correct"
                    is_valid = False
            else:
                error_message = "Invalid email: @ is missing or there are more than one @"
                is_valid = False
        else:
            error_message = "Invalid email: First Letter is not alphabet"
            is_valid = False
    else:
        error_message = "Invalid email: Email Length is less than 6"
        is_valid = False
    if is_valid:
        valid_emails.append(email)
        print("Email is valid!")
    else:
        invalid_emails.append((email, error_message))
        print(f"{error_message}")
    print() 

print("\n" + "="*50)
print("EMAIL CLASSIFICATION RESULTS")
print("="*50)

print(f"\nValid Emails ({len(valid_emails)}):")
for i, email in enumerate(valid_emails, 1):
    print(f"{i}. {email}")

print(f"\nInvalid Emails ({len(invalid_emails)}):")
for i, (email, reason) in enumerate(invalid_emails, 1):
    print(f"{i}. {email} - Reason: {reason}")