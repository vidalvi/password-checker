import requests
import hashlib
import stdiomask


def main(password):
    num_times_appeared = check_password(password)
    if num_times_appeared:
        print(
            f'Your password has appeared {num_times_appeared} times in the data set of previous data breaches. PLEASE CHANGE YOUR PASSWORD.\n')
    else:
        print('Your password is safe.\n')


def check_password(password):
    sha1_pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_chars, remaining_chars = sha1_pass[:5], sha1_pass[5:]
    breached_passwords = get_breached_passwords(first5_chars)
    num_times_breached = count_num_times_appeared(breached_passwords, remaining_chars)
    return num_times_breached


def get_breached_passwords(first5_chars_sha1pass):
    url = 'https://api.pwnedpasswords.com/range/' + first5_chars_sha1pass
    api_response = requests.get(url)
    breached_passwords = (line.split(':') for line in api_response.text.splitlines())
    return breached_passwords


def count_num_times_appeared(response_data, tail_of_pass):
    for breached_password, num_times_breached in response_data:
        if breached_password == tail_of_pass:
            return int(num_times_breached)
    return 0


if __name__ == '__main__':
    inputted_password = stdiomask.getpass(
        prompt='Enter your password: ', mask='?')
    main(inputted_password)
